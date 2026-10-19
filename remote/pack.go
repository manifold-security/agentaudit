package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
)

type cappedTransport struct {
	base       http.RoundTripper
	refs, pack int64
}

var (
	errRefsTooLarge = fmt.Errorf("%w: a ref advertisement over Limits.RefsBytes", ErrTooLarge)
	errPackTooLarge = fmt.Errorf("%w: a pack response over Limits.PackBytes", ErrTooLarge)
)

func (c *cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body := &cappedBody{ReadCloser: resp.Body, left: c.pack, err: errPackTooLarge}
	if strings.HasSuffix(req.URL.Path, "/info/refs") {
		body.left, body.err = c.refs, errRefsTooLarge
	}
	resp.Body = body
	return resp, nil
}

type cappedBody struct {
	io.ReadCloser
	left int64
	err  error
	over bool
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.over {
		return 0, b.err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	if int64(n) > b.left {
		b.over = true
		return int(b.left), b.err
	}
	b.left -= int64(n)
	return n, err
}

func prescan(ctx context.Context, pack []byte, l Limits, total int64) (int64, []plumbing.Hash, error) {
	s := packfile.NewScanner(bytes.NewReader(pack))
	_, count, err := s.Header()
	if err != nil {
		return 0, nil, err
	}
	var over []plumbing.Hash
	for range count {
		h, err := s.NextObjectHeader()
		if err != nil {
			return 0, nil, err
		}
		var size int64
		switch {
		case h.Type == plumbing.OFSDeltaObject || h.Type == plumbing.REFDeltaObject:
			if h.Length > l.FileBytes {
				return 0, nil, fmt.Errorf("%w: a delta of %d bytes", ErrTooLarge, h.Length)
			}
			d := &deltaSink{limit: l.FileBytes}
			if err := inflate(s, h, ctxWriter{ctx, d}); err != nil {
				return 0, nil, err
			}
			if !d.sized {
				return 0, nil, errors.New("a delta without its sizes")
			}
			size = d.target
		case h.Type != plumbing.BlobObject && h.Length > l.FileBytes:
			return 0, nil, fmt.Errorf("%w: a %s of %d bytes", ErrTooLarge, h.Type, h.Length)
		default:
			size = h.Length
		}
		if size > l.TotalBytes-total {
			return 0, nil, fmt.Errorf("%w: objects past %d bytes in all", ErrTooLarge, l.TotalBytes)
		}
		total += size
		switch {
		case h.Type == plumbing.BlobObject && h.Length > l.FileBytes:
			hasher := plumbing.NewHasher(plumbing.BlobObject, h.Length)
			if err := inflate(s, h, ctxWriter{ctx, hasher}); err != nil {
				return 0, nil, err
			}
			over = append(over, hasher.Sum())
		case h.Type != plumbing.OFSDeltaObject && h.Type != plumbing.REFDeltaObject:
			if err := inflate(s, h, ctxWriter{ctx, io.Discard}); err != nil {
				return 0, nil, err
			}
		}
	}
	return total, over, nil
}

// inflate consumes one object into w; the scanner would otherwise discard
// it itself, unbounded by any context.
func inflate(s *packfile.Scanner, h *packfile.ObjectHeader, w io.Writer) error {
	n, _, err := s.NextObject(w)
	if err != nil {
		return err
	}
	if n != h.Length {
		return fmt.Errorf("a pack object inflates to %d bytes, not the %d it declares", n, h.Length)
	}
	return nil
}

type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

// deltaSink reads the target size a delta's data opens with, after its
// source size.
type deltaSink struct {
	limit  int64
	head   []byte
	target int64
	sized  bool
}

func (d *deltaSink) Write(p []byte) (int, error) {
	if d.sized {
		return len(p), nil
	}
	d.head = append(d.head, p[:min(len(p), 2*binary.MaxVarintLen64-len(d.head))]...)
	_, n := binary.Uvarint(d.head)
	if n <= 0 {
		return len(p), nil
	}
	target, m := binary.Uvarint(d.head[n:])
	if m <= 0 {
		return len(p), nil
	}
	if target > math.MaxInt64 || int64(target) > d.limit {
		return 0, fmt.Errorf("%w: a delta inflating to %d bytes", ErrTooLarge, target)
	}
	d.target, d.sized = int64(target), true
	return len(p), nil
}
