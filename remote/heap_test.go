package remote

import (
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit"
)

// BenchmarkPeakHeapAtTheCaps measures one fetch and scan with the
// advertisement at DefaultLimits().RefsBytes, and one with a pack at its
// PackBytes. Run it with:
// go test -run '^$' -bench PeakHeap -benchtime 1x ./remote
func BenchmarkPeakHeapAtTheCaps(b *testing.B) {
	l := DefaultLimits()

	b.Run("advertisement", func(b *testing.B) {
		repo, _ := newFakeRepo(b, oneFile(".mcp.json", mcpJSON))
		base, err := encodeAdvertisement(repo)
		if err != nil {
			b.Fatal(err)
		}
		const line = 4 + 40 + 1 + len("refs/heads/b00000000") + 1
		for i := range (int(l.RefsBytes) - len(base)) / line {
			repo.refs[fmt.Sprintf("refs/heads/b%08d", i)] = repo.refs["refs/heads/main"]
		}
		measurePeakHeap(b, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	})

	b.Run("pack", func(b *testing.B) {
		paths := []string{".mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".cursor/mcp.json", ".codex/config.toml", ".claude/agents/a.md", ".claude/agents/b.md"}
		files := fstest.MapFS{}
		for _, p := range paths {
			data := make([]byte, (l.PackBytes-64<<10)/int64(len(paths)))
			if _, err := rand.Read(data); err != nil {
				b.Fatal(err)
			}
			files[p] = &fstest.MapFile{Data: data}
		}
		repo, _ := newFakeRepo(b, files)
		measurePeakHeap(b, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	})
}

func measurePeakHeap(b *testing.B, f *fakeGit) {
	useFake(b, f)
	scan := func() {
		_, tree, err := Fetch(context.Background(), "https://github.com/o/r", "", agentaudit.New(), DefaultLimits())
		if err != nil {
			b.Fatalf("Fetch() error = %v", err)
		}
		if _, err := agentaudit.New().Scan(tree); err != nil {
			b.Fatalf("Scan() error = %v", err)
		}
	}
	scan()
	largest := 0
	for _, req := range f.requests() {
		largest = max(largest, req.bytes)
	}
	encoded := f.encodedBodies()
	if encoded == 0 {
		b.Fatal("the fake counted no encode in the warm-up fetch")
	}

	for b.Loop() {
		base, peak := peakHeap(scan)
		if f.encodedBodies() != encoded {
			b.Fatal("the fake encoded a response inside the measured window")
		}
		b.ReportMetric(float64(largest)/(1<<20), "MiB-largest-response")
		b.ReportMetric(float64(base)/(1<<20), "MiB-heap-baseline")
		b.ReportMetric(float64(peak)/(1<<20), "MiB-heap-peak")
		b.ReportMetric(float64(peak-base)/(1<<20), "MiB-heap-over-baseline")
	}
}

func peakHeap(f func()) (base, peak uint64) {
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	base, peak = ms.HeapInuse, ms.HeapInuse

	done := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Go(func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				mu.Lock()
				peak = max(peak, ms.HeapInuse)
				mu.Unlock()
			}
		}
	})
	f()
	close(done)
	wg.Wait()
	return base, peak
}
