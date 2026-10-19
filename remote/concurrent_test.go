package remote

import (
	"slices"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

// Two fetches may run at once, and each scans to the findings it gives
// alone; make test-race checks them for a shared write.
func TestFetchRunsConcurrently(t *testing.T) {
	plugin, _ := newFakeRepo(t, rootFS(t, "../testdata/malicious/claude-plugin-components"))
	mcp, _ := newFakeRepo(t, fstest.MapFS{".mcp.json": {Data: []byte(mcpJSON)}})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/plugin": plugin, "o/mcp": mcp}})
	urls := []string{"https://github.com/o/plugin", "https://github.com/o/mcp"}

	want := make([][]string, len(urls))
	for i, url := range urls {
		want[i] = fetchedFindings(t, url)
	}
	got := make([][]string, len(urls))
	var wg sync.WaitGroup
	for i, url := range urls {
		wg.Go(func() { got[i] = fetchedFindings(t, url) })
	}
	wg.Wait()

	for i := range urls {
		if len(want[i]) == 0 {
			t.Fatalf("%s: no finding fetched alone; the comparison would prove nothing", urls[i])
		}
		if !slices.Equal(got[i], want[i]) {
			t.Fatalf("%s: fetched concurrently\n%sfetched alone\n%s", urls[i], indentLines(got[i]), indentLines(want[i]))
		}
	}
}

func fetchedFindings(t *testing.T, url string) []string {
	t.Helper()
	_, tree, err := fetch(url, "", DefaultLimits())
	if err != nil {
		t.Errorf("Fetch(%s) error = %v", url, err)
		return nil
	}
	report, err := agentaudit.New().Scan(tree)
	if err != nil {
		t.Errorf("Scan(%s) error = %v", url, err)
		return nil
	}
	return findingLines(report)
}
