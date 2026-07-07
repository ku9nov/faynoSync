// Staged-rollout simulator.
//
// Generates N random device IDs, hits the update URL (CDN-cached latest response)
// per device, applies the client-side bucketing decision, and reports what share
// of the fleet would update.
//
// The bucket() function below is the REFERENCE algorithm the SDK must replicate:
//   sha256(device_id + ":" + seed) -> first 8 bytes big-endian uint64 % 100
//   update if bucket < rollout.percent
//
// Usage:
//   go run ./scripts/rollout_sim -url "https://cdn.example.com/responses/.../1.0.0.json" -n 1000
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

type rolloutInfo struct {
	Percent int    `json:"percent"`
	Seed    string `json:"seed"`
}

type latestResp struct {
	UpdateAvailable *bool        `json:"update_available"`
	Rollout         *rolloutInfo `json:"rollout"`
}

func bucket(deviceID, seed string) int {
	sum := sha256.Sum256([]byte(deviceID + ":" + seed))
	return int(binary.BigEndian.Uint64(sum[:8]) % 100)
}

func newDeviceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type result struct {
	deviceID string
	bck      int
	update   bool
	percent  int
	seed     string
	err      error
}

func fetch(client *http.Client, url, deviceID string) (latestResp, error) {
	var out latestResp
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("X-Device-ID", deviceID)
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("invalid JSON: %w (body: %.120s)", err, string(body))
	}
	return out, nil
}

func decide(id string, r latestResp) result {
	percent, seed := 100, ""
	if r.Rollout != nil {
		percent, seed = r.Rollout.Percent, r.Rollout.Seed
	}
	noUpdate := r.UpdateAvailable != nil && !*r.UpdateAvailable
	b := bucket(id, seed)
	return result{
		deviceID: id,
		bck:      b,
		update:   !noUpdate && b < percent,
		percent:  percent,
		seed:     seed,
	}
}

func main() {
	url := flag.String("url", "", "update URL returning the cached latest JSON (required)")
	n := flag.Int("n", 1000, "number of simulated devices")
	concurrency := flag.Int("c", 50, "concurrent requests")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Parse()

	if *url == "" {
		fmt.Fprintln(os.Stderr, "error: -url is required")
		flag.Usage()
		os.Exit(2)
	}

	client := &http.Client{Timeout: *timeout}
	ids := make([]string, *n)
	for i := range ids {
		ids[i] = newDeviceID()
	}

	jobs := make(chan string)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				r, err := fetch(client, *url, id)
				if err != nil {
					results <- result{deviceID: id, err: err}
					continue
				}
				results <- decide(id, r)
			}
		}()
	}
	go func() {
		for _, id := range ids {
			jobs <- id
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var ok, errs, updates int
	var hist [10]int
	seen := map[string]int{} // "percent|seed" -> count, to detect inconsistent config
	var firstErr error
	for r := range results {
		if r.err != nil {
			errs++
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		ok++
		seen[fmt.Sprintf("%d|%s", r.percent, r.seed)]++
		hist[r.bck/10]++
		if r.update {
			updates++
		}
	}

	fmt.Printf("devices:            %d\n", *n)
	fmt.Printf("responses ok:       %d\n", ok)
	fmt.Printf("responses failed:   %d\n", errs)
	if firstErr != nil {
		fmt.Printf("first error:        %v\n", firstErr)
	}
	if ok == 0 {
		os.Exit(1)
	}

	if len(seen) > 1 {
		fmt.Printf("WARNING: got %d distinct percent|seed pairs (config not stable across responses):\n", len(seen))
		for k, v := range seen {
			fmt.Printf("  %s -> %d\n", k, v)
		}
	}
	var cfgPercent int
	var cfgSeed string
	for k := range seen {
		fmt.Sscanf(k, "%d|", &cfgPercent)
		cfgSeed = k[len(fmt.Sprintf("%d|", cfgPercent)):]
		break
	}

	fmt.Printf("configured percent: %d\n", cfgPercent)
	fmt.Printf("seed:               %q\n", cfgSeed)
	fmt.Printf("would update:       %d / %d = %.2f%%\n", updates, ok, 100*float64(updates)/float64(ok))
	fmt.Printf("expected ~:         %d%%\n", cfgPercent)

	fmt.Println("bucket distribution (0-99, 10 bins):")
	for i, c := range hist {
		fmt.Printf("  %2d-%2d: %d\n", i*10, i*10+9, c)
	}
}
