// Staged-rollout simulator.
//
// Drives realistic /checkVersion traffic so telemetry (and the dashboard's
// Rollout Health panel) reflects a staged rollout end-state.
//
// Model (per simulated device, mirrors what the real SDK does):
//
//	phase 1 — GET /checkVersion?version=<from> WITHOUT X-Device-ID: fetch the
//	          server-issued rollout {percent, seed} and is_intermediate_required.
//	          No device id => no telemetry written, this is just a config read.
//	client  — bucket = sha256(device_id + ":" + seed)[0:8] % 100
//	          bucket < percent            -> device ends up on -latest
//	          else, intermediate required -> device ends up on -intermediate
//	          else                        -> device stays on -from
//	phase 2 — GET /checkVersion?version=<final> WITH X-Device-ID: the device
//	          reports its resulting version. Telemetry keys version_usage on the
//	          reported version, so this is what populates adoption.
//
// The bucket() function is the REFERENCE algorithm the SDK must replicate.
//
// Server setup this simulator expects (create via the admin API beforehand):
//   - ENABLE_TELEMETRY=true
//   - versions -from, -intermediate, -latest all published on -channel
//   - -intermediate marked required-intermediate
//   - -latest given a rollout percent < 100 (e.g. 60)
//
// -platform and -arch accept comma-separated lists (equal-length lists zip
// positionally, a single value broadcasts). Devices are split evenly across the
// resulting platform/arch targets, so you can validate the dashboard's scope
// filter: selecting one target there should match that target's numbers here.
//
// Example (60% rollout of 1.0.2, intermediate 1.0.1, two targets):
//
//	go run ./examples/rollout_sim \
//	  -url http://localhost:9000/checkVersion \
//	  -app myapp -channel stable -platform darwin,windows -arch arm64,amd64 -owner admin \
//	  -from 1.0.0 -intermediate 1.0.1 -latest 1.0.2 -n 1000
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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type rolloutInfo struct {
	Percent int    `json:"percent"`
	Seed    string `json:"seed"`
}

type checkResp struct {
	Rollout *rolloutInfo `json:"rollout"`
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

type target struct {
	platform, arch string
}

func (t target) label() string { return t.platform + "/" + t.arch }

type config struct {
	base                       string
	app, channel               string
	owner                      string
	from, intermediate, latest string
}

func (cfg config) checkURL(tgt target, version string) string {
	q := url.Values{}
	q.Set("app_name", cfg.app)
	q.Set("channel", cfg.channel)
	q.Set("platform", tgt.platform)
	q.Set("arch", tgt.arch)
	q.Set("version", version)
	if cfg.owner != "" {
		q.Set("owner", cfg.owner)
	}
	return cfg.base + "?" + q.Encode()
}

// hop records one rung of the ladder the device was offered.
type hop struct {
	target   string
	percent  int
	seed     string
	bucket   int
	advanced bool
}

type result struct {
	tgt   string
	final string
	hops  []hop
	err   error
}

func check(client *http.Client, url, deviceID string) (checkResp, error) {
	var out checkResp
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return out, err
	}
	if deviceID != "" {
		req.Header.Set("X-Device-ID", deviceID)
	}
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
		return out, fmt.Errorf("http %d: %.120s", resp.StatusCode, string(body))
	}
	// A "no update" 204 has an empty body; that is fine, leave out zero-valued.
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return out, fmt.Errorf("invalid JSON: %w (body: %.120s)", err, string(body))
		}
	}
	return out, nil
}

func run(client *http.Client, cfg config, tgt target, deviceID string) result {
	// Walk the version ladder. The server only reveals the rollout of the NEXT
	// offered version, and when an intermediate is required it offers that first
	// (at its own rollout), exposing the latest's rollout only once the device is
	// already on the intermediate. So we hop rung by rung, reading the rollout at
	// each step and bucketing where it gates (< 100).
	ladder := make([]string, 0, 2)
	if cfg.intermediate != "" {
		ladder = append(ladder, cfg.intermediate)
	}
	ladder = append(ladder, cfg.latest)

	current := cfg.from
	hops := make([]hop, 0, len(ladder))
	for _, next := range ladder {
		// config read (no device id -> no telemetry) for the offered `next`.
		resp, err := check(client, cfg.checkURL(tgt, current), "")
		if err != nil {
			return result{err: err}
		}
		percent, seed := 100, ""
		if resp.Rollout != nil {
			percent, seed = resp.Rollout.Percent, resp.Rollout.Seed
		}
		b := bucket(deviceID, seed)
		advanced := b < percent
		hops = append(hops, hop{target: next, percent: percent, seed: seed, bucket: b, advanced: advanced})
		if advanced {
			current = next
		} else {
			break
		}
	}

	// device reports its resulting version (this writes telemetry).
	if _, err := check(client, cfg.checkURL(tgt, current), deviceID); err != nil {
		return result{err: err}
	}

	return result{tgt: tgt.label(), final: current, hops: hops}
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildTargets pairs the platform and arch lists: equal-length lists zip
// positionally, and a single value on either side broadcasts across the other.
func buildTargets(platformCSV, archCSV string) ([]target, error) {
	platforms := splitCSV(platformCSV)
	arches := splitCSV(archCSV)
	if len(platforms) == 0 || len(arches) == 0 {
		return nil, fmt.Errorf("platform and arch must be non-empty")
	}
	var targets []target
	switch {
	case len(platforms) == len(arches):
		for i := range platforms {
			targets = append(targets, target{platforms[i], arches[i]})
		}
	case len(platforms) == 1:
		for _, a := range arches {
			targets = append(targets, target{platforms[0], a})
		}
	case len(arches) == 1:
		for _, p := range platforms {
			targets = append(targets, target{p, arches[0]})
		}
	default:
		return nil, fmt.Errorf("platform (%d) and arch (%d) lists must be equal length, or one must be single", len(platforms), len(arches))
	}
	return targets, nil
}

func main() {
	url := flag.String("url", "http://localhost:9000/checkVersion", "checkVersion endpoint")
	app := flag.String("app", "", "app_name (required)")
	channel := flag.String("channel", "stable", "channel")
	platform := flag.String("platform", "", "platform(s), comma-separated (required)")
	arch := flag.String("arch", "", "arch(es), comma-separated (required)")
	owner := flag.String("owner", "", "owner query param")
	from := flag.String("from", "1.0.0", "version each device currently runs")
	intermediate := flag.String("intermediate", "", "version devices stop at when not in the rollout bucket (empty = stay on -from)")
	latest := flag.String("latest", "", "rollout target version devices move to when in the bucket (required)")
	n := flag.Int("n", 1000, "number of simulated devices")
	concurrency := flag.Int("c", 50, "concurrent requests")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Parse()

	missing := ""
	switch {
	case *app == "":
		missing = "-app"
	case *platform == "":
		missing = "-platform"
	case *arch == "":
		missing = "-arch"
	case *latest == "":
		missing = "-latest"
	}
	if missing != "" {
		fmt.Fprintf(os.Stderr, "error: %s is required\n", missing)
		flag.Usage()
		os.Exit(2)
	}

	targets, err := buildTargets(*platform, *arch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	cfg := config{
		base: *url, app: *app, channel: *channel,
		owner: *owner, from: *from, intermediate: *intermediate, latest: *latest,
	}

	client := &http.Client{Timeout: *timeout}

	type job struct {
		id  string
		tgt target
	}
	// Devices are split evenly across targets (round-robin), so each platform/arch
	// gets a comparable slice of the fleet to validate scope filtering on the dashboard.
	ids := make([]job, *n)
	for i := range ids {
		ids[i] = job{id: newDeviceID(), tgt: targets[i%len(targets)]}
	}

	jobs := make(chan job)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- run(client, cfg, j.tgt, j.id)
			}
		}()
	}
	go func() {
		for _, j := range ids {
			jobs <- j
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	// rung aggregates: a device is "offered" a rung when it reaches that hop, and
	// "adopted" it when it buckets in. adopted/offered mirrors the dashboard's
	// eligible-pool adoption and should land near the configured percent.
	type rungAgg struct {
		offered, adopted int
		configs          map[string]int // "percent|seed" -> count, per-rung mid-run change
	}
	var ok, errs int
	var hist [10]int
	versionCounts := map[string]int{}
	targetCounts := map[string]map[string]int{} // target label -> version -> count
	rungs := map[string]*rungAgg{}
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
		versionCounts[r.final]++
		if targetCounts[r.tgt] == nil {
			targetCounts[r.tgt] = map[string]int{}
		}
		targetCounts[r.tgt][r.final]++
		for _, h := range r.hops {
			if h.percent >= 100 {
				continue // full rollout, not a staged rung
			}
			hist[h.bucket/10]++
			agg := rungs[h.target]
			if agg == nil {
				agg = &rungAgg{configs: map[string]int{}}
				rungs[h.target] = agg
			}
			agg.offered++
			if h.advanced {
				agg.adopted++
			}
			agg.configs[fmt.Sprintf("%d|%s", h.percent, h.seed)]++
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

	fmt.Println("rollout rungs (adoption within eligible pool):")
	for _, v := range []string{cfg.intermediate, cfg.latest} {
		agg := rungs[v]
		if v == "" || agg == nil {
			continue // full rollout or never offered
		}
		var percent int
		var seed string
		for k := range agg.configs {
			fmt.Sscanf(k, "%d|", &percent)
			seed = k[len(fmt.Sprintf("%d|", percent)):]
			break
		}
		fmt.Printf("  %-10s target %d%%  seed %q  offered %d  adopted %d = %.2f%%\n",
			v, percent, seed, agg.offered, agg.adopted, 100*float64(agg.adopted)/float64(agg.offered))
		if len(agg.configs) > 1 {
			fmt.Printf("    WARNING: %d distinct percent|seed pairs for this rung (config changed mid-run):\n", len(agg.configs))
			for k, c := range agg.configs {
				fmt.Printf("      %s -> %d\n", k, c)
			}
		}
	}

	fmt.Println("resulting version distribution:")
	for _, v := range []string{cfg.latest, cfg.intermediate, cfg.from} {
		if v == "" {
			continue
		}
		c := versionCounts[v]
		label := v
		switch v {
		case cfg.latest:
			label += " (latest)"
		case cfg.intermediate:
			label += " (intermediate)"
		}
		fmt.Printf("  %-24s %d = %.2f%%\n", label, c, 100*float64(c)/float64(ok))
	}

	// Per-target breakdown lets you cross-check the dashboard's platform/arch scope
	// filter: selecting one target there should match that target's numbers here.
	if len(targets) > 1 {
		fmt.Println("per-target distribution (cross-check dashboard scope filter):")
		for _, t := range targets {
			counts := targetCounts[t.label()]
			total := 0
			for _, c := range counts {
				total += c
			}
			fmt.Printf("  %s (n=%d):\n", t.label(), total)
			for _, v := range []string{cfg.latest, cfg.intermediate, cfg.from} {
				if v == "" || total == 0 {
					continue
				}
				fmt.Printf("    %-14s %d = %.2f%%\n", v, counts[v], 100*float64(counts[v])/float64(total))
			}
		}
	}

	fmt.Println("gating bucket distribution (0-99, 10 bins):")
	for i, c := range hist {
		fmt.Printf("  %2d-%2d: %d\n", i*10, i*10+9, c)
	}
}
