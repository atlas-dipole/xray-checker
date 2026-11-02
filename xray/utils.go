package xray

import (
	"fmt"
	"sort"
	"strings"

	"xray-checker/models"
)

func PrepareProxyConfigs(proxies []*models.ProxyConfig) {
	for i := range proxies {
		proxies[i].Index = i
	}
	// Assign final StableIDs over the whole set so that identical-connection configs
	// are separated deterministically (see models.AssignStableIDs).
	models.AssignStableIDs(proxies)
}

// configSignature includes local source binding and custom metrics labels so
// changes to these fields trigger a refresh without changing the public stable ID.
func configSignature(cfg *models.ProxyConfig) string {
	base := fmt.Sprintf("%s|sendThrough=%d:%s", cfg.GenerateStableID(), len(cfg.SendThrough), cfg.SendThrough)
	if len(cfg.MetricsLabels) == 0 {
		return base
	}
	keys := make([]string, 0, len(cfg.MetricsLabels))
	for k := range cfg.MetricsLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(base)
	for _, k := range keys {
		sb.WriteString("\x1f")
		sb.WriteString(k)
		sb.WriteString("\x1e")
		sb.WriteString(cfg.MetricsLabels[k])
	}
	return sb.String()
}

func IsConfigsEqual(old, new []*models.ProxyConfig) bool {
	if len(old) != len(new) {
		return false
	}

	// Compare on the content signature (connection hash + custom-label fingerprint),
	// not the assigned StableID which may carry a collision suffix, so the comparison
	// is independent of dedup ordering and detects genuine subscription changes —
	// including a custom-label edit on an otherwise-unchanged proxy.
	oldCounts := make(map[string]int, len(old))
	newCounts := make(map[string]int, len(new))

	for _, cfg := range old {
		oldCounts[configSignature(cfg)]++
	}
	for _, cfg := range new {
		newCounts[configSignature(cfg)]++
	}

	if len(oldCounts) != len(newCounts) {
		return false
	}
	for sig, n := range oldCounts {
		if newCounts[sig] != n {
			return false
		}
	}

	return true
}
