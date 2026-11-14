package xray

import (
	"encoding/json"

	"xray-checker/logger"
	"xray-checker/models"
)

// DeduplicateProxyConfigs keeps one generated connection within a subscription,
// preferring the name of a standalone node over an alias from a multi-node profile.
// Names and assigned indices are aliases;
// credentials and every generated transport option are part of the comparison.
func DeduplicateProxyConfigs(proxies []*models.ProxyConfig) []*models.ProxyConfig {
	result := make([]*models.ProxyConfig, 0, len(proxies))
	seen := make(map[string]int, len(proxies))
	g := NewConfigGenerator()
	for _, proxy := range proxies {
		outbound := g.GenerateProxyOutbound(proxy)
		delete(outbound, "tag")
		key, err := json.Marshal(struct {
			Outbound     map[string]interface{}
			Subscription string
			Labels       map[string]string
		}{outbound, proxy.SubName, proxy.MetricsLabels})
		if err != nil {
			// Keep malformed configurations for the normal validation path.
			result = append(result, proxy)
			continue
		}
		if index, exists := seen[string(key)]; exists {
			if result[index].FromMultiNodeProfile && !proxy.FromMultiNodeProfile {
				result[index] = proxy
			}
			continue
		}
		seen[string(key)] = len(result)
		result = append(result, proxy)
	}
	for i, proxy := range result {
		proxy.Index = i
	}
	if removed := len(proxies) - len(result); removed > 0 {
		logger.Info("Removed %d duplicate proxy configurations; %d unique remain", removed, len(result))
	}
	return result
}
