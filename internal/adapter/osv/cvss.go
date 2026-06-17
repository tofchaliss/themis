package osv

import (
	"math"
	"strconv"
	"strings"
)

// parseCVSSScore returns a numeric base score and vector from an OSV severity score field.
func parseCVSSScore(score string) (float64, string) {
	score = strings.TrimSpace(score)
	if score == "" {
		return 0, ""
	}
	if strings.HasPrefix(score, "CVSS:") {
		if base, ok := cvssV3BaseScore(score); ok {
			return base, score
		}
		return 0, score
	}
	if f, err := strconv.ParseFloat(score, 64); err == nil {
		return f, ""
	}
	return 0, ""
}

func cvssV3BaseScore(vector string) (float64, bool) {
	metrics, scope, ok := parseCVSSMetrics(vector)
	if !ok {
		return 0, false
	}
	scopeChanged := scope == "C"

	impactSub := 1 - (1-metrics["C"])*(1-metrics["I"])*(1-metrics["A"])
	var impact float64
	if scopeChanged {
		impact = 7.52*(impactSub-0.029) - 3.25*math.Pow(impactSub-0.02, 15)
	} else {
		impact = 6.42 * impactSub
	}
	if impact <= 0 {
		return 0, true
	}
	exploit := 8.22 * metrics["AV"] * metrics["AC"] * metrics["PR"] * metrics["UI"]
	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploit), 10)
	} else {
		base = math.Min(impact+exploit, 10)
	}
	return roundUp1(base), true
}

func roundUp1(v float64) float64 {
	return math.Ceil(v*10) / 10
}

func parseCVSSMetrics(vector string) (map[string]float64, string, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return nil, "", false
	}
	raw := map[string]string{}
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		raw[kv[0]] = kv[1]
	}
	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, key := range required {
		if _, ok := raw[key]; !ok {
			return nil, "", false
		}
	}
	out := map[string]float64{
		"AV": metricValue("AV", raw["AV"]),
		"AC": metricValue("AC", raw["AC"]),
		"PR": metricValue("PR", raw["PR"], raw["S"]),
		"UI": metricValue("UI", raw["UI"]),
		"C":  metricValue("C", raw["C"]),
		"I":  metricValue("I", raw["I"]),
		"A":  metricValue("A", raw["A"]),
	}
	for _, v := range out {
		if v < 0 {
			return nil, "", false
		}
	}
	return out, raw["S"], true
}

func metricValue(key, val string, scope ...string) float64 {
	switch key {
	case "AV":
		switch val {
		case "N":
			return 0.85
		case "A":
			return 0.62
		case "L":
			return 0.55
		case "P":
			return 0.2
		}
	case "AC":
		switch val {
		case "L":
			return 0.77
		case "H":
			return 0.44
		}
	case "PR":
		unchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
		changed := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
		if len(scope) > 0 && scope[0] == "C" {
			if v, ok := changed[val]; ok {
				return v
			}
		} else if v, ok := unchanged[val]; ok {
			return v
		}
	case "UI":
		switch val {
		case "N":
			return 0.85
		case "R":
			return 0.62
		}
	case "C", "I", "A":
		switch val {
		case "H":
			return 0.56
		case "L":
			return 0.22
		case "N":
			return 0
		}
	}
	return -1
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func extractCVSSFromSeverity(severity []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) (score float64, vector string) {
	for _, item := range severity {
		t := strings.ToUpper(item.Type)
		if t != "CVSS_V3" && t != "CVSS_V4" && t != "CVSSV3" {
			continue
		}
		if s, v := parseCVSSScore(item.Score); s > 0 || v != "" {
			return s, v
		}
	}
	for _, item := range severity {
		if s, v := parseCVSSScore(item.Score); s > 0 || v != "" {
			return s, v
		}
	}
	return 0, ""
}
