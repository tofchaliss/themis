package api

import (
	"encoding/json"
	"io"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/themis-project/themis/internal/adapter/api/gen"
	"github.com/themis-project/themis/internal/domain"
)

func jsonNewDecoder(r io.Reader, dst any) error {
	return json.NewDecoder(r).Decode(dst)
}

func toProduct(p domain.Product) gen.Product {
	return gen.Product{
		Id:          parseUUID(p.ID),
		Name:        p.Name,
		Description: ptrString(p.Description),
		CreatedAt:   ptrTime(p.CreatedAt),
	}
}

func toProductList(items []domain.Product, page domain.PageResult) gen.ProductList {
	out := make([]gen.Product, 0, len(items))
	for _, item := range items {
		out = append(out, toProduct(item))
	}
	resp := gen.ProductList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toProject(p domain.Project) gen.Project {
	return gen.Project{
		Id:          parseUUID(p.ID),
		ProductId:   parseUUID(p.ProductID),
		Name:        p.Name,
		Description: ptrString(p.Description),
		CreatedAt:   ptrTime(p.CreatedAt),
	}
}

func toProjectList(items []domain.Project, page domain.PageResult) gen.ProjectList {
	out := make([]gen.Project, 0, len(items))
	for _, item := range items {
		out = append(out, toProject(item))
	}
	resp := gen.ProjectList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toProductVersion(v domain.ProductVersion) gen.ProductVersion {
	return gen.ProductVersion{
		Id:            parseUUID(v.ID),
		ProductId:     parseUUID(v.ProductID),
		Version:       v.Version,
		ReleaseStatus: ptrString(v.ReleaseStatus),
	}
}

func toProductVersionList(items []domain.ProductVersion, page domain.PageResult) gen.ProductVersionList {
	out := make([]gen.ProductVersion, 0, len(items))
	for _, item := range items {
		out = append(out, toProductVersion(item))
	}
	resp := gen.ProductVersionList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toScanSummary(s domain.ScanSummary) gen.ScanSummary {
	return gen.ScanSummary{
		Id:          parseUUID(s.ID),
		ProjectId:   parseUUID(s.ProjectID),
		ImageDigest: ptrString(s.ImageDigest),
		Format:      ptrString(s.Format),
		TrustStatus: ptrString(s.TrustStatus),
		IngestedAt:  ptrTime(s.IngestedAt),
	}
}

func toScanList(items []domain.ScanSummary, page domain.PageResult) gen.ScanList {
	out := make([]gen.ScanSummary, 0, len(items))
	for _, item := range items {
		out = append(out, toScanSummary(item))
	}
	resp := gen.ScanList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toScanDetail(s domain.ScanDetail) gen.ScanDetail {
	counts := s.VulnerabilityCounts
	return gen.ScanDetail{
		Id:                  parseUUID(s.ID),
		ProjectId:           parseUUID(s.ProjectID),
		ImageDigest:         ptrString(s.ImageDigest),
		Format:              ptrString(s.Format),
		TrustStatus:         ptrString(s.TrustStatus),
		IngestedAt:          ptrTime(s.IngestedAt),
		VulnerabilityCounts: &counts,
		IngestionId:          uuidPtr(s.IngestionID),
	}
}

func uuidPtr(id string) *openapi_types.UUID {
	if id == "" {
		return nil
	}
	parsed := parseUUID(id)
	return &parsed
}

func toScanVulnerabilityList(items []domain.ScanVulnerability, page domain.PageResult) gen.ScanVulnerabilityList {
	out := make([]gen.ScanVulnerability, 0, len(items))
	for _, item := range items {
		out = append(out, gen.ScanVulnerability{
			Id:             parseUUID(item.ID),
			CveId:          item.CVEID,
			Severity:       item.Severity,
			EffectiveState: ptrString(item.EffectiveState),
			ComponentPurl:  ptrString(item.ComponentPURL),
		})
	}
	resp := gen.ScanVulnerabilityList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toComponentList(items []domain.CatalogComponent, page domain.PageResult) gen.ComponentList {
	out := make([]gen.Component, 0, len(items))
	for _, item := range items {
		out = append(out, gen.Component{
			Purl:      item.PURL,
			Name:      item.Name,
			Ecosystem: item.Ecosystem,
			Version:   ptrString(item.Version),
		})
	}
	resp := gen.ComponentList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toCVEWatchList(items []domain.CVEWatchFinding, page domain.PageResult) gen.CVEWatchFindingList {
	out := make([]gen.CVEWatchFinding, 0, len(items))
	for _, item := range items {
		out = append(out, gen.CVEWatchFinding{
			Id:         parseUUID(item.ID),
			CveId:      item.CVEID,
			ProductId:  uuidPtr(item.ProductID),
			ProjectId:  uuidPtr(item.ProjectID),
			Status:     item.Status,
			DetectedAt: ptrTime(item.DetectedAt),
		})
	}
	resp := gen.CVEWatchFindingList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func toNotificationRules(rules []domain.NotificationRule) []gen.NotificationRule {
	out := make([]gen.NotificationRule, 0, len(rules))
	for _, rule := range rules {
		enabled := rule.Enabled
		out = append(out, gen.NotificationRule{
			Name:        rule.Name,
			EventType:   rule.EventType,
			Channel:     gen.NotificationRuleChannel(rule.Channel),
			Destination: rule.Destination,
			Enabled:     &enabled,
		})
	}
	return out
}

func ptrRules(rules []gen.NotificationRule) *[]gen.NotificationRule {
	return &rules
}

func fromNotificationRules(rules *[]gen.NotificationRule) []domain.NotificationRule {
	if rules == nil {
		return nil
	}
	out := make([]domain.NotificationRule, 0, len(*rules))
	for _, rule := range *rules {
		enabled := true
		if rule.Enabled != nil {
			enabled = *rule.Enabled
		}
		out = append(out, domain.NotificationRule{
			Name:        rule.Name,
			EventType:   rule.EventType,
			Channel:     string(rule.Channel),
			Destination: rule.Destination,
			Enabled:     enabled,
		})
	}
	return out
}

func toScannerConfig(settings domain.ScannerSettings) gen.ScannerConfig {
	return gen.ScannerConfig{
		EnabledFormats:      &settings.EnabledFormats,
		MaxComponents:       &settings.MaxComponents,
		ParseTimeoutSeconds: &settings.ParseTimeoutSeconds,
	}
}

func fromScannerConfig(cfg gen.ScannerConfig) domain.ScannerSettings {
	settings := domain.ScannerSettings{}
	if cfg.EnabledFormats != nil {
		settings.EnabledFormats = *cfg.EnabledFormats
	}
	if cfg.MaxComponents != nil {
		settings.MaxComponents = *cfg.MaxComponents
	}
	if cfg.ParseTimeoutSeconds != nil {
		settings.ParseTimeoutSeconds = *cfg.ParseTimeoutSeconds
	}
	return settings
}

func toTriageHistoryList(items []domain.TriageHistoryEntry, page domain.PageResult) gen.TriageHistoryList {
	out := make([]gen.TriageHistoryEntry, 0, len(items))
	for _, item := range items {
		out = append(out, gen.TriageHistoryEntry{
			Decision:      item.Decision,
			Justification: item.Justification,
			Actor:         ptrString(item.Actor),
			RecordedAt:    item.RecordedAt,
		})
	}
	resp := gen.TriageHistoryList{Items: &out}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}
