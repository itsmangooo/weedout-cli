package api

// Plan is the single Free capability set reported by the server.
//
// The CLI exposes this metadata in JSON responses; enforcement remains
// server-side. Legacy servers may omit the block entirely.
type Plan struct {
	Tier              string `json:"tier"`
	Name              string `json:"name"`
	ScanDepth         *int   `json:"scan_depth"`
	CustomRules       bool   `json:"custom_rules"`
	ScanIntervalHours int    `json:"scan_interval_hours"`
	MaxProjects       *int   `json:"max_projects"`
}
