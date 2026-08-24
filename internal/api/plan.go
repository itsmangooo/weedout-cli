package api

// Plan is what the account can do, as the server reports it on every response.
//
// It exists so the CLI can notice a plan change and say so. A CLI cannot be
// pushed to — it runs, prints and exits, and there is nothing to send an event
// at — so the honest version of "in real time" is that the very next command
// reflects the change and mentions it once.
//
// Nothing here is trusted for a decision. The server enforces every limit, and
// a client that decided for itself what a plan allows would be a client
// somebody could edit. This is for describing what happened, not for gating.
type Plan struct {
	// Tier is "free" or "pro". Empty from a server that predates this field,
	// which is the case the CLI has to stay quiet about rather than announce
	// as a downgrade.
	Tier string `json:"tier"`
	// Name is what to call it in a sentence: "Free", "Pro".
	Name string `json:"name"`
	// ScanDepth is how deep a scan reaches, or nil for the whole tree. The
	// same convention as the server's own policy, so there is not a second one
	// to learn.
	ScanDepth *int `json:"scan_depth"`
	// CustomRules is whether severity floors, ignore rules and .weedout.yml
	// apply at all.
	CustomRules bool `json:"custom_rules"`
	// ScanIntervalHours is how often the scheduler re-checks a project.
	ScanIntervalHours int `json:"scan_interval_hours"`
	// MaxProjects is nil for unlimited.
	MaxProjects *int `json:"max_projects"`
}

// Known reports whether the server said anything about the plan.
//
// A server older than this field sends nothing, and an empty Plan must read as
// "no information" rather than as a downgrade — announcing a plan change that
// did not happen would be worse than announcing nothing.
func (p Plan) Known() bool { return p.Tier != "" }

// Describes returns what changed, in one sentence, or "" when nothing did.
//
// Written as a capability rather than a label. "You are on Pro" tells somebody
// what they already know from their receipt; "scans now reach the whole
// dependency tree" tells them what is different about the thing they just ran.
func (p Plan) Describes(previous string) string {
	if !p.Known() || previous == "" || previous == p.Tier {
		return ""
	}

	switch {
	case p.ScanDepth == nil && p.CustomRules:
		return "Your plan is now " + p.Name +
			". Scans reach the whole dependency tree, and your custom rules apply."
	case p.ScanDepth == nil:
		return "Your plan is now " + p.Name + ". Scans reach the whole dependency tree."
	case !p.CustomRules:
		// The downgrade sentence, and the one that has to be plainest. Somebody
		// whose rules have stopped applying needs to know before they read a
		// result that was produced without them.
		return "Your plan is now " + p.Name +
			". Scans stop after direct dependencies and theirs, and your custom rules no " +
			"longer apply — they are kept, not deleted."
	default:
		return "Your plan is now " + p.Name + "."
	}
}
