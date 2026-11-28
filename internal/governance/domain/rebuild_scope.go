package domain

import "strings"

// Which Releases take part in the rebuild policy, and with which mode (EDR-REBUILD-01 D4, D17).
// A Release takes part only by tag: its own, or its Project's, or its Product's. A tag can only
// restrict what the policies allow. Pure: this file reads tag lists and returns a mode.

// The three rebuild tags (D4).
const (
	RebuildTagAuto = "rebuild:auto"
	RebuildTagAsk  = "rebuild:ask"
	RebuildTagOff  = "rebuild:off"
)

// Where a rebuild tag was found. There IS a Project level for tags (D4), unlike for policies.
const (
	RebuildTagLevelRelease = "release"
	RebuildTagLevelProject = "project"
	RebuildTagLevelProduct = "product"
)

// RebuildModeSetByTag names the tag as the value that set the effective mode (D17 value 3). It
// is also what a Release with no rebuild tag reads: the missing tag is what keeps it out.
const RebuildModeSetByTag = "tag"

// RebuildTagMode is what the tags of one Release say (D17 value 3).
type RebuildTagMode struct {
	// Mode is off when a `rebuild:off` tag sits on any level or when no rebuild tag exists at
	// all; otherwise ask or auto, from the nearest level that carries one.
	Mode RebuildMode
	// Tag is the tag that decided, "" when the Release carries no rebuild tag on any level.
	Tag string
	// Level is where that tag sits, "" with no tag.
	Level string
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.ToLower(strings.TrimSpace(t)) == want {
			return true
		}
	}
	return false
}

// ResolveRebuildTag reads the own tags of a Release, its Project and its Product (D4, D17):
//
//  1. `rebuild:off` on any of the three always wins (the nearest one is named);
//  2. otherwise the nearest level carrying `rebuild:auto` or `rebuild:ask` decides, and a level
//     carrying both reads `ask`, because a tag can only restrict;
//  3. no rebuild tag at all is off: the Release takes no part.
func ResolveRebuildTag(release, project, product []string) RebuildTagMode {
	levels := []struct {
		name string
		tags []string
	}{
		{RebuildTagLevelRelease, release}, {RebuildTagLevelProject, project}, {RebuildTagLevelProduct, product},
	}
	for _, l := range levels {
		if hasTag(l.tags, RebuildTagOff) {
			return RebuildTagMode{Mode: RebuildModeOff, Tag: RebuildTagOff, Level: l.name}
		}
	}
	for _, l := range levels {
		switch {
		case hasTag(l.tags, RebuildTagAsk):
			return RebuildTagMode{Mode: RebuildModeAsk, Tag: RebuildTagAsk, Level: l.name}
		case hasTag(l.tags, RebuildTagAuto):
			return RebuildTagMode{Mode: RebuildModeAuto, Tag: RebuildTagAuto, Level: l.name}
		}
	}
	return RebuildTagMode{Mode: RebuildModeOff}
}

// EffectiveRebuildMode is D17 whole: the lowest of the installation policy's mode, the mode of
// the policy in force (both already folded into ceiling) and the tag. setBy names the value that
// set it; when the tag and the ceiling give the same mode the ceiling's setter is named, because
// lifting the tag alone would change nothing.
func EffectiveRebuildMode(ceiling RebuildMode, ceilingSetBy string, tag RebuildTagMode) (mode RebuildMode, setBy string) {
	mode = LowestRebuildMode(ceiling, tag.Mode)
	if tag.Mode.rank() < ceiling.rank() {
		return mode, RebuildModeSetByTag
	}
	return mode, ceilingSetBy
}

// Rebuild outcomes: what the effective mode and the count give for one Release (D5, D9).
const (
	// RebuildOutcomeNone: nothing is asked for.
	RebuildOutcomeNone = "none"
	// RebuildOutcomeRecommend: mode ask, and at least one component counts. A person decides.
	RebuildOutcomeRecommend = "recommend"
	// RebuildOutcomeRequest: mode auto, and at least one component counts.
	RebuildOutcomeRequest = "request"
)

// RebuildOutcome names what the policy would do for a Release with this effective mode and this
// many counted components. It starts nothing.
func RebuildOutcome(mode RebuildMode, targeted int) string {
	if targeted <= 0 {
		return RebuildOutcomeNone
	}
	switch mode {
	case RebuildModeAuto:
		return RebuildOutcomeRequest
	case RebuildModeAsk:
		return RebuildOutcomeRecommend
	default:
		return RebuildOutcomeNone
	}
}
