package domain

import "strings"

// MatchedComponent is one release component that triggered a Finding, carried in from
// Knowledge's ComponentMatched (D1/D5). It is **content/context** on the Finding, never
// part of its identity: one Finding may list several matched components for the same
// (Release, Faultline), all governed as one decision. The PURL is the dedup key.
type MatchedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
}

// validComponent reports an error unless the component carries a non-empty PURL (its
// identity within the Finding).
func validComponent(c MatchedComponent) error {
	if strings.TrimSpace(c.PURL) == "" {
		return errEmptyComponentURL
	}
	return nil
}
