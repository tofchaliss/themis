package domain

import (
	"errors"
	"strings"
)

// ReleaseID is a Release's opaque, stable identity. It is the identifier the rest of
// Themis references (Evidence's SubjectRef, Governance's Findings/Positions).
type ReleaseID string

// Release is a specific version of a Project and the governance boundary the pipeline
// points at (DOM-0022). Immutable structural identity + membership + version only —
// no security state.
type Release struct {
	id      ReleaseID
	project ProjectID
	version string
}

// NewRelease validates and constructs a Release. Every Release must belong to a
// Project (non-empty project id) and carry a version.
func NewRelease(id ReleaseID, project ProjectID, version string) (Release, error) {
	version = strings.TrimSpace(version)
	switch {
	case id == "":
		return Release{}, errors.New("release: empty id")
	case project == "":
		return Release{}, errors.New("release: empty project id")
	case version == "":
		return Release{}, errors.New("release: empty version")
	}
	return Release{id: id, project: project, version: version}, nil
}

// ID returns the stable release identity.
func (r Release) ID() ReleaseID { return r.id }

// ProjectID returns the owning project's identity.
func (r Release) ProjectID() ProjectID { return r.project }

// Version returns the release version string.
func (r Release) Version() string { return r.version }
