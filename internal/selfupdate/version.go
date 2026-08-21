package selfupdate

import (
	"strconv"
	"strings"
)

// Version comparison, deliberately small.
//
// Only what the release process actually produces: a tag like v1.4.2, and the
// 0.0.0-dev+abc1234 that a build off an untagged commit gets. A full semver
// implementation would be more code than the thing it decides, and the
// decision it makes -- whether to overwrite the binary the user is running --
// is one where "I do not understand this version, so I will do nothing" is a
// perfectly good answer.

// Version is a parsed release number.
type Version struct {
	Major, Minor, Patch int
	// PreRelease is the bit after a hyphen, if any. Its presence is what
	// matters more than its content: 1.0.0-rc1 is older than 1.0.0.
	PreRelease string
	// Raw is the string it was parsed from, for printing back.
	Raw string
}

// Development reports whether this is a locally built binary rather than a
// release.
//
// Such a build is never replaced automatically. Somebody running a binary they
// compiled has a reason to be running it, and silently swapping it for a
// release would throw away whatever they were testing.
func (v Version) Development() bool {
	return v.Raw == "" || v.Raw == "dev" || strings.Contains(v.Raw, "dev")
}

// ParseVersion reads a version string. ok is false if it is not one.
func ParseVersion(raw string) (Version, bool) {
	trimmed := strings.TrimSpace(raw)
	parsed := Version{Raw: trimmed}

	if trimmed == "" || trimmed == "dev" {
		return parsed, false
	}

	// Both "v1.2.3" and "1.2.3" appear: the git tag carries the v, the
	// -ldflags value has it stripped, and a user typing one at a prompt could
	// write either.
	numbers := strings.TrimPrefix(trimmed, "v")

	if plus := strings.IndexByte(numbers, '+'); plus >= 0 {
		// Build metadata is explicitly not part of precedence in semver, and
		// treating it as such would make two builds of the same version look
		// different to each other.
		numbers = numbers[:plus]
	}
	if hyphen := strings.IndexByte(numbers, '-'); hyphen >= 0 {
		parsed.PreRelease = numbers[hyphen+1:]
		numbers = numbers[:hyphen]
	}

	fields := strings.Split(numbers, ".")
	if len(fields) != 3 {
		return parsed, false
	}

	targets := []*int{&parsed.Major, &parsed.Minor, &parsed.Patch}
	for i, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil || value < 0 {
			return parsed, false
		}
		*targets[i] = value
	}
	return parsed, true
}

// NewerThan reports whether v is a later release than other.
//
// Strictly later. Equal versions return false, which is what makes "already up
// to date" the outcome of running update twice rather than a second download.
func (v Version) NewerThan(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	if v.Patch != other.Patch {
		return v.Patch > other.Patch
	}

	// Same numbers. A release beats a pre-release of itself, and two
	// pre-releases compare as text, which is right for rc1 vs rc2 and is not
	// worth more machinery than that.
	switch {
	case v.PreRelease == "" && other.PreRelease != "":
		return true
	case v.PreRelease != "" && other.PreRelease == "":
		return false
	default:
		return v.PreRelease > other.PreRelease
	}
}

// String renders the version the way it was written.
func (v Version) String() string {
	if v.Raw != "" {
		return v.Raw
	}
	return "unknown"
}
