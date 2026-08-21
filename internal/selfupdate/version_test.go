package selfupdate

import "testing"

func mustParse(t *testing.T, raw string) Version {
	t.Helper()
	parsed, ok := ParseVersion(raw)
	if !ok {
		t.Fatalf("could not parse %q", raw)
	}
	return parsed
}

func TestBothTagAndLdflagsSpellingsParse(t *testing.T) {
	// The git tag carries a v, the -ldflags value has it stripped, and both
	// reach this code.
	withV := mustParse(t, "v1.4.2")
	without := mustParse(t, "1.4.2")

	if withV.NewerThan(without) || without.NewerThan(withV) {
		t.Error("v1.4.2 and 1.4.2 should be the same version")
	}
}

func TestOrdering(t *testing.T) {
	cases := []struct{ newer, older string }{
		{"1.0.1", "1.0.0"},
		{"1.1.0", "1.0.9"},
		{"2.0.0", "1.99.99"},
		{"0.3.0", "0.2.9"},
		// A double-digit component: string comparison would get this wrong,
		// which is the classic version-sorting bug.
		{"1.10.0", "1.9.0"},
		{"1.0.10", "1.0.9"},
	}
	for _, c := range cases {
		if !mustParse(t, c.newer).NewerThan(mustParse(t, c.older)) {
			t.Errorf("%s should be newer than %s", c.newer, c.older)
		}
		if mustParse(t, c.older).NewerThan(mustParse(t, c.newer)) {
			t.Errorf("%s should not be newer than %s", c.older, c.newer)
		}
	}
}

func TestTheSameVersionIsNotNewerThanItself(t *testing.T) {
	// This is what makes running update twice a no-op rather than a second
	// download of the same bytes.
	same := mustParse(t, "1.2.3")

	if same.NewerThan(same) {
		t.Error("a version is newer than itself")
	}
}

func TestAReleaseBeatsItsOwnPreRelease(t *testing.T) {
	if !mustParse(t, "1.0.0").NewerThan(mustParse(t, "1.0.0-rc1")) {
		t.Error("1.0.0 should be newer than 1.0.0-rc1")
	}
	if mustParse(t, "1.0.0-rc1").NewerThan(mustParse(t, "1.0.0")) {
		t.Error("a release candidate should not replace the release")
	}
}

func TestBuildMetadataDoesNotAffectOrdering(t *testing.T) {
	// Semver is explicit that build metadata is not part of precedence.
	// Treating it as such would make two builds of one version look different.
	plain := mustParse(t, "1.2.3")
	stamped := mustParse(t, "1.2.3+abc1234")

	if plain.NewerThan(stamped) || stamped.NewerThan(plain) {
		t.Error("build metadata changed the ordering")
	}
}

func TestDevelopmentBuildsAreNotVersions(t *testing.T) {
	// The guard that stops a locally compiled binary being silently swapped
	// for a release. Someone running a build they made has a reason to.
	for _, raw := range []string{"dev", "", "0.0.0-dev+abc1234"} {
		parsed, ok := ParseVersion(raw)
		if raw != "0.0.0-dev+abc1234" && ok {
			t.Errorf("%q parsed as a release version", raw)
		}
		if !parsed.Development() {
			t.Errorf("%q was not recognised as a development build", raw)
		}
	}
}

func TestAReleaseIsNotMistakenForADevelopmentBuild(t *testing.T) {
	if mustParse(t, "1.2.3").Development() {
		t.Error("a real release was treated as a development build")
	}
}

func TestNonsenseDoesNotParse(t *testing.T) {
	for _, raw := range []string{"banana", "1.2", "1.2.3.4", "1.x.3", "-1.0.0", "v"} {
		if _, ok := ParseVersion(raw); ok {
			t.Errorf("%q was accepted as a version", raw)
		}
	}
}
