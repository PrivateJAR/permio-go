package permio

import (
	"errors"
	"reflect"
	"testing"
)

func TestValidateAPIKey(t *testing.T) {
	if k, err := ValidateAPIKey(testKey); err != nil || k != APIKeyOpaque {
		t.Fatalf("valid key: %v, %v", k, err)
	}
	if k, err := ValidateAPIKey("aaa.bbb.ccc"); err != nil || k != APIKeyJWT {
		t.Fatalf("jwt: %v, %v", k, err)
	}
	// Last checksum character changed.
	last := "a"
	if testKey[len(testKey)-1] == 'a' {
		last = "b"
	}
	bad := testKey[:len(testKey)-1] + last
	for name, key := range map[string]string{
		"empty":    "",
		"checksum": bad,
		"length":   testKey[:20],
		"alphabet": testKey[:10] + "!" + testKey[11:],
		"garbage":  "not-a-key",
	} {
		if _, err := ValidateAPIKey(key); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same check runs in New, before any network use.
	if _, err := New(Options{APIKey: bad}); !errors.Is(err, ErrConfig) {
		t.Fatalf("New: %v", err)
	}
	t.Setenv(EnvAPIKey, testKey)
	c, err := New(Options{})
	if err != nil {
		t.Fatalf("env key: %v", err)
	}
	_ = c.Close()
}

func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string]struct {
		target string
		tls    bool
	}{
		"":                          {DefaultEndpoint, true},
		"dev-api.perms.io:443":      {"dev-api.perms.io:443", true},
		"https://dev-api.perms.io":  {"dev-api.perms.io:443", true},
		"https://dev-api.perms.io/": {"dev-api.perms.io:443", true},
		"http://localhost:8080":     {"localhost:8080", false},
		"localhost":                 {"localhost:443", true},
	} {
		target, tls, err := parseEndpoint(in)
		if err != nil || target != want.target || tls != want.tls {
			t.Errorf("%q: %q %v %v", in, target, tls, err)
		}
	}
	for _, bad := range []string{"ftp://x", "https://x/path", "https://"} {
		if _, _, err := parseEndpoint(bad); !errors.Is(err, ErrConfig) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestResource(t *testing.T) {
	if got := Resource("projects", "p1", "docs", "a/b c"); got != "/projects/p1/docs/a%2Fb%20c" {
		t.Fatal(got)
	}
	if got := EncodeSegment("x(1)*!'~._-é"); got != "x%281%29%2A%21%27~._-%C3%A9" {
		t.Fatal(got)
	}
	if err := ValidateResourceURI(Resource("docs", "")); err == nil {
		t.Fatal("empty segment accepted")
	}
	for _, ok := range []string{"/a", "/a/b/c", "/tenants/_/docs", "/a%2Fb"} {
		if err := ValidateResourceURI(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "/a/", "//a", "/a b", "/a(1)", "/a*"} {
		if err := ValidateResourceURI(bad); !errors.Is(err, ErrValidation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if GroupPrincipal("eds") != "group:eds" {
		t.Fatal("GroupPrincipal")
	}
}

func TestAccessScopes(t *testing.T) {
	a := &AccessScopes{Under: "/docs", Scopes: []AccessScope{
		{URI: "/docs/1", Kind: ScopeSubtree},
		{URI: "/docs/1/sub", Kind: ScopeSubtree},
		{URI: "/docs/_/public", Kind: ScopePattern},
		{URI: "/docs/x", Kind: ScopeUnknown},
	}}
	re := a.Regexp()
	cases := map[string]bool{
		"/docs/1":          true,
		"/docs/1/a/b":      true,
		"/docs/12":         false, // segment-wise, not string prefix
		"/docs/7/public":   true,
		"/docs/7/public/x": true,
		"/docs/7":          false,
		"/docs/x":          false, // unknown kinds never match
		"docs/1":           false,
	}
	for uri, want := range cases {
		if got := a.Allows(uri); got != want {
			t.Errorf("Allows(%q) = %v, want %v", uri, got, want)
		}
		if got := re.MatchString(uri); got != want {
			t.Errorf("Regexp(%q) = %v, want %v", uri, got, want)
		}
	}
	if got := a.Prefixes(); !reflect.DeepEqual(got, []string{"/docs/1"}) {
		t.Errorf("Prefixes = %v", got)
	}
	if got := a.Patterns(); !reflect.DeepEqual(got, []string{"/docs/_/public"}) {
		t.Errorf("Patterns = %v", got)
	}
	empty := &AccessScopes{Under: "/docs"}
	if !empty.IsEmpty() || empty.Regexp().MatchString("/docs") || empty.Regexp().MatchString("") {
		t.Error("empty scopes")
	}
}
