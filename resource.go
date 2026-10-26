package permio

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// MaxResourceURILength is the longest resource URI the API accepts, in bytes.
const MaxResourceURILength = 2048

// Resource builds a resource URI from raw segments, percent-encoding each one
// so that IDs containing "/", spaces or other reserved characters stay a
// single segment:
//
//	uri, err := permio.Resource("projects", projectID, "docs", "a/b") // "/projects/p1/docs/a%2Fb"
//
// Build URIs the same way when granting and when checking, or they will not
// match. It fails with [KindValidation] when given no segments (rather than
// returning "/", which would cover every resource in a grant), an empty
// segment, or segments that make the URI too long.
func Resource(segments ...string) (string, error) {
	if len(segments) == 0 {
		return "", invalid("permio.Resource needs at least one segment")
	}
	var b strings.Builder
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(EncodeSegment(s))
	}
	uri := b.String()
	if err := ValidateResourceURI(uri); err != nil {
		return "", err
	}
	return uri, nil
}

// MustResource is like [Resource] but panics if the URI is invalid. Use it for
// segments known to be non-empty, such as literals.
func MustResource(segments ...string) string {
	uri, err := Resource(segments...)
	if err != nil {
		panic(err)
	}
	return uri
}

// EncodeSegment percent-encodes one resource URI segment. Only A-Z, a-z, 0-9
// and "-_.~" are left as they are (like JavaScript's encodeURIComponent, but
// also encoding "!'()*", which the API rejects in segments).
func EncodeSegment(segment string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// ValidateResourceURI checks the basic shape the API accepts: a leading "/",
// no empty segments (so no "//" or trailing "/"), no whitespace or control
// characters, no regex metacharacters in segments, at most 2048 bytes. Errors
// are of kind [KindValidation].
func ValidateResourceURI(uri string) error {
	fail := func(why string) error { return invalid("invalid resource URI %q: %s", uri, why) }
	if uri == "" {
		return fail("it is empty")
	}
	if !strings.HasPrefix(uri, "/") {
		return fail(`it must start with "/" (use permio.Resource to build URIs)`)
	}
	if len(uri) > MaxResourceURILength {
		return fail(fmt.Sprintf("it is longer than %d bytes", MaxResourceURILength))
	}
	for _, r := range uri {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fail("it contains whitespace or control characters")
		}
		if strings.ContainsRune(`()[]{}*+?|^$\`, r) {
			return fail(fmt.Sprintf("segments may not contain %q", r))
		}
	}
	for _, seg := range strings.Split(uri[1:], "/") {
		if seg == "" {
			return fail("it contains an empty segment")
		}
	}
	return nil
}

// GroupPrefix starts the principal ID of every group.
const GroupPrefix = "group:"

var groupSlug = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// GroupPrincipal returns the principal ID of the group with this slug,
// "group:<slug>". Grant to it, or check it, like any other principal; every
// member of the group holds what the group is granted.
func GroupPrincipal(slug string) string { return GroupPrefix + slug }

// ValidateGroupName checks a group slug: 1-64 lower-case letters, digits and
// hyphens. Errors are of kind [KindValidation].
func ValidateGroupName(slug string) error {
	if !groupSlug.MatchString(slug) {
		return invalid("invalid group name %q: use 1-64 lower-case letters, digits and hyphens", slug)
	}
	return nil
}

// groupSlugOf accepts a slug or a "group:<slug>" principal ID.
func groupSlugOf(nameOrPrincipal string) (string, error) {
	slug := strings.TrimPrefix(nameOrPrincipal, GroupPrefix)
	return slug, ValidateGroupName(slug)
}

func uniq(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
