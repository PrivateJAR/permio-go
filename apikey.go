package permio

import (
	"hash/crc32"
	"regexp"
	"strings"
)

// API key format, mirroring the server: "perms_" + 32 random base62 characters
// + 6 base62 characters encoding the CRC32 (IEEE) of those 32, 44 in total.
const (
	apiKeyPrefix         = "perms_"
	apiKeyRandomLength   = 32
	apiKeyChecksumLength = 6
	// APIKeyLength is the length of an opaque "perms_" API key.
	APIKeyLength = len(apiKeyPrefix) + apiKeyRandomLength + apiKeyChecksumLength
	base62       = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// APIKeyKind says which form an API key has.
type APIKeyKind string

const (
	// APIKeyOpaque is a "perms_" key from the dashboard.
	APIKeyOpaque APIKeyKind = "opaque"
	// APIKeyJWT is a legacy JWT key.
	APIKeyJWT APIKeyKind = "jwt"
)

var jwtShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// ValidateAPIKey checks that key looks like a perms.io API key and returns its
// kind. Opaque "perms_" keys are checked for length, alphabet and checksum, so
// a typo is caught before any request is made; legacy JWT keys only for their
// three-part shape. Only the API can say whether a key exists and is valid.
// Errors are of kind [KindConfig].
func ValidateAPIKey(key string) (APIKeyKind, error) {
	if key == "" {
		return "", configError("an API key is required (Options.APIKey or PERMIO_API_KEY)")
	}
	if strings.HasPrefix(key, apiKeyPrefix) {
		if len(key) != APIKeyLength {
			return "", configError("malformed API key (expected %d characters starting with %q, got %d)", APIKeyLength, apiKeyPrefix, len(key))
		}
		rest := key[len(apiKeyPrefix):]
		for _, r := range rest {
			if !strings.ContainsRune(base62, r) {
				return "", configError("malformed API key (characters after perms_ must be 0-9, A-Z or a-z)")
			}
		}
		if apiKeyChecksum(rest[:apiKeyRandomLength]) != rest[apiKeyRandomLength:] {
			return "", configError("API key checksum mismatch; check it was copied correctly")
		}
		return APIKeyOpaque, nil
	}
	if jwtShape.MatchString(key) {
		return APIKeyJWT, nil
	}
	return "", configError(`malformed API key (expected a "perms_" key from the dashboard, or a legacy JWT key)`)
}

func apiKeyChecksum(body string) string {
	v := crc32.ChecksumIEEE([]byte(body))
	out := make([]byte, apiKeyChecksumLength)
	for i := apiKeyChecksumLength - 1; i >= 0; i-- {
		out[i] = base62[v%62]
		v /= 62
	}
	return string(out)
}
