// Package config holds the KU Leuven NextAuth deployment parameters decoded
// from resources/assets/nextauth.json (a base64 URL-safe protobuf blob).
package config

// Channel identifies a sigmai endpoint.
type Channel string

const (
	ChannelMC  Channel = "mc"  // main channel
	ChannelSFS Channel = "sfs" // second-factor / step-up channel
)

// Endpoint is a sigmai WebSocket endpoint.
type Endpoint struct {
	Channel Channel
	URL     string
}

// KULeuven is the decoded deployment configuration.
var KULeuven = struct {
	MC  Endpoint
	SFS Endpoint

	WebHost   string
	MCHost    string
	SFSHost   string
	LinkBase  string // universalLinkPathPrefix, e.g. /apps/authenticator
	AccountURL string

	// Feature flags observed in the config blob.
	AutomaticallySelectSingleAccountWhenSecondFactorNeeded bool
	MaxNumberSecondFactorWithoutPin                        int
	MaxTimeSecondFactorWithoutPin                          string
	LegacyBioAddFlow                                       bool
	LegacyUserInteraction                                  bool

	Environment string
}{
	MC:        Endpoint{Channel: ChannelMC, URL: "wss://authenticator-mc.icts.kuleuven.be/mc/sigmai"},
	SFS:       Endpoint{Channel: ChannelSFS, URL: "wss://authenticator-sfs.icts.kuleuven.be/sfs/sigmai"},
	WebHost:   "authenticator.icts.kuleuven.be",
	MCHost:    "authenticator-mc.icts.kuleuven.be",
	SFSHost:   "authenticator-sfs.icts.kuleuven.be",
	LinkBase:  "/apps/authenticator",
	AccountURL: "https://account.kuleuven.be/mfa?origin=authenticator",

	AutomaticallySelectSingleAccountWhenSecondFactorNeeded: false,
	MaxNumberSecondFactorWithoutPin:                        30,
	MaxTimeSecondFactorWithoutPin:                          "720h",
	LegacyBioAddFlow:                                       true,
	LegacyUserInteraction:                                  true,

	Environment: "production",
}
