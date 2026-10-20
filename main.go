// Command kut-leuven-authenticator is a minimal, dependency-light Go client for
// the KU Leuven NextAuth authenticator protocol.
//
// Subcommands:
//
//	register   open the sigmai WebSocket for app registration (enrolment)
//	qrscan     decode a QR code from an image file (no camera needed)
//
// Run `go run ./cmd/register` or `go run ./cmd/qrscan` directly for each tool.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "kut-leuven-authenticator")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "This module exposes tools under cmd/:")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/register [-channel mc|sfs] [-url wss://...]")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/qrscan path/to/qr.png")
	os.Exit(2)
}
