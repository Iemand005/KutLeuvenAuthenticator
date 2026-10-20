// Command qrscan decodes a QR code from an image file (e.g. a PNG screenshot of
// the enrolment QR) and prints its payload, so you can enrol without a camera.
//
// Usage:
//
//	qrscan path/to/qr.png
//
// The payload is printed raw, as hex, and (if it looks like text) also as a
// string. This is the enrolment QR material that feeds the register command.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"unicode/utf8"

	"kut-leuven-authenticator/internal/qr"
)

func main() {
	asHexOnly := flag.Bool("hex", false, "print only the hex payload")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: qrscan [flags] <image.png>\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	path := flag.Arg(0)
	results, err := qr.DecodeFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "qrscan: %v\n", err)
		os.Exit(1)
	}

	for i, r := range results {
		fmt.Printf("QR #%d  version=%d  ecc=%d  len=%d\n", i+1, r.Version, r.EccLevel, len(r.Payload))
		fmt.Printf("hex   : %s\n", hex.EncodeToString(r.Payload))
		if !*asHexOnly && utf8.Valid(r.Payload) {
			fmt.Printf("text  : %s\n", string(r.Payload))
		}
		fmt.Println()
	}
}
