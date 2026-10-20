// Package qr decodes QR codes from image files (e.g. PNG screenshots of the
// enrolment QR), without a camera. It uses the pure-Go github.com/liyue201/goqr
// recognizer (which includes perspective correction) over the standard library
// image decoders.
package qr

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"

	"github.com/liyue201/goqr"
)

// Result is a decoded QR payload.
type Result struct {
	Payload []byte
	Version int
	EccLevel int
}

// DecodeFile opens path, decodes the image, and returns all QR codes found.
func DecodeFile(path string) ([]Result, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("qr: decode image: %w", err)
	}
	return DecodeImage(img)
}

// DecodeImage returns all QR codes found in img.
func DecodeImage(img image.Image) ([]Result, error) {
	codes, err := goqr.Recognize(img)
	if err != nil {
		return nil, fmt.Errorf("qr: recognize: %w", err)
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("qr: no QR code found")
	}
	out := make([]Result, 0, len(codes))
	for _, c := range codes {
		out = append(out, Result{
			Payload:  c.Payload,
			Version:  c.Version,
			EccLevel: c.EccLevel,
		})
	}
	return out, nil
}
