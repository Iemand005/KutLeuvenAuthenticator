// Command watchlogin watches a folder for a newly dropped login-QR screenshot
// and immediately runs the browser oracle (wsswatch) plus the ns approval
// probes (nsprobe -mode auth) for a set of variants.
//
// It shells out to bin/wsswatch.exe and bin/nsprobe.exe so the exact same code
// paths as manual testing are used.
//
// Usage:
//
//	watchlogin -dir "C:\...\ballbag" -variants 1,5,6,7 -wait 10m
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", `C:\Users\Lasse\Downloads\New folder (2)\ballbag`, "folder to watch")
	bin := flag.String("bin", `.\bin`, "folder containing wsswatch.exe and nsprobe.exe")
	root := flag.String("root", `.`, "working directory for the child processes")
	variants := flag.String("variants", "1,5,6,7", "comma-separated auth variants to try")
	wait := flag.Duration("wait", 10*time.Minute, "how long to watch")
	poll := flag.Duration("poll", 400*time.Millisecond, "poll interval")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	seen := map[string]time.Time{}
	entries, _ := os.ReadDir(*dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			seen[e.Name()] = info.ModTime()
		}
	}
	log.Printf("watching %s for new PNGs (variants %s, wait %s)", *dir, *variants, *wait)

	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(*dir)
		if err != nil {
			log.Printf("readdir: %v", err)
			time.Sleep(*poll)
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".png") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			prev, ok := seen[e.Name()]
			if ok && !info.ModTime().After(prev) {
				continue
			}
			seen[e.Name()] = info.ModTime()
			if ok {
				continue // modified, not new
			}
			path := filepath.Join(*dir, e.Name())
			log.Printf("NEW %s (%d B) -> testing", e.Name(), info.Size())
			testQR(*root, *bin, path, *variants)
		}
		time.Sleep(*poll)
	}
	log.Printf("watch finished")
}

func testQR(root, bin, qrPath, variants string) {
	absBin, _ := filepath.Abs(bin)
	wss := exec.Command(filepath.Join(absBin, "wsswatch.exe"), "-qr", qrPath, "-wait", "9s")
	wss.Dir = root
	var wssOut bytes.Buffer
	wss.Stdout = &wssOut
	wss.Stderr = &wssOut
	if err := wss.Start(); err != nil {
		log.Printf("wsswatch start: %v", err)
		return
	}
	time.Sleep(1500 * time.Millisecond)

	seedSpecs := []string{"", "qr0,qr0", "qr0,qr1", "qr1,qr0", "qr1,qr1", "qrn0,qrn0"}
	for _, s := range seedSpecs {
		for _, v := range strings.Split(variants, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			args := []string{"-qr", qrPath, "-mode", "auth", "-variant", v, "-wait", "2s"}
			if s != "" {
				args = append(args, "-seed", s)
			}
			ns := exec.Command(filepath.Join(absBin, "nsprobe.exe"), args...)
			ns.Dir = root
			out, err := ns.CombinedOutput()
			log.Printf("--- seed=%q variant %s (err=%v) ---", s, v, err)
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "auth variant") || strings.Contains(line, "structB") ||
					strings.Contains(line, "nested[") || strings.Contains(line, "login QR") ||
					strings.Contains(line, "close") || strings.Contains(line, "recv") {
					log.Printf("  %s", sanitize(line))
				}
			}
			time.Sleep(150 * time.Millisecond)
		}
	}

	_ = wss.Wait()
	log.Printf("=== wsswatch ===")
	for _, line := range strings.Split(wssOut.String(), "\n") {
		if line != "" {
			log.Printf("  %s", sanitize(line))
		}
	}
}

func sanitize(s string) string {
	// strip ANSI colour sequences emitted by the child loggers
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return fmt.Sprintf("%s", b.String())
}
