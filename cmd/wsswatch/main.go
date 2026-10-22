// Command wsswatch connects to the browser-facing authenticator websocket,
// registers the (register id, server id) pair from a login QR, and prints every
// message the server pushes. This is the login page's own oracle: if the phone
// approves, the server sends CONFIRMSCAN and then LOGIN.
//
// Usage:
//
//	wsswatch -qr "login.png"
//	wsswatch -register <registerid> -server <serverid>
package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"kut-leuven-authenticator/internal/qr"
	"kut-leuven-authenticator/internal/transport"
)

func main() {
	qrPath := flag.String("qr", "", "login QR PNG (derive register/server ids)")
	register := flag.String("register", "", "register id (base64url)")
	server := flag.String("server", "", "server id (base64url)")
	url := flag.String("url", "wss://authenticator-wss.icts.kuleuven.be/", "browser websocket endpoint")
	origin := flag.String("origin", "https://idp.kuleuven.be", "Origin header")
	wait := flag.Duration("wait", 5*time.Minute, "how long to listen")
	send := flag.String("send", "", "extra client lines to send after 1.5s, ';'-separated ({reg}/{srv} substituted)")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *qrPath != "" {
		codes, err := qr.DecodeFile(*qrPath)
		if err != nil {
			log.Fatalf("qr: %v", err)
		}
		l, err := qr.ParseLogin(codes[0].Payload)
		if err != nil {
			log.Fatalf("qr parse: %v", err)
		}
		if !l.IsLogin() {
			log.Fatalf("QR is not a login QR (type=%d register=%d server=%d)", l.Type, len(l.Register), len(l.Server))
		}
		*register = l.RegisterID()
		*server = l.ServerID()
		log.Printf("login QR: register=%s server=%s created=%s", *register, *server, l.Created().UTC())
	}
	if *register == "" || *server == "" {
		log.Fatalf("need -qr or both -register and -server")
	}

	hdr := map[string][]string{"Origin": {*origin}}
	conn, err := transport.Dial(*url, &transport.Config{
		Headers:          hdr,
		HandshakeTimeout: 20 * time.Second,
	})
	if err != nil {
		log.Fatalf("dial %s: %v", *url, err)
	}
	defer conn.Close()

	msg := fmt.Sprintf("REGISTER %s %s", *register, *server)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		log.Fatalf("write REGISTER: %v", err)
	}
	log.Printf("-> %s", msg)

	if *send != "" {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			for _, line := range strings.Split(*send, ";") {
				line = strings.ReplaceAll(line, "{reg}", *register)
				line = strings.ReplaceAll(line, "{srv}", *server)
				if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
					log.Printf("write %q: %v", line, err)
					return
				}
				log.Printf("-> %s", line)
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}

	deadline := time.Now().Add(*wait)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			log.Fatalf("deadline: %v", err)
		}
		typ, data, err := conn.ReadMessage()
		if err != nil {
			if time.Now().After(deadline) {
				log.Printf("done waiting")
				return
			}
			log.Printf("read: %v", err)
			return
		}
		kind := "binary"
		if typ == websocket.TextMessage {
			kind = "text"
		}
		log.Printf("<- %s (%d B): %q", kind, len(data), data)
	}
}
