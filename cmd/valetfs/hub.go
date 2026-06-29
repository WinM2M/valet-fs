package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/anomalyco/valet-fs/internal/hub"
)

// runHub starts the self-hosted Go session hub (a Durable-Object-equivalent
// WebSocket relay). It is primarily for local testing and self-hosting; the
// production control plane uses the Cloudflare Durable Object.
func runHub(args []string) error {
	fs := flag.NewFlagSet("hub", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:8799", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	srv := &http.Server{Addr: *addr, Handler: hub.New()}
	log.Printf("valetfs hub: listening on http://%s", *addr)
	fmt.Printf("hub listening on http://%s\n", *addr)
	return srv.ListenAndServe()
}
