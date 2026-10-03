// Manager is a local-development process, not a production fleet control plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"localrmm/internal/api"
	"localrmm/internal/collector"
	"localrmm/internal/fixtures"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"localrmm/internal/telemetry"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := flag.Int("port", 8787, "Loopback port (1..65535); host is fixed to 127.0.0.1")
	dbPath := flag.String("db", ".local/state.db", "Local development SQLite file")
	web := flag.String("web", "web/dist", "Built UI directory")
	managedPreview := flag.Bool("managed-preview", false, "Developer-only localhost telemetry ingestion; disable all manager-side sampling")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatal("port must be between 1 and 65535")
	}
	db, e := store.Open(*dbPath)
	if e != nil {
		log.Fatal("open local state: ", e)
	}
	defer db.Close()
	devices, cases := fixtures.Seed(time.Now())
	if e = db.Seed(devices, cases); e != nil {
		log.Fatal("seed demo state: ", e)
	}
	var localSample model.Device
	var transport *telemetry.State
	if *managedPreview {
		transport = telemetry.NewState()
		localSample = transport.Device(time.Now().UTC())
	} else {
		localSample = collector.Snapshot()
	}
	handler, e := api.New(db, *port, *web, localSample)
	if e != nil {
		log.Fatal(e)
	}
	if transport != nil {
		handler.EnableManagedPreview(transport)
	}
	listener, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if e != nil {
		log.Fatal(e)
	}
	server := newHTTPServer(handler)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !*managedPreview {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					handler.SetSample(collector.Snapshot())
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if *managedPreview {
		log.Print("Managed preview enabled: awaiting a separate local dev-agent sample; no internal collector or fallback; no production enrollment/authentication.")
	}
	scope := "7 synthetic devices + limited local read-only sample"
	if *managedPreview {
		scope = "7 synthetic devices + separate Linux developer-transport slot (no internal collector)"
	}
	log.Printf("Tracebolt development MVP: http://127.0.0.1:%d | %s | no remote enrollment or commands", *port, scope)
	if e = server.Serve(listener); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
