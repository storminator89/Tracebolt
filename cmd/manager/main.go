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
	demoOnly := flag.Bool("demo-only", false, "Synthetic examples only; no local collector or developer telemetry ingestion")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatal("port must be between 1 and 65535")
	}
	if *demoOnly && *managedPreview {
		log.Fatal("--demo-only and --managed-preview are mutually exclusive")
	}
	db, e := store.Open(*dbPath)
	if e != nil {
		log.Fatal("open local state: ", e)
	}
	defer db.Close()
	if e = seedDevelopmentFixtures(db, *demoOnly, time.Now()); e != nil {
		log.Fatal("seed demo state: ", e)
	}
	handler, e := newDevelopmentHandler(db, *port, *web, *demoOnly, *managedPreview, collector.Snapshot)
	if e != nil {
		log.Fatal(e)
	}
	listener, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if e != nil {
		log.Fatal(e)
	}
	server := newHTTPServer(handler)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !*managedPreview && !*demoOnly {
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
	if *demoOnly {
		scope = "7 synthetic devices only; no local collection or telemetry ingestion"
	}
	log.Printf("Tracebolt development MVP: http://127.0.0.1:%d | %s | no remote enrollment or commands", *port, scope)
	if e = server.Serve(listener); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}

func seedDevelopmentFixtures(db *store.Store, demoOnly bool, now time.Time) error {
	if demoOnly {
		if err := db.RequireSyntheticDemo(); err != nil {
			return err
		}
	}
	devices, cases := fixtures.Seed(now)
	return db.Seed(devices, cases)
}

// Keep mode selection before the first collector call. Tests inject a collector
// to prove that fixture-only and developer-transport modes never sample a host.
func newDevelopmentHandler(db *store.Store, port int, web string, demoOnly, managedPreview bool, snapshot func() model.Device) (*api.Server, error) {
	if demoOnly && managedPreview {
		return nil, fmt.Errorf("--demo-only and --managed-preview are mutually exclusive")
	}
	if demoOnly {
		return api.NewDemoOnly(db, port, web)
	}
	if managedPreview {
		transport := telemetry.NewState()
		handler, err := api.New(db, port, web, transport.Device(time.Now().UTC()))
		if err == nil {
			handler.EnableManagedPreview(transport)
		}
		return handler, err
	}
	return api.New(db, port, web, snapshot())
}
