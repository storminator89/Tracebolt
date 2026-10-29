package customerpending

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
)

func TestRollbackPanicDiscardsConnectionBeforeReleasingAuthority(t *testing.T) {
	for _, operation := range []string{"accept", "review", "status"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1790000000, 0).UTC()
			clock := func() time.Time { return now }
			path := filepath.Join(t.TempDir(), "pending.db")
			base := openFixture(t, path)
			if err := Initialize(ctx, base); err != nil {
				t.Fatal(err)
			}
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			proof := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
			initial, _ := New(base)
			record, err := initial.Accept(ctx, proof, clock, leaseFor(func() error { return nil }))
			if err != nil {
				t.Fatal(err)
			}
			connector := &panicBeginConnector{path: path}
			db := sql.OpenDB(connector)
			defer db.Close()
			db.SetMaxOpenConns(1)
			s, err := New(db)
			if err != nil {
				t.Fatal(err)
			}
			released := false
			authority := trackingLease{check: func() error {
				if operation == "accept" {
					return errors.New("fixture denies commit")
				}
				return nil
			}, release: func() {
				released = true
				// The pending connection must already be discarded, so this writer
				// can acquire its lock while the nested authority is releasing.
				if _, e := base.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
					t.Error("pending lock held during authority release", e)
					return
				}
				if _, e := base.ExecContext(ctx, `ROLLBACK`); e != nil {
					t.Error(e)
				}
			}}
			acquire := func(context.Context, customerclaim.Metadata) (AuthorityLease, error) { return authority, nil }
			var statusLease *StatusLease
			var reviewLease *ReviewLease
			switch operation {
			case "status":
				c := customerclaim.Context{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, Origin: record.Origin, AgentOrigin: record.AgentOrigin, IssuerFingerprint: record.IssuerFingerprint, ClaimID: record.ClaimID, Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), ExpiresAt: now.Unix() + 60}
				m := reviewMetadata(record)
				request := "request_" + strings.Repeat("a", 32)
				msg, e := customerclaim.StatusSigningMessage(c, m, record.PublicKeyDER, request, now)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := customerclaim.EncodeStatus(c, m, record.PublicKeyDER, request, ed25519.Sign(key, msg), now)
				if e != nil {
					t.Fatal(e)
				}
				statusLease, err = s.AcquireStatus(ctx, c, raw, clock, acquire)
			case "review":
				reviewLease, err = s.AcquireReview(ctx, reviewExpected(record), clock, func(context.Context, customerclaim.Metadata, string, uint64) (AuthorityLease, error) {
					return authority, nil
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			connector.panicRollback.Store(true)
			func() {
				defer func() {
					if recover() == nil {
						t.Error("rollback panic was swallowed")
					}
				}()
				switch operation {
				case "accept":
					_, _ = s.Accept(ctx, proof, clock, acquire)
				case "review":
					reviewLease.Release()
				case "status":
					statusLease.Release()
				}
			}()
			if !released || connector.closes.Load() != 1 || db.Stats().InUse != 0 {
				t.Fatal("cleanup incomplete", released, connector.closes.Load(), db.Stats())
			}
			rows, err := s.Records(ctx)
			if err != nil || len(rows) != 1 || rows[0].ClaimID != record.ClaimID {
				t.Fatal("reopen after rollback panic", err)
			}
		})
	}
}
