// Package inventoryledger is an isolated SQLite storage foundation for complete
// package generations. It has no database opener, network endpoint, collector,
// authentication cache, profile grant, or runtime integration.
//
// All calls require the caller's existing authority database connection inside
// its BEGIN IMMEDIATE transaction. The caller must validate current identity,
// profile, lifecycle, replay and admission in that SAME transaction, using a
// trusted manager clock. The device key must be derived from that fresh authority
// identity, not trusted from JSON or reused to grant a new identity/profile old
// inventory. Calls do not start, commit or roll back transactions.
// On any error the caller MUST roll back the entire transaction. Returned values
// are provisional and must not escape until COMMIT succeeds; CommitResult is a
// helper for enforcing that rule around the authority owner's transaction runner.
//
// The caller owns database path protection, schema migration/validation, SQLite
// durability settings, database/WAL physical caps, concurrency admission and
// deadlines. Logical byte budgets here are not a filesystem or memory cap.
package inventoryledger
