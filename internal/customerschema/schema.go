// Package customerschema validates the complete SQLite schema of the isolated
// customer source candidates. It is not a path, database authenticity, backup
// rollback or host permission check. Call it only within the owning transaction.
package customerschema

import (
	"context"
	"database/sql"
	"errors"
)

var ErrSchema = errors.New("customer database schema is invalid")

const Version = 1

type Object struct {
	Type, Name, Table string
	SQL               *string
}

// ObjectSQL constructs an expected table definition. Autoindexes have nil SQL.
func ObjectSQL(name, definition string) Object {
	return Object{Type: "table", Name: name, Table: name, SQL: &definition}
}
func AutoIndex(name, table string) Object { return Object{Type: "index", Name: name, Table: table} }

func checkAttachments(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return ErrSchema
	}
	for rows.Next() {
		var n int
		var name, path string
		if rows.Scan(&n, &name, &path) != nil || name != "main" && name != "temp" {
			rows.Close()
			return ErrSchema
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrSchema
	}
	if rows.Close() != nil {
		return ErrSchema
	}
	var n int
	if conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_temp_master`).Scan(&n) != nil || n != 0 {
		return ErrSchema
	}
	return nil
}

// Empty permits only a brand-new main schema, version zero, no attached DBs or
// temp objects. It does not detect deletion of a whole previously used database.
func Empty(ctx context.Context, conn *sql.Conn) error {
	if ctx == nil || conn == nil || checkAttachments(ctx, conn) != nil {
		return ErrSchema
	}
	var version, count int
	if conn.QueryRowContext(ctx, `PRAGMA main.user_version`).Scan(&version) != nil || version != 0 || conn.QueryRowContext(ctx, `SELECT count(*) FROM main.sqlite_master`).Scan(&count) != nil || count != 0 {
		return ErrSchema
	}
	return nil
}

// Validate rejects every non-exact object, including extra tables, views,
// triggers and explicit indexes; it checks expected autoindexes as well. The
// comparison is exact on SQLite's stored SQL, not SQL normalization.
func Validate(ctx context.Context, conn *sql.Conn, expected []Object) error {
	return ValidateVersion(ctx, conn, expected, Version)
}

// ValidateVersion applies the same exact schema checks to a separately
// versioned fresh domain. It never upgrades or repairs an older database.
func ValidateVersion(ctx context.Context, conn *sql.Conn, expected []Object, expectedVersion int) error {
	if ctx == nil || conn == nil || len(expected) == 0 || expectedVersion <= 0 || checkAttachments(ctx, conn) != nil {
		return ErrSchema
	}
	var version int
	if conn.QueryRowContext(ctx, `PRAGMA main.user_version`).Scan(&version) != nil || version != expectedVersion {
		return ErrSchema
	}
	want := make(map[string]Object, len(expected))
	for _, v := range expected {
		if v.Name == "" || want[v.Name].Name != "" {
			return ErrSchema
		}
		want[v.Name] = v
	}
	rows, err := conn.QueryContext(ctx, `SELECT type,name,tbl_name,sql FROM main.sqlite_master ORDER BY name LIMIT ?`, len(expected)+1)
	if err != nil {
		return ErrSchema
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var typ, name, table string
		var definition sql.NullString
		if rows.Scan(&typ, &name, &table, &definition) != nil {
			return ErrSchema
		}
		v, ok := want[name]
		if !ok || typ != v.Type || table != v.Table || definition.Valid != (v.SQL != nil) || definition.Valid && definition.String != *v.SQL {
			return ErrSchema
		}
		delete(want, name)
		count++
	}
	if rows.Err() != nil || count != len(expected) || len(want) != 0 {
		return ErrSchema
	}
	return nil
}
