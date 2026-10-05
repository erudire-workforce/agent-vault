// Store backends for the kmsaad tests. The deployment target is a dedicated
// Postgres instance (20260617143022_postgres_baseline.go); SQLite is kept as a
// second backend because upstream still ships it. Each test runs once per
// backend as a subtest.
//
// Postgres: set AGENT_VAULT_TEST_POSTGRES_URL to an admin URL, e.g.
//
//	postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable
//
// Each subtest creates and drops its own database. Without the variable the
// postgres subtests are skipped (with a log line); set
// AGENT_VAULT_TEST_REQUIRE_POSTGRES=1 in CI to turn that skip into a failure.
//
// This file is copied verbatim (package clause aside) into every package that
// needs it, because test helpers cannot be shared across packages.
package bootstrap

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

type testDB struct {
	Kind string // "sqlite" or "postgres"
	DSN  string // sqlite file path or postgres URL
	Raw  *sql.DB
}

// Open opens a fresh store handle on the same database (a "restart").
func (d testDB) Open(t *testing.T) store.Store {
	t.Helper()
	var (
		s   store.Store
		err error
	)
	if d.Kind == "postgres" {
		s, err = store.OpenStore(store.StoreConfig{DatabaseURL: d.DSN})
	} else {
		s, err = store.Open(d.DSN)
	}
	if err != nil {
		t.Fatalf("open %s store: %v", d.Kind, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Exec runs a raw statement (written with ? placeholders) to tamper with
// rows behind the store's back.
func (d testDB) Exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := d.Raw.Exec(d.rebind(q), args...); err != nil {
		t.Fatalf("raw exec %q: %v", q, err)
	}
}

func (d testDB) QueryRow(q string, args ...any) *sql.Row {
	return d.Raw.QueryRow(d.rebind(q), args...)
}

func (d testDB) rebind(q string) string {
	if d.Kind != "postgres" {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// RowBytesContain reports whether any column of any row in table contains needle.
func (d testDB) RowBytesContain(t *testing.T, table string, needle []byte) bool {
	t.Helper()
	rows, err := d.Raw.Query("SELECT * FROM " + table)
	if err != nil {
		t.Fatalf("select %s: %v", table, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			switch x := v.(type) {
			case []byte:
				if strings.Contains(string(x), string(needle)) {
					return true
				}
			case string:
				if strings.Contains(x, string(needle)) {
					return true
				}
			}
		}
	}
	return false
}

func randName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newSQLiteTestDB(t *testing.T) testDB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent-vault.db")
	// Create the schema first so the raw handle sees a migrated file.
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	raw, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return testDB{Kind: "sqlite", DSN: path, Raw: raw}
}

func newPostgresTestDB(t *testing.T) (testDB, bool) {
	t.Helper()
	admin := os.Getenv("AGENT_VAULT_TEST_POSTGRES_URL")
	if admin == "" {
		if os.Getenv("AGENT_VAULT_TEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal("AGENT_VAULT_TEST_REQUIRE_POSTGRES=1 but AGENT_VAULT_TEST_POSTGRES_URL is not set")
		}
		return testDB{}, false
	}
	adminDB, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatalf("open postgres admin: %v", err)
	}
	name := "av_kmsaad_" + randName()
	if _, err := adminDB.Exec("CREATE DATABASE " + name); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dsn := u.String()
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Run migrations once so the raw handle sees the schema.
	s, err := store.OpenStore(store.StoreConfig{DatabaseURL: dsn})
	if err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	_ = s.Close()
	t.Cleanup(func() {
		_ = raw.Close()
		_, _ = adminDB.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		_ = adminDB.Close()
	})
	return testDB{Kind: "postgres", DSN: dsn, Raw: raw}, true
}

// fresh returns a new, empty database of the same kind (for subtests).
func (d testDB) fresh(t *testing.T) testDB {
	t.Helper()
	if d.Kind == "postgres" {
		db, ok := newPostgresTestDB(t)
		if !ok {
			t.Skip("postgres not configured")
		}
		return db
	}
	return newSQLiteTestDB(t)
}

// forEachBackend runs fn as a "postgres" and a "sqlite" subtest.
func forEachBackend(t *testing.T, fn func(t *testing.T, db testDB)) {
	t.Helper()
	t.Run("postgres", func(t *testing.T) {
		db, ok := newPostgresTestDB(t)
		if !ok {
			t.Skip("AGENT_VAULT_TEST_POSTGRES_URL not set; postgres backend not exercised")
		}
		fn(t, db)
	})
	t.Run("sqlite", func(t *testing.T) {
		fn(t, newSQLiteTestDB(t))
	})
}
