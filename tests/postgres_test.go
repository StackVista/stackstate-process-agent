package tests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRunSimplePostgresQuery(t *testing.T) {
	ctx := context.Background()

	// Request a postgres container
	req := tc.ContainerRequest{
		Image:        "postgres:13-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(7 * time.Second),
	}

	postgresC, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	if err != nil {
		t.Fatal(err)
	}
	defer postgresC.Terminate(ctx)

	// Get host and port for connecting
	host, err := postgresC.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := postgresC.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatal(err)
	}

	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%s user=testuser password=testpass dbname=testdb sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Verify connection
	if err := db.Ping(); err != nil {
		t.Fatal("failed to ping database:", err)
	}

	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
    );
    `
	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("failed to create table: %v", err)
	}
	t.Log("Table created successfully.")

	// Insert a row.
	insertStmt := `INSERT INTO users (name) VALUES ($1) RETURNING id;`
	var userID int
	if err := db.QueryRow(insertStmt, "Alice").Scan(&userID); err != nil {
		t.Fatalf("failed to insert row: %v", err)
	}
	t.Logf("Inserted user with ID: %d", userID)

	selectQuery := `SELECT id, name FROM users;`

	// Run a SELECT query.
	t.Log("Send Select!")
	rows, err := db.Query(selectQuery)
	if err != nil {
		t.Fatalf("failed to execute select query: %v", err)
	}
	defer rows.Close()
	t.Log("Transaction completed!")
}
