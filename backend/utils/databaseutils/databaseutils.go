package databaseutils

import (
    "fmt"
    "log"

    "github.com/gocql/gocql"
)

// DatabaseMigration ensures the Cassandra database is in the required state.
func DatabaseMigration(session *gocql.Session) error {
    tables := map[string]string{
        "users": `CREATE TABLE IF NOT EXISTS users (
            user_id UUID PRIMARY KEY,
            email TEXT,
            login TEXT,
            password TEXT
            )`,
        "users_email_index": `CREATE INDEX IF NOT EXISTS ON users (email)`,
        "users_login_index": `CREATE INDEX IF NOT EXISTS ON users (login)`,
        "jwt_keys": `CREATE TABLE IF NOT EXISTS jwt_keys (
            kid UUID PRIMARY KEY,
            secret TEXT,
            created_at TIMESTAMP,
            valid_until TIMESTAMP
            )`,
    }

    for tableName, createStmt := range tables {
        log.Printf("Ensuring table '%s' exists...", tableName)
        if err := session.Query(createStmt).Exec(); err != nil {
            return fmt.Errorf("failed to ensure table '%s': %w", tableName, err)
        }
    }

    return nil
}

func InitialiseCassandraConnection() (*gocql.Session, error) {
    cluster := gocql.NewCluster("127.0.0.1")
    cluster.Consistency = gocql.Quorum

    // Connect to Cassandra without a keyspace first
    session, err := cluster.CreateSession()
    if err != nil {
        return nil, fmt.Errorf("failed to connect to Cassandra: %w", err)
    }

    log.Println("Ensuring keyspace exists...")
    if err := ensureKeyspace(session); err != nil {
        session.Close()
        return nil, fmt.Errorf("failed to ensure keyspace: %w", err)
    }
    session.Close()

    // Reconnect with the keyspace
    cluster.Keyspace = "mykeyspace"
    session, err = cluster.CreateSession()
    if err != nil {
        return nil, fmt.Errorf("failed to connect to Cassandra keyspace: %w", err)
    }

    return session, nil
}

func ensureKeyspace(session *gocql.Session) error {
    keyspaceQuery := `CREATE KEYSPACE IF NOT EXISTS mykeyspace WITH replication = {
        'class': 'SimpleStrategy',
        'replication_factor': 1
    }`
    if err := session.Query(keyspaceQuery).Exec(); err != nil {
        return fmt.Errorf("failed to create keyspace: %w", err)
    }
    return nil
}
