package databaseutils

import (
    "fmt"
    "log"
    "time"

    "github.com/gocql/gocql"
    "golang.org/x/crypto/bcrypt"
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
        "admin_users": `CREATE TABLE IF NOT EXISTS admin_users (
            user_id UUID PRIMARY KEY,
            admin_from TIMESTAMP,
            admin_until TIMESTAMP
            )`,
        "remove_jwt_keys": `DROP TABLE IF EXISTS jwt_keys`,
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

    indexes := map[string]string{
        "users_email_index": `CREATE INDEX IF NOT EXISTS ON users (email)`,
        "users_login_index": `CREATE INDEX IF NOT EXISTS ON users (login)`,
    }

    for indexName, createStmt := range indexes {
        log.Printf("Ensuring index '%s' exists...", indexName)
        if err := session.Query(createStmt).Exec(); err != nil {
            return fmt.Errorf("failed to ensure index '%s': %w", indexName, err)
        }
    }

    // Ensure the default admin user exists
    if err := ensureDefaultAdminUser(session); err != nil {
        return fmt.Errorf("failed to ensure default admin user: %w", err)
    }

    return nil
}

// ensureDefaultAdminUser ensures the default admin user exists in both the users and admin tables.
func ensureDefaultAdminUser(session *gocql.Session) error {
    const (
        defaultAdminLogin    = "admin"
        defaultAdminEmail    = "admin@admin.com"
        defaultAdminPassword = "admin"
    )

    // Check if the default admin user already exists in the users table
    var userId gocql.UUID
    err := session.Query("SELECT user_id FROM users WHERE login = ?", defaultAdminLogin).Consistency(gocql.One).Scan(&userId)
    if err == nil {
        log.Println("Default admin user already exists in the users table.")
    } else if err == gocql.ErrNotFound {
        // Generate a new UUID for the admin user
        userId = gocql.TimeUUID()

        // Hash the default admin password
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultAdminPassword), bcrypt.DefaultCost)
        if err != nil {
            return fmt.Errorf("failed to hash default admin password: %w", err)
        }

        // Insert the default admin user into the users table
        if err := session.Query(
            "INSERT INTO users (user_id, email, login, password) VALUES (?, ?, ?, ?)",
                                userId, defaultAdminEmail, defaultAdminLogin, string(hashedPassword),
        ).Exec(); err != nil {
            return fmt.Errorf("failed to insert default admin user: %w", err)
        }

        log.Println("Default admin user created in the users table.")
    } else {
        return fmt.Errorf("failed to query default admin user in users table: %w", err)
    }

    // Check if the admin entry already exists in the admin table
    var count int
    err = session.Query("SELECT COUNT(*) FROM admin_users WHERE user_id = ?", userId).Consistency(gocql.One).Scan(&count)
    if err != nil {
        return fmt.Errorf("failed to check admin entry for default admin user: %w", err)
    }

    if count > 0 {
        log.Println("Admin entry for default admin user already exists.")
    } else {
        adminFrom := time.Unix(0, 0)
        adminUntil := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
        if err := session.Query(
            "INSERT INTO admin_users (user_id, admin_from, admin_until) VALUES (?, ?, ?)",
                                userId, adminFrom, adminUntil,
        ).Exec(); err != nil {
            return fmt.Errorf("failed to insert admin entry for default admin user: %w", err)
        }
        log.Println("Admin entry for default admin user created successfully.")
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
