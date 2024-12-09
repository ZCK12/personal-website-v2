package main

import (
    "fmt"
    "log"
    "math/rand"
    "net/http"
    "os"
    "context"
    "time"

    "github.com/joho/godotenv"
    "github.com/ZCK12/personal-website-v2/backend/utils/databaseutils"
    "github.com/ZCK12/personal-website-v2/backend/api/systemcontroller"
    "github.com/ZCK12/personal-website-v2/backend/api/authcontroller"
    "github.com/ZCK12/personal-website-v2/backend/api/usercontroller"

    "github.com/gocql/gocql"
    "github.com/go-chi/chi/v5"
)

func main() {
    // Seed random number generator
    rand.Seed(time.Now().UnixNano())

    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, loading environment variables from system.")
    }

    // Get server address and port from environment
    serverAddress := os.Getenv("SERVER_ADDRESS")
    serverPort := os.Getenv("SERVER_PORT")
    if serverAddress == "" {
        serverAddress = "127.0.0.1" // Default to localhost
    }
    if serverPort == "" {
        serverPort = "8080" // Default port
    }

    // Initialise Database
    cassandraSession, err := connectToCassandra()
    if err != nil {
        log.Fatalf("Cassandra connection failed: %v", err)
    }
    defer cassandraSession.Close()

    log.Println("Starting database migration...")
    if err := databaseutils.DatabaseMigration(cassandraSession); err != nil {
        log.Fatalf("Database migration failed: %v", err)
    }
    log.Println("Database migration completed successfully.")

    // Initialise Controllers
    sc := systemcontroller.NewSystemController(cassandraSession)
    ac := authcontroller.NewAuthController(cassandraSession)
    uc := usercontroller.NewUserController(cassandraSession)

    // Configure routes
    r := chi.NewRouter()

    r.Route("/api", func(r chi.Router) {
        r.Get("/status", sc.SystemStatusHandler)
        r.Get("/health", sc.SystemHealthHandler)
        r.Post("/login", ac.LoginHandler)
        r.Post("/logout", ac.LogoutHandler)

        r.Route("/user", func(r chi.Router) {
            r.Post("/", uc.NewUserInsertionHandler)
            r.With(ac.UserAuthenticationMiddleware).Get("/", uc.UserSelfFetchHandler)
            r.With(ac.UserAuthenticationMiddleware).Delete("/", uc.UserSelfDeletionHandler)
            r.With(ac.UserAuthenticationMiddleware).Put("/password", uc.UserSelfPasswordChangeHandler)
            r.With(ac.UserAuthenticationMiddleware).Get("/referralcodes", uc.UserReferralCodeHandler)
        })

        r.Route("/admin", func(r chi.Router) {
            r.Route("/users", func(r chi.Router) {
                r.With(ac.AdminAuthenticationMiddleware).Get("/", uc.FetchAllUsersHandler)
                r.With(ac.AdminAuthenticationMiddleware).With(withParsedUserId).Get("/{userId}", uc.UserFetchHandler)
                r.With(ac.AdminAuthenticationMiddleware).With(withParsedUserId).Delete("/{userId}", uc.UserDeletionHandler)
                r.With(ac.AdminAuthenticationMiddleware).With(withParsedUserId).Put("/{userId}/password", uc.UserPasswordChangeHandler)
                r.With(ac.AdminAuthenticationMiddleware).With(withParsedUserId).Get("/{userId}/activity", uc.UserActivityHandler)
            })

            r.Route("/crypto", func(r chi.Router) {
                r.Route("/keys", func(r chi.Router) {
                    r.With(ac.AdminAuthenticationMiddleware).Post("/rotate", sc.RotateCryptoKeyHandler)
                    r.With(ac.AdminAuthenticationMiddleware).Post("/invalidate", sc.InvalidateAllCryptoKeysHandler)
                    r.With(ac.AdminAuthenticationMiddleware).Post("/flush", sc.FlushAllCryptoKeysHandler)
                })
            })
        })
    })

    // Start the server
    address := fmt.Sprintf("%s:%s", serverAddress, serverPort)
    log.Printf("Starting server on %s", address)
    log.Fatal(http.ListenAndServe(address, r))
}

func withParsedUserId(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract userId from URL parameters
        userIdStr := chi.URLParam(r, "userId")

        // Parse userId into gocql.UUID
        userId, err := gocql.ParseUUID(userIdStr)
        if err != nil {
            http.Error(w, "Invalid userId format", http.StatusBadRequest)
            return
        }

        // Attach the userId to the request context
        ctx := context.WithValue(r.Context(), "contextualUserId", userId)

        // Call the next handler with the updated request
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func connectToCassandra() (*gocql.Session, error) {
    // Load Cassandra configuration from environment variables
    cassandraHost := os.Getenv("CASSANDRA_HOST")
    cassandraKeyspace := os.Getenv("CASSANDRA_KEYSPACE")
    cassandraUsername := os.Getenv("CASSANDRA_USERNAME")
    cassandraPassword := os.Getenv("CASSANDRA_PASSWORD")

    if cassandraHost == "" || cassandraKeyspace == "" {
        return nil, fmt.Errorf("CASSANDRA_HOST or CASSANDRA_KEYSPACE is not set")
    }

    // Step 1: Connect to Cassandra without a keyspace
    log.Println("Connecting to Cassandra without keyspace...")
    cluster := gocql.NewCluster(cassandraHost)
    cluster.Consistency = gocql.Quorum

    if cassandraUsername != "" && cassandraPassword != "" {
        cluster.Authenticator = gocql.PasswordAuthenticator{
            Username: cassandraUsername,
            Password: cassandraPassword,
        }
    }

    session, err := cluster.CreateSession()
    if err != nil {
        return nil, fmt.Errorf("failed to connect to Cassandra: %w", err)
    }
    defer session.Close()

    // Step 2: Ensure the desired keyspace exists
    log.Printf("Ensuring keyspace '%s' exists...", cassandraKeyspace)
    if err := ensureKeyspace(session, cassandraKeyspace); err != nil {
        return nil, fmt.Errorf("failed to ensure keyspace: %w", err)
    }

    // Step 3: Reconnect to Cassandra with the desired keyspace
    log.Printf("Reconnecting to Cassandra using keyspace '%s'...", cassandraKeyspace)
    cluster.Keyspace = cassandraKeyspace
    keyspaceSession, err := cluster.CreateSession()
    if err != nil {
        return nil, fmt.Errorf("failed to connect to Cassandra keyspace '%s': %w", cassandraKeyspace, err)
    }

    return keyspaceSession, nil
}

// ensureKeyspace ensures that the desired keyspace exists in Cassandra
func ensureKeyspace(session *gocql.Session, keyspace string) error {
    keyspaceQuery := fmt.Sprintf(`
    CREATE KEYSPACE IF NOT EXISTS %s
    WITH replication = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
    }`, keyspace)

    return session.Query(keyspaceQuery).Exec()
}
