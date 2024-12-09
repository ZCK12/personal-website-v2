package main

import (
    "fmt"
    "log"
    "math/rand"
    "net/http"
    "context"
    "time"

    "github.com/ZCK12/personal-website-v2/backend/utils/databaseutils"
    "github.com/ZCK12/personal-website-v2/backend/api/systemcontroller"
    "github.com/ZCK12/personal-website-v2/backend/api/usercontroller"

    "github.com/gocql/gocql"
    "github.com/go-chi/chi/v5"
)

func main() {
    rand.Seed(time.Now().UnixNano())

    // Initilise Database
    log.Println("Connecting to Cassandra database...")
    cassandraSession, err := databaseutils.InitialiseCassandraConnection()
    if err != nil {
        log.Fatalf("Cassandra connection failed: %v", err)
    }
    defer cassandraSession.Close()

    log.Println("Starting database migration...")
    if err := databaseutils.DatabaseMigration(cassandraSession); err != nil {
        log.Fatalf("Database migration failed: %v", err)
    }
    log.Println("Database migration completed successfully.")

    // Initilise Controllers
    sc := systemcontroller.NewSystemController(cassandraSession)
    uc := usercontroller.NewUserController(cassandraSession)

    r := chi.NewRouter()

    r.Route("/api", func(r chi.Router) {
        r.Get("/status", sc.SystemStatusHandler)
        r.Get("/health", sc.SystemHealthHandler)
        r.Post("/login", uc.LoginHandler)
        r.Post("/logout", uc.LogoutHandler)

        r.Route("/user", func(r chi.Router) {
            r.Post("/", uc.NewUserInsertionHandler)
            r.With(uc.UserAuthenticationMiddleware).Get("/", uc.UserSelfFetchHandler)
            r.With(uc.UserAuthenticationMiddleware).Delete("/", uc.UserSelfDeletionHandler)
            r.With(uc.UserAuthenticationMiddleware).Put("/password", uc.UserSelfPasswordChangeHandler)
            r.With(uc.UserAuthenticationMiddleware).Get("/referralcodes", uc.UserReferralCodeHandler)
        })

        r.Route("/admin", func(r chi.Router) {
            r.Route("/users", func(r chi.Router) {
                r.With(uc.AdminAuthenticationMiddleware).Get("/", uc.FetchAllUsersHandler)
                r.With(uc.AdminAuthenticationMiddleware).With(withParsedUserId).Get("/{userId}", uc.UserFetchHandler)
                r.With(uc.AdminAuthenticationMiddleware).With(withParsedUserId).Delete("/{userId}", uc.UserDeletionHandler)
                r.With(uc.AdminAuthenticationMiddleware).With(withParsedUserId).Put("/{userId}/password", uc.PasswordChangeHandler)
                r.With(uc.AdminAuthenticationMiddleware).With(withParsedUserId).Get("/{userId}/activity", uc.UserActivityHandler)
            })

            r.Route("/crypto", func(r chi.Router) {
                r.Route("/key", func(r chi.Router) {
                    r.With(uc.AdminAuthenticationMiddleware).Post("/rotate", sc.RotateCryptoKeyHandler)
                    r.With(uc.AdminAuthenticationMiddleware).Post("/invalidate", sc.InvalidateCryptoKeyHandler)
                }
            })
        })
    })

    fmt.Println("Starting server on :8080")
    log.Fatal(http.ListenAndServe(":8080", r))
}

func connectToCassandra() *gocql.Session {
    cluster := gocql.NewCluster("127.0.0.1")
    cluster.Keyspace = "mykeyspace"
    cluster.Consistency = gocql.Quorum

    session, err := cluster.CreateSession()
    if err != nil {
        log.Fatalf("Failed to connect to Cassandra: %v", err)
    }
    return session
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
        ctx := context.WithValue(r.Context(), "userId", userId)

        // Call the next handler with the updated request
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Example of retrieving UserId from request context
func someProtectedHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve userId from the context
    userId, ok := r.Context().Value("userId").(string)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    // Use the userId for your logic
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Authenticated request for user: " + userId))
}
