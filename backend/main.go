package main

import (
    "fmt"
    "log"
    "math/rand"
    "net/http"
    "time"

    uc "github.com/ZCK12/personal-website-v2/backend/api/usercontroller"

    "github.com/gocql/gocql"
    "github.com/go-chi/chi/v5"
)

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

func main() {
    rand.Seed(time.Now().UnixNano())
    cassandraSession := connectToCassandra()
    defer cassandraSession.Close()

    // Pass Cassandra session to usercontroller
    userController := uc.NewUserController(cassandraSession)

    r := chi.NewRouter()

    r.Route("/api", func(r chi.Router) {
        r.Route("/users", func(r chi.Router) {

        })
    })

    // User-related endpoints
    r.Post("/api/users", userController.NewUserInsertionHandler)

    fmt.Println("Starting server on :8080")
    log.Fatal(http.ListenAndServe(":8080", r))
}
