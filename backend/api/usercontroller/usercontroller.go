package usercontroller

import (
    "encoding/json"
    "errors"
    "net/http"

    "github.com/gocql/gocql"
    "golang.org/x/crypto/bcrypt"
)

type UserAccount struct {
    UserEmail    string `json:"email"`
    UserLogin    string `json:"login"`
    UserPassword string `json:"password"`
}

type UserController struct {
    CassandraSession *gocql.Session
}

// Constructor for UserController
func NewUserController(session *gocql.Session) *UserController {
    return &UserController{CassandraSession: session}
}

// Handler for user insertion
func (uc *UserController) NewUserInsertionHandler(w http.ResponseWriter, r *http.Request) {
    var user UserAccount

    // Parse the request body
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate input (e.g., non-empty fields)
    if user.UserEmail == "" || user.UserLogin == "" || user.UserPassword == "" {
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Insert the user into Cassandra
    userId, err := uc.insertNewUser(user)
    if err != nil {
        http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with the new user ID
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{
        "userId": userId.String(),
    })
}

func (uc *UserController) insertNewUser(user UserAccount) (gocql.UUID, error) {
    // Check if the email or login already exists
    var existingUserId gocql.UUID
    err := uc.CassandraSession.Query(
        "SELECT user_id FROM users WHERE email = ?",
        user.UserEmail,
    ).Consistency(gocql.One).Scan(&existingUserId)
    if err == nil {
        return gocql.UUID{}, errors.New("user already exists")
    }
    if err != gocql.ErrNotFound {
        return gocql.UUID{}, err
    }

    err = uc.CassandraSession.Query(
        "SELECT user_id FROM users WHERE login = ?",
        user.UserLogin,
    ).Consistency(gocql.One).Scan(&existingUserId)
    if err == nil {
        return gocql.UUID{}, errors.New("user already exists")
    }
    if err != gocql.ErrNotFound {
        return gocql.UUID{}, err
    }

    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.UserPassword), bcrypt.DefaultCost)
    if err != nil {
        return gocql.UUID{}, err
    }

    // Generate a new user ID
    userId := gocql.TimeUUID()

    // Insert the new user
    if err := uc.CassandraSession.Query(
        "INSERT INTO users (user_id, email, login, password) VALUES (?, ?, ?, ?)",
        userId, user.UserEmail, user.UserLogin, hashedPassword,
    ).Exec(); err != nil {
        return gocql.UUID{}, err
    }

    return userId, nil
}

// Handler for user query
func (uc *UserController) UserFetchHandler(w http.ResponseWriter, r *http.Request) {

}
