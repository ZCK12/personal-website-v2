package usercontroller

import (
    "encoding/json"
    "errors"
    "context"
    "net/http"

    "github.com/ZCK12/personal-website-v2/backend/utils/jwtutils"

    "github.com/gocql/gocql"
    "golang.org/x/crypto/bcrypt"
)

type NewUserAccount struct {
    UserEmail    string `json:"email"`
    UserLogin    string `json:"login"`
    UserPassword string `json:"password"`
}

type RegisteredUserAccount struct {
    UserId       gocql.UUID `json:"userId"`
    UserEmail    string     `json:"email"`
    UserLogin    string     `json:"login"`
    UserPassword string     `json:"password"`
}

type UserFetchResponse struct {
    UserId    gocql.UUID `json:"userId"`
    UserEmail string     `json:"email"`
    UserLogin string     `json:"login"`
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
    var user NewUserAccount

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

// Handler for user query
func (uc *UserController) UserFetchHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve userId from the request context
    userId, ok := r.Context().Value("userId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    user, err := uc.fetchUserById(userId)
    if err == gocql.ErrNotFound {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    if err != nil {
        http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Map to the response struct
    response := UserFetchResponse {
        UserId:    user.UserId,
        UserEmail: user.UserEmail,
        UserLogin: user.UserLogin,
    }

    // Respond with the fetched user
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (uc *UserController) LoginHandler(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        UserLogin    string `json:"login"`
        UserPassword string `json:"password"`
    }

    // Parse the login request body
    if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Fetch the user by login
    user, err := uc.fetchUserByLogin(credentials.UserLogin)
    if err != nil {
        http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
        return
    }

    // Verify the password
    if err := bcrypt.CompareHashAndPassword([]byte(user.UserPassword), []byte(credentials.UserPassword)); err != nil {
        http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
        return
    }

    // Generate a JWT
    token, err := jwtutils.GenerateJWT(uc.CassandraSession, user.UserId.String())
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // Respond with the token
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": token,
    })
}

func (uc *UserController) UserAuthenticationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract the Authorization header
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Missing token", http.StatusUnauthorized)
            return
        }

        // Validate the token and retrieve the userId
        userId, err := jwtutils.ValidateJWT(uc.CassandraSession, tokenString)
        if err != nil {
            http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Attach the userId to the request context
        ctx := context.WithValue(r.Context(), "userId", userId)

        // Pass the request to the next handler
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (uc *UserController) insertNewUser(user NewUserAccount) (gocql.UUID, error) {
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

func (uc *UserController) fetchUserById(userId gocql.UUID) (RegisteredUserAccount, error) {
    var fetchedUser RegisteredUserAccount

    // Fetch user by userId
    err := uc.CassandraSession.Query(
        "SELECT user_id, email, login, password FROM users WHERE user_id = ?",
        userId,
    ).Consistency(gocql.One).Scan(
        &fetchedUser.UserId,
        &fetchedUser.UserEmail,
        &fetchedUser.UserLogin,
        &fetchedUser.UserPassword,
    )

    return fetchedUser, err
}

func (uc *UserController) fetchUserByLogin(userLogin string) (RegisteredUserAccount, error) {
    var fetchedUser RegisteredUserAccount

    err := uc.CassandraSession.Query(
        "SELECT user_id, email, login, password FROM users WHERE login = ?",
        userLogin,
    ).Consistency(gocql.One).Scan(
        &fetchedUser.UserId,
        &fetchedUser.UserEmail,
        &fetchedUser.UserLogin,
        &fetchedUser.UserPassword,
    )

    return fetchedUser, err
}
