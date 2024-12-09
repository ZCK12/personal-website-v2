package authcontroller

import (
    "encoding/json"
    "net/http"

    "github.com/ZCK12/personal-website-v2/backend/utils/jwtutils"

    "golang.org/x/crypto/bcrypt"
)

// LoginHandler handles user login and token generation.
func (ac *AuthController) LoginHandler(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        UserLogin    string `json:"login"`
        UserPassword string `json:"password"`
    }

    // Decode the incoming JSON request body into credentials struct.
    if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Fetch the user by login name.
    user, err := ac.fetchUserByLogin(credentials.UserLogin)
    if err != nil {
        http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
        return
    }

    // Compare the provided password with the stored hashed password.
    if err := bcrypt.CompareHashAndPassword([]byte(user.UserPassword), []byte(credentials.UserPassword)); err != nil {
        http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
        return
    }

    // Generate a new JWT for the user.
    token, err := jwtutils.GenerateJWT(ac.CassandraSession, user.UserId)
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // Respond with the generated token.
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": token,
    })
}

// LogoutHandler invalidates the user's JWT token by adding it to the blacklist.
func (ac *AuthController) LogoutHandler(w http.ResponseWriter, r *http.Request) {
    // Placeholder implementation
    http.Error(w, "LogoutHandler not implemented", http.StatusNotImplemented)
}

