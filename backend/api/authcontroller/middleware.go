package authcontroller

import (
    "context"
    "net/http"
    "strings"

    "github.com/ZCK12/personal-website-v2/backend/utils/jwtutils"
    "github.com/gocql/gocql"
)

// UserAuthenticationMiddleware verifies the user's JWT and adds their ID to the context.
func (ac *AuthController) UserAuthenticationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Retrieve the token from the Authorization header.
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
            return
        }

        // Validate the Authorization header format.
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
            return
        }

        tokenString := parts[1]

        // Validate the token and extract the userId.
        userId, err := jwtutils.ValidateJWT(ac.CassandraSession, tokenString)
        if err != nil {
            http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Validate that the User can be found and is not deleted, etc.
        _, err = ac.fetchUserById(userId)
        if err != nil {
            http.Error(w, "Invalid token holder: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Attach the userId to the request context and pass control to the next handler.
        ctx := context.WithValue(r.Context(), "authenticatedUserId", userId)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// AdminAuthenticationMiddleware verifies the user's JWT, checks admin status, and adds their ID to the context.
func (ac *AuthController) AdminAuthenticationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Retrieve the token from the Authorization header.
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
            return
        }

        // Validate the Authorization header format.
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
            return
        }

        tokenString := parts[1]

        // Validate the token and extract the userId.
        userId, err := jwtutils.ValidateJWT(ac.CassandraSession, tokenString)
        if err != nil {
            http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Check if the user exists and is not deleted, banned, etc.
        _, err = ac.fetchUserById(userId)
        if err != nil {
            if err == gocql.ErrNotFound {
                http.Error(w, "User not found", http.StatusUnauthorized)
                return
            }
            http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
            return
        }

        // Ensure the user is an admin.
        isAdmin, err := ac.isUserAdmin(userId)
        if err != nil {
            http.Error(w, "Failed to verify admin status: "+err.Error(), http.StatusInternalServerError)
            return
        }
        if !isAdmin {
            http.Error(w, "User does not have admin privileges", http.StatusForbidden)
            return
        }

        // Attach the userId to the request context and pass control to the next handler.
        ctx := context.WithValue(r.Context(), "authenticatedUserId", userId)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
