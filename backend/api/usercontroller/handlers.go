package usercontroller

import (
    "encoding/json"
    "net/http"

    "golang.org/x/crypto/bcrypt"
    "github.com/gocql/gocql"
)

// NewUserInsertionHandler handles the creation of a new user account.
func (uc *UserController) NewUserInsertionHandler(w http.ResponseWriter, r *http.Request) {
    var user NewUserAccount

    // Decode the incoming JSON request body into a NewUserAccount struct.
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields.
    if user.UserEmail == "" || user.UserLogin == "" || user.UserPassword == "" {
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Attempt to insert a new user into the database.
    userId, err := uc.insertNewUser(user)
    if err != nil {
        http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with the newly created user's ID.
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{
        "userId": userId.String(),
    })
}

func (uc *UserController) UserSelfFetchHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the context set by the authentication middleware.
    userId, ok := r.Context().Value("authenticatedUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    // Fetch the user's details from the database.
    user, err := uc.fetchUserById(userId)
    if err == gocql.ErrNotFound {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    if err != nil {
        http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Prepare and send the user's details as a JSON response.
    response := UserFetchResponse{
        UserId:    user.UserId,
        UserEmail: user.UserEmail,
        UserLogin: user.UserLogin,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// UserFetchHandler handles fetching a user's information by their ID.
func (uc *UserController) UserFetchHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the request context.
    userId, ok := r.Context().Value("contextualUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    // Fetch the user from the database.
    user, err := uc.fetchUserById(userId)
    if err == gocql.ErrNotFound {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    if err != nil {
        http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Prepare and send the user data as a JSON response.
    response := UserFetchResponse{
        UserId:    user.UserId,
        UserEmail: user.UserEmail,
        UserLogin: user.UserLogin,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (uc *UserController) FetchAllUsersHandler(w http.ResponseWriter, r *http.Request) {
    // Query the database for all users.
    query := "SELECT user_id, email, login FROM users"
    iter := uc.CassandraSession.Query(query).Iter()

    // Iterate through the results and construct the response.
    var users []UserFetchResponse
    var user UserFetchResponse
    for iter.Scan(&user.UserId, &user.UserEmail, &user.UserLogin) {
        users = append(users, user)
    }

    // Check for iteration errors.
    if err := iter.Close(); err != nil {
        http.Error(w, "Failed to fetch users: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with the list of users as JSON.
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}

func (uc *UserController) UserSelfDeletionHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the request context
    userId, ok := r.Context().Value("authenticatedUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    // Attempt to delete the user from the database
    if err := uc.deleteUserById(userId); err != nil {
        if err == gocql.ErrNotFound {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }
        http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with success
    w.WriteHeader(http.StatusNoContent) // 204 No Content
}

func (uc *UserController) UserDeletionHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the URL path parameter
    userId, ok := r.Context().Value("contextualUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusBadRequest)
        return
    }

    // Attempt to delete the user from the database
    if err := uc.deleteUserById(userId); err != nil {
        if err == gocql.ErrNotFound {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }
        http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with success
    w.WriteHeader(http.StatusNoContent) // 204 No Content
}

func (uc *UserController) UserSelfPasswordChangeHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the request context
    userId, ok := r.Context().Value("authenticatedUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    var req struct {
        CurrentPassword string `json:"currentPassword"`
        NewPassword     string `json:"newPassword"`
    }

    // Decode the JSON body into the request struct
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate that all required fields are provided
    if req.CurrentPassword == "" || req.NewPassword == "" {
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Fetch the user by userId
    user, err := uc.fetchUserById(userId)
    if err == gocql.ErrNotFound {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    if err != nil {
        http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Verify the current password
    if err := bcrypt.CompareHashAndPassword([]byte(user.UserPassword), []byte(req.CurrentPassword)); err != nil {
        http.Error(w, "Incorrect current password", http.StatusUnauthorized)
        return
    }

    // Hash the new password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Failed to hash password", http.StatusInternalServerError)
        return
    }

    // Update the password in the database
    if err := uc.updateUserPassword(userId, string(hashedPassword)); err != nil {
        http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Password updated successfully",
    })
}

func (uc *UserController) UserPasswordChangeHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the URL path
    userId, ok := r.Context().Value("contextualUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusBadRequest)
        return
    }

    var req struct {
        NewPassword string `json:"newPassword"`
    }

    // Decode the JSON body into the request struct
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate that the new password is provided
    if req.NewPassword == "" {
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Hash the new password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Failed to hash password", http.StatusInternalServerError)
        return
    }

    // Update the password in the database
    if err := uc.updateUserPassword(userId, string(hashedPassword)); err != nil {
        http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Password updated successfully",
    })
}

// UserActivityHandler fetches activity logs for a specific user.
func (uc *UserController) UserReferralCodeHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the request context.
    userId, ok := r.Context().Value("authenticatedUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    // Placeholder implementation
    http.Error(w, "UserActivityHandler not implemented for userId: "+userId.String(), http.StatusNotImplemented)
}


// UserActivityHandler fetches activity logs for a specific user.
func (uc *UserController) UserActivityHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the userId from the request context.
    userId, ok := r.Context().Value("contextualUserId").(gocql.UUID)
    if !ok {
        http.Error(w, "userId not found in context", http.StatusInternalServerError)
        return
    }

    // Placeholder implementation
    http.Error(w, "UserActivityHandler not implemented for userId: "+userId.String(), http.StatusNotImplemented)
}


