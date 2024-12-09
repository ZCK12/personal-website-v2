package authcontroller

import (
    "time"
    "fmt"

    "github.com/gocql/gocql"
)

func (ac *AuthController) fetchUserByLogin(userLogin string) (AuthenticatedUserAccount, error) {
    var fetchedUser AuthenticatedUserAccount

    err := ac.CassandraSession.Query(
        "SELECT user_id, login, password FROM users WHERE login = ?",
        userLogin,
    ).Consistency(gocql.One).Scan(
        &fetchedUser.UserId,
        &fetchedUser.UserLogin,
        &fetchedUser.UserPassword,
    )

    return fetchedUser, err
}

func (ac *AuthController) fetchUserById(userId gocql.UUID) (AuthenticatedUserAccount, error) {
    var fetchedUser AuthenticatedUserAccount

    err := ac.CassandraSession.Query(
        "SELECT user_id, login, password FROM users WHERE user_id = ?",
        userId,
    ).Consistency(gocql.One).Scan(
        &fetchedUser.UserId,
        &fetchedUser.UserLogin,
        &fetchedUser.UserPassword,
    )

    return fetchedUser, err
}

func (ac *AuthController) isUserAdmin(userId gocql.UUID) (bool, error) {
    var adminFrom, adminUntil time.Time

    // Query the admin table for the given userId
    query := "SELECT admin_from, admin_until FROM admin_users WHERE user_id = ?"
    if err := ac.CassandraSession.Query(query, userId).Consistency(gocql.One).Scan(&adminFrom, &adminUntil); err != nil {
        if err == gocql.ErrNotFound {
            // User is not an admin if no record is found
            return false, nil
        }
        // Return an error if the query fails
        return false, fmt.Errorf("failed to query admin table: %v", err)
    }

    // Check if the current time falls within the admin_from and admin_until range
    now := time.Now().UTC()
    if now.After(adminFrom) && now.Before(adminUntil) {
        return true, nil
    }

    // User is not an admin if the current time is outside the valid range
    return false, nil
}
