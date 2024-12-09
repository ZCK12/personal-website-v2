package usercontroller

import (
    "errors"

    "golang.org/x/crypto/bcrypt"
    "github.com/gocql/gocql"
)

func (uc *UserController) insertNewUser(user NewUserAccount) (gocql.UUID, error) {
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

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.UserPassword), bcrypt.DefaultCost)
    if err != nil {
        return gocql.UUID{}, err
    }

    userId := gocql.TimeUUID()

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

func (uc *UserController) deleteUserById(userId gocql.UUID) error {
    query := "DELETE FROM users WHERE user_id = ?"
    return uc.CassandraSession.Query(query, userId).Exec()
}

func (uc *UserController) updateUserPassword(userId gocql.UUID, hashedPassword string) error {
    query := "UPDATE users SET password = ? WHERE user_id = ?"
    return uc.CassandraSession.Query(query, hashedPassword, userId).Exec()
}
