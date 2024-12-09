package usercontroller

import "github.com/gocql/gocql"

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

func NewUserController(session *gocql.Session) *UserController {
    return &UserController{CassandraSession: session}
}
