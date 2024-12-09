package authcontroller

import (
    "github.com/gocql/gocql"
)

type AuthController struct {
    CassandraSession *gocql.Session
}

// Constructor
func NewAuthController(session *gocql.Session) *AuthController {
    return &AuthController{CassandraSession: session}
}

type AuthenticatedUserAccount struct {
    UserId       gocql.UUID `json:"userId"`
    UserLogin    string     `json:"login"`
    UserPassword string     `json:"password"`
}
