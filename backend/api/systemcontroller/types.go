package systemcontroller

import (
    "github.com/gocql/gocql"
)

type SystemController struct {
    CassandraSession *gocql.Session
}

// Constructor
func NewSystemController(session *gocql.Session) *SystemController {
    return &SystemController{CassandraSession: session}
}
