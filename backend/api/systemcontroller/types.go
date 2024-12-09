package systemcontroller

import (
    "encoding/json"
    "errors"
    "context"
    "net/http"

    "github.com/ZCK12/personal-website-v2/backend/utils/jwtutils"

    "github.com/gocql/gocql"
)

type SystemController struct {
    CassandraSession *gocql.Session
}

// Constructor
func NewSystemController(session *gocql.Session) *SystemController {
    return &SystemController{CassandraSession: session}
}
