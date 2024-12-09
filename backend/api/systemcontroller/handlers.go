package systemcontroller

import (
    "encoding/json"
    "errors"
    "context"
    "net/http"

    "github.com/ZCK12/personal-website-v2/backend/utils/jwtutils"

    "github.com/gocql/gocql"
)

// SystemStatusHandler responds with a simple OK for status checks.
func (sc *SystemController) SystemStatusHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status": "ok"}`))
}

// SystemHealthHandler performs a health check (can be expanded as needed).
func (sc *SystemController) SystemHealthHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"health": "good"}`))
}

// RotateCryptoKeyHandler rotates the cryptographic key.
func (sc *SystemController) RotateCryptoKeyHandler(w http.ResponseWriter, r *http.Request) {
    _, err := jwtutils.RotateKey(sc.CassandraSession)
    if err != nil {
        http.Error(w, "Could not rotate crypto key: "+err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "Crypto key rotated successfully"}`))
}

// InvalidateCryptoKeyHandler invalidates the current cryptographic key.
func (sc *SystemController) InvalidateCryptoKeyHandler(w http.ResponseWriter, r *http.Request) {
    _, err := jwtutils.InvalidateKey(sc.CassandraSession)
    if err != nil {
        http.Error(w, "Could not invalidate crypto key: "+err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "Crypto key invalidated successfully"}`))
}
