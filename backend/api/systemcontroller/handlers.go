package systemcontroller

import (
    "net/http"

    "github.com/ZCK12/personal-website-v2/backend/utils/jwtutils"
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

// InvalidateAllCryptoKeysHandler invalidates all cryptographic keys.
func (sc *SystemController) InvalidateAllCryptoKeysHandler(w http.ResponseWriter, r *http.Request) {
    err := jwtutils.InvalidateAllKeys(sc.CassandraSession)
    if err != nil {
        http.Error(w, "Could not invalidate crypto keys: "+err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "All crypto keys invalidated successfully"}`))
}

// FlushAllCryptoKeysHandler invalidates all cryptographic keys.
func (sc *SystemController) FlushAllCryptoKeysHandler(w http.ResponseWriter, r *http.Request) {
    err := jwtutils.TruncateKeysTable(sc.CassandraSession)
    if err != nil {
        http.Error(w, "Could not flush crypto keys: "+err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "Flushed all crypto keys successfully"}`))
}
