package jwtutils

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"
    "log"

    "github.com/gocql/gocql"
    "github.com/golang-jwt/jwt/v5"
)

const (
    KEY_VALIDITY_PERIOD_HOURS = 48
    KEY_SIZE_BYTES            = 32
    JWT_EXPIRATION_HOURS      = 4
)

// JWTToken represents a JWT token and its associated data
type JWTToken struct {
    KID        string
    Secret     string
    CreatedAt  time.Time
    ValidUntil time.Time
}

// GenerateJWT creates a JWT signed with the most recent key or generates a new one if none exist
func GenerateJWT(session *gocql.Session, userId gocql.UUID) (string, error) {
    // Try to fetch the latest valid key
    key, err := fetchLatestKey(session)
    if err != nil || time.Now().After(key.ValidUntil) {
        // Generate a new key if no valid key is found
        key, err = generateNewKey(session)
        if err != nil {
            return "", fmt.Errorf("failed to generate new key: %v", err)
        }
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "userId": userId.String(),
        "exp":    time.Now().Add(time.Hour * JWT_EXPIRATION_HOURS).Unix(),
    })

    token.Header["kid"] = key.KID

    return token.SignedString([]byte(key.Secret))
}

// ValidateJWT validates a JWT and retrieves the userId from its claims
func ValidateJWT(session *gocql.Session, tokenString string) (gocql.UUID, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return gocql.UUID{}, fmt.Errorf("missing kid in token header")
        }

        var secret string
        var validUntil time.Time
        if err := session.Query(
            "SELECT secret, valid_until FROM jwt_keys WHERE kid = ?",
            kid,
        ).Scan(&secret, &validUntil); err != nil {
            return gocql.UUID{}, fmt.Errorf("failed to fetch signing key: %v", err)
        }

        if time.Now().After(validUntil) {
            return gocql.UUID{}, fmt.Errorf("key is no longer valid")
        }

        return []byte(secret), nil
    })

    if err != nil || !token.Valid {
        return gocql.UUID{}, fmt.Errorf("invalid token: %v", err)
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return gocql.UUID{}, fmt.Errorf("invalid token claims")
    }

    userId, ok := claims["userId"].(string)
    if !ok {
        return gocql.UUID{}, fmt.Errorf("userId not found in token claims")
    }

    parsedUserId, err := gocql.ParseUUID(userId)
    if err != nil {
        return gocql.UUID{}, fmt.Errorf("userId could not be parsed as Cassandra UUID !")
    }

    return parsedUserId, nil
}

// RotateKey creates a new signing key
func RotateKey(session *gocql.Session) (*JWTToken, error) {
    return generateNewKey(session)
}

// InvalidateAllKeys invalidates all currently valid keys by updating their valid_until timestamps
func InvalidateAllKeys(session *gocql.Session) error {
    // Fetch all keys
    iter := session.Query(
        "SELECT kid, valid_until FROM jwt_keys",
    ).Iter()

    var (
        now          = time.Now().UTC()
        kid          gocql.UUID
        validUntil   time.Time
        invalidated  []gocql.UUID
    )

    // Collect keys that are still valid
    for iter.Scan(&kid, &validUntil) {
        if validUntil.After(now) {
            invalidated = append(invalidated, kid)
        }
    }

    if err := iter.Close(); err != nil {
        return fmt.Errorf("failed to fetch keys: %v", err)
    }

    if len(invalidated) == 0 {
        log.Println("No currently valid keys found to invalidate.")
        return nil
    }

    // Invalidate each key
    for _, key := range invalidated {
        log.Printf("Invalidating key: %s", key)
        query := "UPDATE jwt_keys SET valid_until = ? WHERE kid = ?"
        if err := session.Query(query, now, key).Consistency(gocql.All).Exec(); err != nil {
            return fmt.Errorf("failed to invalidate key %s: %v", key, err)
        }
    }

    log.Printf("Invalidated %d currently valid keys.", len(invalidated))
    return nil
}

// TruncateKeysTable truncates the entire jwt_keys table, removing all entries.
func TruncateKeysTable(session *gocql.Session) error {
    log.Println("Truncating the jwt_keys table...")

    // Execute the TRUNCATE command
    query := "TRUNCATE TABLE jwt_keys"
    if err := session.Query(query).Exec(); err != nil {
        return fmt.Errorf("failed to truncate jwt_keys table: %v", err)
    }

    log.Println("Successfully truncated the jwt_keys table.")
    return nil
}

// newJWTToken creates a new JWT token instance
func newJWTToken(kid, secret string, createdAt, validUntil time.Time) *JWTToken {
    return &JWTToken{
        KID:        kid,
        Secret:     secret,
        CreatedAt:  createdAt,
        ValidUntil: validUntil,
    }
}

// generateNewKey creates a new cryptographically secure key and stores it in the database
func generateNewKey(session *gocql.Session) (*JWTToken, error) {
    kid := gocql.TimeUUID().String()

    // Generate a cryptographically secure random secret
    secret, err := generateRandomSecret(KEY_SIZE_BYTES)
    if err != nil {
        return nil, fmt.Errorf("failed to generate secret: %v", err)
    }

    createdAt := time.Now()
    validUntil := createdAt.Add(time.Hour * KEY_VALIDITY_PERIOD_HOURS)

    // Insert the new key into the database
    if err := session.Query(
        "INSERT INTO jwt_keys (kid, secret, created_at, valid_until) VALUES (?, ?, ?, ?)",
                            kid, secret, createdAt, validUntil,
    ).Exec(); err != nil {
        return nil, fmt.Errorf("failed to store new key: %v", err)
    }

    return newJWTToken(kid, secret, createdAt, validUntil), nil
}

// generateRandomSecret creates a cryptographically secure random secret of the specified length
func generateRandomSecret(length int) (string, error) {
    bytes := make([]byte, length)

    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %v", err)
    }

    return base64.URLEncoding.EncodeToString(bytes), nil
}

// fetchLatestKey retrieves the most recent valid signing key from the database
func fetchLatestKey(session *gocql.Session) (*JWTToken, error) {
    iter := session.Query(
        "SELECT kid, secret, created_at, valid_until FROM jwt_keys",
    ).Iter()

    var (
        latestKey   *JWTToken
        kid         string
        secret      string
        createdAt   time.Time
        validUntil  time.Time
    )

    now := time.Now().UTC() // Current time for validation
    for iter.Scan(&kid, &secret, &createdAt, &validUntil) {
        if validUntil.After(now) && (latestKey == nil || createdAt.After(latestKey.CreatedAt)) {
            // Only consider keys where valid_until > now and createdAt is the latest
            latestKey = newJWTToken(kid, secret, createdAt, validUntil)
        }
    }

    if err := iter.Close(); err != nil {
        return nil, fmt.Errorf("failed to iterate over keys: %v", err)
    }

    if latestKey == nil {
        return nil, fmt.Errorf("no valid keys found")
    }

    return latestKey, nil
}

