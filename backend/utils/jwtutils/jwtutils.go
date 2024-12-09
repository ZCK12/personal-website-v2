package jwtutils

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"

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
    KID       string
    Secret    string
    CreatedAt time.Time
    ValidUntil time.Time
}

// GenerateJWT creates a JWT signed with the most recent key or generates a new one if none exist
func GenerateJWT(session *gocql.Session, userId string) (string, error) {
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
        "userId": userId,
        "exp":    time.Now().Add(time.Hour * JWT_EXPIRATION_HOURS).Unix(),
    })

    token.Header["kid"] = key.KID

    return token.SignedString([]byte(key.Secret))
}

// ValidateJWT validates a JWT and retrieves the userId from its claims
func ValidateJWT(session *gocql.Session, tokenString string) (string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("missing kid in token header")
        }

        var secret string
        var validUntil time.Time
        if err := session.Query(
            "SELECT secret, valid_until FROM jwt_keys WHERE kid = ?",
            kid,
        ).Scan(&secret, &validUntil); err != nil {
            return nil, fmt.Errorf("failed to fetch signing key: %v", err)
        }

        if time.Now().After(validUntil) {
            return nil, fmt.Errorf("key is no longer valid")
        }

        return []byte(secret), nil
    })

    if err != nil || !token.Valid {
        return "", fmt.Errorf("invalid token: %v", err)
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return "", fmt.Errorf("invalid token claims")
    }

    userId, ok := claims["userId"].(string)
    if !ok {
        return "", fmt.Errorf("userId not found in token claims")
    }

    return userId, nil
}

// RotateKey creates a new signing key by calling generateNewKey
func RotateKey(session *gocql.Session) (*JWTToken, error) {
    return generateNewKey(session)
}

// newJWTToken creates a new JWT token instance
func newJWTToken(kid string, secret string, createdAt time.Time, validUntil time.Time) *JWTToken {
    return &JWTToken{
        KID:       kid,
        Secret:    secret,
        CreatedAt: createdAt,
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

// fetchLatestKey retrieves the latest signing key from the database
func fetchLatestKey(session *gocql.Session) (*JWTToken, error) {
    var kid gocql.UUID
    var secret string
    var createdAt, validUntil time.Time

    err := session.Query(
        "SELECT kid, secret, created_at, valid_until FROM jwt_keys ORDER BY created_at DESC LIMIT 1",
    ).Scan(&kid, &secret, &createdAt, &validUntil)

    if err != nil {
        return nil, fmt.Errorf("failed to fetch latest key: %v", err)
    }

    return newJWTToken(kid.String(), secret, createdAt, validUntil), nil
}
