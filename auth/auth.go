// Package auth provides JWT verification and subscription validation for
// incoming VPN connections.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Result is returned by AuthenticateAndRegister.
type Result struct {
	// OK is true when the user is authenticated and has an active subscription.
	OK bool

	// UserID is the authenticated user's UUID string.
	UserID string

	// Reason contains a human-readable error message when OK is false.
	Reason string
}

// VerifyJWT parses and validates a JWT token string, returning the contained
// userId claim on success.
//
// @param tokenStr - raw JWT string from the client hello message
// @param secret   - HMAC secret used to sign tokens
// @returns (userId string, error)
func VerifyJWT(tokenStr string, secret []byte) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	userID, ok := claims["userId"].(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("missing userId claim")
	}
	return userID, nil
}

// AuthenticateAndRegister verifies the JWT, looks up the user's subscription
// in the database, and returns an auth Result.
//
// @param pool      - PostgreSQL connection pool
// @param token     - raw JWT string from ClientHello.Auth
// @param jwtSecret - HMAC secret
// @returns Result
func AuthenticateAndRegister(pool *pgxpool.Pool, token string, jwtSecret []byte) Result {
	userID, err := VerifyJWT(token, jwtSecret)
	if err != nil {
		return Result{Reason: "unauthorized: " + err.Error()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var isLifetime bool
	var activeUntil time.Time
	// Look up the user's subscription — only the active/lifetime columns are needed.
	err = pool.QueryRow(ctx,
		`SELECT "isLifetime", "activeUntil" FROM subscriptions WHERE "userId" = $1`,
		userID,
	).Scan(&isLifetime, &activeUntil)
	if err != nil {
		return Result{Reason: "нет активной подписки"}
	}

	if !isLifetime && time.Now().After(activeUntil) {
		return Result{Reason: "подписка истекла"}
	}

	return Result{OK: true, UserID: userID}
}
