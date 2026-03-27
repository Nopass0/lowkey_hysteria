package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

type Result struct {
	OK     bool
	UserID string
	Reason string
}

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

func AuthenticateAndRegister(token string, jwtSecret []byte) Result {
	userID, err := VerifyJWT(token, jwtSecret)
	if err != nil {
		return Result{Reason: "unauthorized: " + err.Error()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := db.FindOne(
		ctx,
		"subscriptions",
		voidorm.NewQuery().Where("userId", voidorm.Eq, userID),
	)
	if err != nil {
		return Result{Reason: "нет активной подписки"}
	}

	isLifetime := db.AsBool(sub, "isLifetime")
	activeUntil := db.AsTime(sub, "activeUntil")
	if !isLifetime && (activeUntil.IsZero() || time.Now().After(activeUntil)) {
		return Result{Reason: "подписка истекла"}
	}

	return Result{OK: true, UserID: userID}
}
