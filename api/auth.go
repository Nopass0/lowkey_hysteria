package api

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	voidorm "github.com/Nopass0/void_go"
	"golang.org/x/crypto/bcrypt"

	"hysteria_server/db"
)

type loginReq struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type registerReq struct {
	Login        string  `json:"login"`
	Password     string  `json:"password"`
	ReferralCode *string `json:"referralCode,omitempty"`
}

type authUser struct {
	ID         string `json:"id"`
	Login      string `json:"login"`
	AvatarHash string `json:"avatarHash"`
	IsAdmin    bool   `json:"isAdmin"`
}

type authResp struct {
	Token string   `json:"token"`
	User  authUser `json:"user"`
}

var loginRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,24}$`)

func avatarHash(login string) string {
	hash := md5.Sum([]byte(strings.ToLower(login)))
	return hex.EncodeToString(hash[:])
}

func generateReferralCode(login string) string {
	loginUpper := strings.ToUpper(login)
	if len(loginUpper) > 8 {
		loginUpper = loginUpper[:8]
	}
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	suffix := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("%s%s", loginUpper, suffix)
}

func (h *handler) signJwt(userID string, isAdmin bool) (string, error) {
	jti := uuid.New().String()
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":  userID,
		"isAdmin": isAdmin,
		"jti":     jti,
		"iat":     time.Now().Unix(),
		"exp":     exp,
	})
	return token.SignedString(h.cfg.JWTSecret)
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errmsg("invalid JSON"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	userDoc, err := db.FindOne(ctx, "users", voidorm.NewQuery().Where("login", voidorm.Eq, req.Login))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("User not found"))
		return
	}

	if db.AsBool(userDoc, "isBanned") {
		writeJSON(w, http.StatusForbidden, errmsg("Account banned"))
		return
	}

	passwordHash := db.AsString(userDoc, "passwordHash")
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, errmsg("Wrong password"))
		return
	}

	token, err := h.signJwt(db.AsString(userDoc, "_id"), db.AsBool(userDoc, "isAdmin"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Internal server error"))
		return
	}

	login := db.AsString(userDoc, "login")
	writeJSON(w, http.StatusOK, authResp{
		Token: token,
		User: authUser{
			ID:         db.AsString(userDoc, "_id"),
			Login:      login,
			AvatarHash: avatarHash(login),
			IsAdmin:    db.AsBool(userDoc, "isAdmin"),
		},
	})
}

func (h *handler) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errmsg("invalid JSON"))
		return
	}

	if !loginRegex.MatchString(req.Login) {
		writeJSON(w, http.StatusBadRequest, errmsg("Login must be 3-24 chars, alphanumeric + underscore"))
		return
	}
	if len(req.Password) < 6 {
		writeJSON(w, http.StatusBadRequest, errmsg("Password must be at least 6 characters"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if _, err := db.FindOne(ctx, "users", voidorm.NewQuery().Where("login", voidorm.Eq, req.Login)); err == nil {
		writeJSON(w, http.StatusConflict, errmsg("Login already taken"))
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Internal server error"))
		return
	}

	referredByID := ""
	if req.ReferralCode != nil && *req.ReferralCode != "" {
		if refDoc, err := db.FindOne(ctx, "users", voidorm.NewQuery().Where("referralCode", voidorm.Eq, *req.ReferralCode)); err == nil {
			referredByID = db.AsString(refDoc, "_id")
		}
	}

	referralCode := ""
	for {
		referralCode = generateReferralCode(req.Login)
		if _, err := db.FindOne(ctx, "users", voidorm.NewQuery().Where("referralCode", voidorm.Eq, referralCode)); err != nil {
			break
		}
	}

	doc := voidorm.Doc{
		"login":               req.Login,
		"passwordHash":        string(hash),
		"balance":             0.0,
		"referralBalance":     0.0,
		"isBanned":            false,
		"isAdmin":             false,
		"referralCode":        referralCode,
		"joinedAt":            time.Now().UTC(),
		"pendingDiscountFixed": 0.0,
		"pendingDiscountPct":   0.0,
		"referralRate":         0.05,
		"hideAiMenu":           false,
	}
	if referredByID != "" {
		doc["referredById"] = referredByID
	}

	newUserID, err := db.Insert(ctx, "users", doc)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Internal server error"))
		return
	}

	token, _ := h.signJwt(newUserID, false)
	writeJSON(w, http.StatusCreated, authResp{
		Token: token,
		User: authUser{
			ID:         newUserID,
			Login:      req.Login,
			AvatarHash: avatarHash(req.Login),
			IsAdmin:    false,
		},
	})
}
