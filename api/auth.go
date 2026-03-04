package api

import (
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
	"golang.org/x/crypto/bcrypt"
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
	rand.Read(b)
	suffix := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("%s%s", loginUpper, suffix)
}

func (h *handler) signJwt(userID string, isAdmin bool) (string, error) {
	jti := uuid.New().String()
	exp := time.Now().Add(30 * 24 * time.Hour).Unix() // 30 days
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

	var id, passwordHash string
	var isBanned bool
	err := h.db.QueryRow(r.Context(), `SELECT id, "passwordHash", "isBanned" FROM users WHERE login = $1`, req.Login).
		Scan(&id, &passwordHash, &isBanned)

	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("User not found"))
		return
	}

	if isBanned {
		writeJSON(w, http.StatusForbidden, errmsg("Account banned"))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, errmsg("Wrong password"))
		return
	}

	token, err := h.signJwt(id, false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Internal server error"))
		return
	}

	writeJSON(w, http.StatusOK, authResp{
		Token: token,
		User: authUser{
			ID:         id,
			Login:      req.Login,
			AvatarHash: avatarHash(req.Login),
			IsAdmin:    false,
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

	var existing string
	h.db.QueryRow(r.Context(), `SELECT id FROM users WHERE login = $1`, req.Login).Scan(&existing)
	if existing != "" {
		writeJSON(w, http.StatusConflict, errmsg("Login already taken"))
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Internal server error"))
		return
	}

	var referredByID *string
	if req.ReferralCode != nil && *req.ReferralCode != "" {
		var rId string
		if err := h.db.QueryRow(r.Context(), `SELECT id FROM users WHERE "referralCode" = $1`, *req.ReferralCode).Scan(&rId); err == nil {
			referredByID = &rId
		}
	}

	var userReferralCode string
	for {
		userReferralCode = generateReferralCode(req.Login)
		var c string
		h.db.QueryRow(r.Context(), `SELECT id FROM users WHERE "referralCode" = $1`, userReferralCode).Scan(&c)
		if c == "" {
			break
		}
	}

	var newUserID string
	err = h.db.QueryRow(r.Context(), `
		INSERT INTO users (login, "passwordHash", "referralCode", "referredById")
		VALUES ($1, $2, $3, $4) RETURNING id
	`, req.Login, string(hash), userReferralCode, referredByID).Scan(&newUserID)

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
