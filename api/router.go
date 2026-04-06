package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"hysteria_server/config"
	"hysteria_server/payments"
)

type contextKey string

const ctxKeyUserID contextKey = "userID"

type handler struct {
	cfg *config.Config
	sbp *payments.Client
}

func getUserID(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyUserID).(string)
	return v
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n
	}
	return defaultVal
}

func NewRouter(cfg *config.Config) http.Handler {
	sbpClient := payments.NewClient(cfg.TochkaAPIKey, cfg.TochkaMerchantID, cfg.TochkaAccountID)
	h := &handler{cfg: cfg, sbp: sbpClient}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "lowkey-vpn-go-api",
		})
	})
	mux.HandleFunc("GET /blocked", h.blockedPage)

	mux.HandleFunc("GET /api/servers/list", h.getServers)

	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/register", h.register)

	mux.Handle("GET /api/user/profile", h.auth(http.HandlerFunc(h.getProfile)))
	mux.Handle("GET /api/user/transactions", h.auth(http.HandlerFunc(h.getTransactions)))

	mux.Handle("POST /api/user/promo/activate", h.auth(http.HandlerFunc(h.activatePromo)))
	mux.Handle("GET /api/user/promo/history", h.auth(http.HandlerFunc(h.promoHistory)))

	mux.HandleFunc("GET /api/subscriptions/plans", h.getPlans)
	mux.Handle("POST /api/subscriptions/purchase", h.auth(http.HandlerFunc(h.purchaseSubscription)))

	mux.Handle("POST /api/payments/create", h.auth(http.HandlerFunc(h.createPayment)))
	mux.Handle("GET /api/payments/{id}/status", h.auth(http.HandlerFunc(h.paymentStatus)))

	return mux
}

func ListenAndServe(mux http.Handler, addr string) {
	log.Printf("[API] HTTP management server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[API] Fatal: %v", err)
	}
}

func (h *handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, errmsg("missing authorization header"))
			return
		}

		tokenStr := strings.TrimPrefix(header, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return h.cfg.JWTSecret, nil
		})
		if err != nil || !token.Valid {
			writeJSON(w, http.StatusUnauthorized, errmsg("invalid token"))
			return
		}

		claims, _ := token.Claims.(jwt.MapClaims)
		userID, _ := claims["userId"].(string)
		if userID == "" {
			writeJSON(w, http.StatusUnauthorized, errmsg("missing userId"))
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[API] JSON encode error: %v", err)
	}
}

func errmsg(text string) map[string]string {
	return map[string]string{"message": text}
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errmsg("invalid JSON: "+err.Error()))
		return false
	}
	return true
}
