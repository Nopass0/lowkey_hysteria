package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ─── User profile ─────────────────────────────────────────────────────────────

type subInfo struct {
	PlanID      string `json:"planId"`
	PlanName    string `json:"planName"`
	ActiveUntil string `json:"activeUntil"`
	IsLifetime  bool   `json:"isLifetime"`
}

// getProfile handles GET /api/user/profile.
//
// @route  GET /api/user/profile
// @access authenticated
func (h *handler) getProfile(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	type profile struct {
		ID              string   `json:"id"`
		Login           string   `json:"login"`
		Balance         float64  `json:"balance"`
		ReferralBalance float64  `json:"referralBalance"`
		Subscription    *subInfo `json:"subscription"`
		JoinedAt        string   `json:"joinedAt"`
	}

	var p profile
	var joinedAt time.Time
	err := h.db.QueryRow(ctx, `
		SELECT id, login, balance, "referralBalance", "joinedAt"
		FROM users WHERE id = $1
	`, userID).Scan(&p.ID, &p.Login, &p.Balance, &p.ReferralBalance, &joinedAt)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("user not found"))
		return
	}
	p.JoinedAt = joinedAt.Format(time.RFC3339)

	var sub subInfo
	var activeUntil time.Time
	err = h.db.QueryRow(ctx, `
		SELECT "planId", "planName", "activeUntil", "isLifetime"
		FROM subscriptions WHERE "userId" = $1
	`, userID).Scan(&sub.PlanID, &sub.PlanName, &activeUntil, &sub.IsLifetime)
	if err == nil {
		sub.ActiveUntil = activeUntil.Format(time.RFC3339)
		p.Subscription = &sub
	}

	writeJSON(w, http.StatusOK, p)
}

// ─── Transactions ─────────────────────────────────────────────────────────────

// getTransactions handles GET /api/user/transactions?page=1&pageSize=10.
//
// @route  GET /api/user/transactions
// @access authenticated
func (h *handler) getTransactions(w http.ResponseWriter, r *http.Request) {
	userID   := getUserID(r)
	page     := queryInt(r, "page", 1)
	pageSize := queryInt(r, "pageSize", 10)
	skip     := (page - 1) * pageSize

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	type txItem struct {
		ID        string  `json:"id"`
		Type      string  `json:"type"`
		Amount    float64 `json:"amount"`
		Title     string  `json:"title"`
		CreatedAt string  `json:"createdAt"`
	}

	rows, err := h.db.Query(ctx, `
		SELECT id, type, amount, title, "createdAt"
		FROM transactions WHERE "userId" = $1
		ORDER BY "createdAt" DESC LIMIT $2 OFFSET $3
	`, userID, pageSize, skip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}
	defer rows.Close()

	var items []txItem
	for rows.Next() {
		var item txItem
		var createdAt time.Time
		if err = rows.Scan(&item.ID, &item.Type, &item.Amount, &item.Title, &createdAt); err == nil {
			item.CreatedAt = createdAt.Format(time.RFC3339)
			items = append(items, item)
		}
	}

	var total int
	h.db.QueryRow(ctx, `SELECT COUNT(*) FROM transactions WHERE "userId"=$1`, userID).Scan(&total) //nolint:errcheck

	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total,
		"page": page, "pageSize": pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	})
}

// formatFloat форматирует float64 без лишних нулей.
func formatFloat(f float64) string {
	s := fmt.Sprintf("%.2f", f)
	for len(s) > 1 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if len(s) > 1 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

// max64 возвращает большее из двух float64.
func max64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
