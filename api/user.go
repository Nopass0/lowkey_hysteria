package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

type subInfo struct {
	PlanID      string `json:"planId"`
	PlanName    string `json:"planName"`
	ActiveUntil string `json:"activeUntil"`
	IsLifetime  bool   `json:"isLifetime"`
}

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

	userDoc, err := db.FindByID(ctx, "users", userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("user not found"))
		return
	}

	p := profile{
		ID:              db.AsString(userDoc, "_id"),
		Login:           db.AsString(userDoc, "login"),
		Balance:         db.AsFloat64(userDoc, "balance"),
		ReferralBalance: db.AsFloat64(userDoc, "referralBalance"),
		JoinedAt:        db.AsTime(userDoc, "joinedAt").Format(time.RFC3339),
	}

	subDoc, err := db.FindOne(ctx, "subscriptions", voidorm.NewQuery().Where("userId", voidorm.Eq, userID))
	if err == nil {
		p.Subscription = &subInfo{
			PlanID:      db.AsString(subDoc, "planId"),
			PlanName:    db.AsString(subDoc, "planName"),
			ActiveUntil: db.AsTime(subDoc, "activeUntil").Format(time.RFC3339),
			IsLifetime:  db.AsBool(subDoc, "isLifetime"),
		}
	}

	writeJSON(w, http.StatusOK, p)
}

func (h *handler) getTransactions(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "pageSize", 10)
	skip := (page - 1) * pageSize

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	type txItem struct {
		ID        string  `json:"id"`
		Type      string  `json:"type"`
		Amount    float64 `json:"amount"`
		Title     string  `json:"title"`
		CreatedAt string  `json:"createdAt"`
	}

	rows, total, err := db.QueryCount(
		ctx,
		"transactions",
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			OrderBy("createdAt", voidorm.Desc).
			Skip(skip).
			Limit(pageSize),
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}

	items := make([]txItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, txItem{
			ID:        db.AsString(row, "_id"),
			Type:      db.AsString(row, "type"),
			Amount:    db.AsFloat64(row, "amount"),
			Title:     db.AsString(row, "title"),
			CreatedAt: db.AsTime(row, "createdAt").Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

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

func max64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
