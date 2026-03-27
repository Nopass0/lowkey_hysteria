package api

import (
	"context"
	"net/http"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

func (h *handler) createPayment(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	var body struct {
		Amount float64 `json:"amount"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Amount < 10 {
		writeJSON(w, http.StatusBadRequest, errmsg("Minimum amount is 10 RUB"))
		return
	}

	qrcID, payloadURL, err := h.sbp.CreateSBP(body.Amount, "Пополнение баланса lowkey VPN")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Failed to create payment: "+err.Error()))
		return
	}

	expiresAt := time.Now().Add(30 * time.Minute).UTC()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	paymentID, err := db.Insert(ctx, "payments", voidorm.Doc{
		"userId":       userID,
		"sbpPaymentId": qrcID,
		"amount":       body.Amount,
		"status":       "pending",
		"qrUrl":        payloadURL,
		"sbpUrl":       payloadURL,
		"createdAt":    time.Now().UTC(),
		"expiresAt":    expiresAt,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Failed to store payment"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"paymentId": paymentID,
		"qrUrl":     payloadURL,
		"sbpUrl":    payloadURL,
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
}

func (h *handler) paymentStatus(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	paymentID := r.PathValue("id")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	paymentDoc, err := db.FindByID(ctx, "payments", paymentID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("Payment not found"))
		return
	}
	if db.AsString(paymentDoc, "userId") != userID {
		writeJSON(w, http.StatusForbidden, errmsg("Forbidden"))
		return
	}

	amount := db.AsFloat64(paymentDoc, "amount")
	status := db.AsString(paymentDoc, "status")
	expiresAt := db.AsTime(paymentDoc, "expiresAt")
	sbpPaymentID := db.AsString(paymentDoc, "sbpPaymentId")

	resp := func(nextStatus string) {
		writeJSON(w, http.StatusOK, map[string]any{
			"paymentId": paymentID,
			"status":    nextStatus,
			"amount":    amount,
		})
	}

	if status != "pending" {
		resp(status)
		return
	}

	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		_, _ = db.Patch(ctx, "payments", paymentID, voidorm.Doc{"status": "expired"})
		resp("expired")
		return
	}

	sbpResp, err := h.sbp.GetPaymentStatus(sbpPaymentID)
	if err == nil && sbpResp != nil {
		switch sbpResp.OperationStatus {
		case "ACWP", "ACSC", "Accepted":
			_, _ = db.Patch(ctx, "payments", paymentID, voidorm.Doc{"status": "success"})
			_ = h.sbp.OnPaymentSuccess(ctx, userID, amount)
			resp("success")
			return
		case "RJCT", "CANC", "Rejected":
			_, _ = db.Patch(ctx, "payments", paymentID, voidorm.Doc{"status": "failed"})
			resp("failed")
			return
		}
	}

	resp("pending")
}
