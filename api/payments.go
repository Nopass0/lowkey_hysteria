package api

import (
	"context"
	"net/http"
	"time"

	"hysteria_server/payments"
)

// ─── POST /api/payments/create ────────────────────────────────────────────────

// createPayment handles POST /api/payments/create.
// Creates a Tochka SBP QR-code session and saves it to the payments table.
//
// @route  POST /api/payments/create
// @body   { "amount": number }  (minimum 10 RUB)
// @access authenticated
// @returns { paymentId, qrUrl, sbpUrl, expiresAt }
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

	// Call Tochka SBP API
	qrcID, payloadURL, err := h.sbp.CreateSBP(body.Amount, "Пополнение баланса lowkey VPN")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("Failed to create payment: "+err.Error()))
		return
	}

	expiresAt := time.Now().Add(30 * time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var paymentID string
	err = h.db.QueryRow(ctx, `
		INSERT INTO payments(id,"userId","sbpPaymentId",amount,status,"qrUrl","sbpUrl","createdAt","expiresAt")
		VALUES(gen_random_uuid(),$1,$2,$3,'pending',$4,$4,NOW(),$5)
		RETURNING id
	`, userID, qrcID, body.Amount, payloadURL, expiresAt).Scan(&paymentID)
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

// ─── GET /api/payments/{id}/status ───────────────────────────────────────────

// paymentStatus handles GET /api/payments/{id}/status.
// Polls Tochka for payment status; credits user balance on success.
//
// @route  GET /api/payments/{id}/status
// @param  id - payment UUID
// @access authenticated
// @returns { paymentId, status, amount }
func (h *handler) paymentStatus(w http.ResponseWriter, r *http.Request) {
	userID    := getUserID(r)
	paymentID := r.PathValue("id")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	type payRow struct {
		ID           string
		UserID       string
		SbpPaymentID string
		Amount       float64
		Status       string
		ExpiresAt    time.Time
	}
	var p payRow
	err := h.db.QueryRow(ctx, `
		SELECT id, "userId", "sbpPaymentId", amount, status, "expiresAt"
		FROM payments WHERE id=$1
	`, paymentID).Scan(&p.ID, &p.UserID, &p.SbpPaymentID, &p.Amount, &p.Status, &p.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("Payment not found"))
		return
	}
	if p.UserID != userID {
		writeJSON(w, http.StatusForbidden, errmsg("Forbidden"))
		return
	}

	resp := func(status string) { writeJSON(w, http.StatusOK, map[string]any{"paymentId": p.ID, "status": status, "amount": p.Amount}) }

	if p.Status != "pending" {
		resp(p.Status)
		return
	}
	if time.Now().After(p.ExpiresAt) {
		h.db.Exec(ctx, `UPDATE payments SET status='expired' WHERE id=$1`, p.ID) //nolint:errcheck
		resp("expired")
		return
	}

	sbpResp, err := h.sbp.GetPaymentStatus(p.SbpPaymentID)
	if err == nil && sbpResp != nil {
		switch sbpResp.OperationStatus {
		case "ACWP", "ACSC", "Accepted":
			h.db.Exec(ctx, `UPDATE payments SET status='success' WHERE id=$1`, p.ID) //nolint:errcheck
			payments.OnPaymentSuccess(h.db, ctx, p.UserID, p.Amount)                 //nolint:errcheck
			resp("success")
			return
		case "RJCT", "CANC", "Rejected":
			h.db.Exec(ctx, `UPDATE payments SET status='failed' WHERE id=$1`, p.ID) //nolint:errcheck
			resp("failed")
			return
		}
	}

	resp("pending")
}
