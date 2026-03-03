// Package payments provides a Tochka SBP (Fast Payment System) API client
// implemented as plain Go HTTP calls — no external SDK layer required.
//
// Tochka API reference:  https://api.tochka.com/docs
// The same flow is replicated from the tochka-sbp npm package used in the
// TypeScript backend so both services behave identically.
package payments

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const tochkaBaseURL = "https://enter.tochka.com/uapi/sbp/v1.0"

// Client is the SBP API client.
type Client struct {
	apiKey     string // Bearer token
	merchantID string // Merchant identifier
	accountID  string // Bank account identifier
	http       *http.Client
}

// NewClient creates a new Client with the given credentials.
//
// @param apiKey     - Tochka Bearer token
// @param merchantID - Tochka merchant ID
// @param accountID  - Tochka account ID
func NewClient(apiKey, merchantID, accountID string) *Client {
	return &Client{
		apiKey:     apiKey,
		merchantID: merchantID,
		accountID:  accountID,
		http:       &http.Client{Timeout: 15 * time.Second},
	}
}

// ─── Request / response types ─────────────────────────────────────────────

// CreateQRRequest is the body sent to POST /qr-codes.
type CreateQRRequest struct {
	// Amount in kopecks (1 RUB = 100 kopecks).
	Amount      int    `json:"amount"`
	Currency    string `json:"currency"`
	Description string `json:"description"`
	MerchantID  string `json:"merchantId"`
	AccountID   string `json:"accountId"`
}

// CreateQRResponse is the Tochka API response for a newly created QR code.
type CreateQRResponse struct {
	// QrcID is the unique identifier of the QR code / payment session.
	QrcID   string `json:"qrcId"`
	// Payload is the SBP scheme URL / image URL used to display the QR.
	Payload string `json:"payload"`
}

// PaymentStatusResponse is the Tochka API response for a status query.
type PaymentStatusResponse struct {
	// OperationStatus can be "ACWP", "ACSC", "RJCT", "CANC", "PDNG".
	OperationStatus string `json:"operationStatus"`
	// Amount in kopecks.
	Amount          int    `json:"amount"`
}

// ─── API methods ──────────────────────────────────────────────────────────

// CreateSBP creates a new SBP QR-code payment session for the given amount
// (in rubles). Returns the QR payload URL and the qrcId that can be used for
// status polling.
//
// @param amountRUB  - amount in Russian Rubles
// @param description - payment description shown to the payer
// @returns (qrcId, payloadURL, error)
func (c *Client) CreateSBP(amountRUB float64, description string) (string, string, error) {
	reqBody := CreateQRRequest{
		Amount:      int(amountRUB * 100), // convert to kopecks
		Currency:    "RUB",
		Description: description,
		MerchantID:  c.merchantID,
		AccountID:   c.accountID,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", tochkaBaseURL+"/qr-codes", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("tochka API error %d: %s", resp.StatusCode, string(respBytes))
	}

	var result CreateQRResponse
	if err = json.Unmarshal(respBytes, &result); err != nil {
		return "", "", fmt.Errorf("unmarshal: %w", err)
	}
	return result.QrcID, result.Payload, nil
}

// GetPaymentStatus queries Tochka for the current status of a payment session.
//
// @param qrcID - the QR code identifier returned by CreateSBP
// @returns (PaymentStatusResponse, error)
func (c *Client) GetPaymentStatus(qrcID string) (*PaymentStatusResponse, error) {
	url := fmt.Sprintf("%s/qr-codes/%s/payment-status", tochkaBaseURL, qrcID)
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tochka API error %d: %s", resp.StatusCode, string(respBytes))
	}

	var result PaymentStatusResponse
	if err = json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &result, nil
}

// ─── Payment success handler ──────────────────────────────────────────────

// OnPaymentSuccess credits the user's balance and records a topup transaction.
// If the user was referred, 20% commission is awarded to the referrer.
// All operations run in a single PostgreSQL transaction for atomicity.
//
// @param pool   - PostgreSQL pool
// @param ctx    - request context for timeout propagation
// @param userID - UUID of the user who paid
// @param amount - amount in rubles
func OnPaymentSuccess(pool *pgxpool.Pool, ctx context.Context, userID string, amount float64) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1. Add to user's main balance.
	_, err = tx.Exec(ctx, `UPDATE users SET balance = balance + $1 WHERE id = $2`, amount, userID)
	if err != nil {
		return fmt.Errorf("update balance: %w", err)
	}

	// 2. Create topup transaction record.
	_, err = tx.Exec(ctx, `
		INSERT INTO transactions (id, "userId", type, amount, title, "createdAt")
		VALUES (gen_random_uuid(), $1, 'topup', $2, 'Пополнение через СБП', NOW())
	`, userID, amount)
	if err != nil {
		return fmt.Errorf("insert transaction: %w", err)
	}

	// 3. Award 20% referral commission if the user was referred.
	var referredByID *string
	row := tx.QueryRow(ctx, `SELECT "referredById" FROM users WHERE id = $1`, userID)
	if scanErr := row.Scan(&referredByID); scanErr == nil && referredByID != nil {
		commission := amount * 0.2
		_, err = tx.Exec(ctx, `UPDATE users SET "referralBalance" = "referralBalance" + $1 WHERE id = $2`, commission, *referredByID)
		if err != nil {
			return fmt.Errorf("update referral balance: %w", err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO transactions (id, "userId", type, amount, title, "createdAt")
			VALUES (gen_random_uuid(), $1, 'referral_earning', $2, 'Реферальное начисление', NOW())
		`, *referredByID, commission)
		if err != nil {
			return fmt.Errorf("insert referral tx: %w", err)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	log.Printf("[SBP] Payment success: userID=%s amount=%.2f", userID, amount)
	return nil
}

// OnPaymentSuccess is the method version for use from the api package.
//
// @param pool   - PostgreSQL pool
// @param ctx    - context
// @param userID - user UUID
// @param amount - rubles
func (c *Client) OnPaymentSuccess(pool *pgxpool.Pool, ctx context.Context, userID string, amount float64) error {
	return OnPaymentSuccess(pool, ctx, userID, amount)
}
