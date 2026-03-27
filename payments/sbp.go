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

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

const tochkaBaseURL = "https://enter.tochka.com/uapi/sbp/v1.0"

type Client struct {
	apiKey     string
	merchantID string
	accountID  string
	http       *http.Client
}

func NewClient(apiKey, merchantID, accountID string) *Client {
	return &Client{
		apiKey:     apiKey,
		merchantID: merchantID,
		accountID:  accountID,
		http:       &http.Client{Timeout: 15 * time.Second},
	}
}

type CreateQRRequest struct {
	Amount      int    `json:"amount"`
	Currency    string `json:"currency"`
	Description string `json:"description"`
	MerchantID  string `json:"merchantId"`
	AccountID   string `json:"accountId"`
}

type CreateQRResponse struct {
	QrcID   string `json:"qrcId"`
	Payload string `json:"payload"`
}

type PaymentStatusResponse struct {
	OperationStatus string `json:"operationStatus"`
	Amount          int    `json:"amount"`
}

func (c *Client) CreateSBP(amountRUB float64, description string) (string, string, error) {
	reqBody := CreateQRRequest{
		Amount:      int(amountRUB * 100),
		Currency:    "RUB",
		Description: description,
		MerchantID:  c.merchantID,
		AccountID:   c.accountID,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tochkaBaseURL+"/qr-codes", bytes.NewReader(body))
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

func (c *Client) GetPaymentStatus(qrcID string) (*PaymentStatusResponse, error) {
	url := fmt.Sprintf("%s/qr-codes/%s/payment-status", tochkaBaseURL, qrcID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
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

func OnPaymentSuccess(ctx context.Context, userID string, amount float64) error {
	userDoc, err := db.FindByID(ctx, "users", userID)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}

	if _, err = db.Patch(ctx, "users", userID, voidorm.Doc{
		"balance": db.AsFloat64(userDoc, "balance") + amount,
	}); err != nil {
		return fmt.Errorf("update balance: %w", err)
	}

	if _, err = db.Insert(ctx, "transactions", voidorm.Doc{
		"userId":    userID,
		"type":      "topup",
		"amount":    amount,
		"title":     "Пополнение через СБП",
		"createdAt": time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("insert transaction: %w", err)
	}

	referredByID := db.AsString(userDoc, "referredById")
	if referredByID != "" {
		refDoc, refErr := db.FindByID(ctx, "users", referredByID)
		if refErr == nil {
			commission := amount * 0.2
			_, _ = db.Patch(ctx, "users", referredByID, voidorm.Doc{
				"referralBalance": db.AsFloat64(refDoc, "referralBalance") + commission,
			})
			_, _ = db.Insert(ctx, "transactions", voidorm.Doc{
				"userId":    referredByID,
				"type":      "referral_earning",
				"amount":    commission,
				"title":     "Реферальное начисление",
				"createdAt": time.Now().UTC(),
			})
		}
	}

	log.Printf("[SBP] Payment success: userID=%s amount=%.2f", userID, amount)
	return nil
}

func (c *Client) OnPaymentSuccess(ctx context.Context, userID string, amount float64) error {
	return OnPaymentSuccess(ctx, userID, amount)
}
