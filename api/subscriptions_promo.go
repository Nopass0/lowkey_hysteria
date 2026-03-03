package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ─── Subscription plans ───────────────────────────────────────────────────────

type plan struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Prices    map[string]float64 `json:"prices"`
	Features  []string           `json:"features"`
	IsPopular bool               `json:"isPopular"`
}

var plans = []plan{
	{ID: "starter", Name: "Начальный",
		Prices:   map[string]float64{"monthly": 149, "3months": 129, "6months": 99, "yearly": 79},
		Features: []string{"1 устройство", "Базовая скорость", "Доступ к 5 локациям"},
	},
	{ID: "pro", Name: "Продвинутый", IsPopular: true,
		Prices:   map[string]float64{"monthly": 299, "3months": 249, "6months": 199, "yearly": 149},
		Features: []string{"3 устройства", "Высокая скорость", "Доступ ко всем локациям", "Kill Switch"},
	},
	{ID: "advanced", Name: "Максимальный",
		Prices:   map[string]float64{"monthly": 499, "3months": 399, "6months": 349, "yearly": 249},
		Features: []string{"5 устройств", "Максимальная скорость", "Доступ ко всем локациям", "Kill Switch", "Выделенный IP", "Приоритетная поддержка"},
	},
}

var periodDays = map[string]int{
	"monthly": 30, "3months": 90, "6months": 180, "yearly": 365,
}

// getPlans handles GET /api/subscriptions/plans (public).
//
// @route GET /api/subscriptions/plans
// @access public
func (h *handler) getPlans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plans)
}

// purchaseSubscription handles POST /api/subscriptions/purchase.
// Reads pendingDiscountPct / pendingDiscountFixed, applies and resets them
// atomically, deducts from balance, creates/updates subscription.
//
// @route POST /api/subscriptions/purchase
// @body  { "planId": string, "period": string }
// @access authenticated
func (h *handler) purchaseSubscription(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	var body struct {
		PlanID string `json:"planId"`
		Period string `json:"period"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	// Validate plan and period
	var p *plan
	for i := range plans {
		if plans[i].ID == body.PlanID {
			p = &plans[i]
			break
		}
	}
	if p == nil {
		writeJSON(w, http.StatusNotFound, errmsg("plan not found"))
		return
	}
	pricePerMonth, ok := p.Prices[body.Period]
	if !ok {
		writeJSON(w, http.StatusBadRequest, errmsg("invalid billing period"))
		return
	}
	days := periodDays[body.Period]

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Fetch user with discount fields
	var balance, discPct, discFixed float64
	var referredByID *string
	err := h.db.QueryRow(ctx, `
		SELECT balance, "pendingDiscountPct", "pendingDiscountFixed", "referredById"
		FROM users WHERE id = $1
	`, userID).Scan(&balance, &discPct, &discFixed, &referredByID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("user not found"))
		return
	}

	// Calculate price
	months := float64(days) / 30.0
	basePrice := pricePerMonth * months
	finalPrice := basePrice
	if discFixed > 0 {
		finalPrice = max64(0, finalPrice-discFixed)
	}
	if discPct > 0 {
		finalPrice *= 1 - discPct/100
	}
	if finalPrice < 1 {
		finalPrice = 1
	}
	finalPrice = float64(int(finalPrice*100+0.5)) / 100

	if balance < finalPrice {
		writeJSON(w, http.StatusPaymentRequired, errmsg("Insufficient balance"))
		return
	}

	activeUntil := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	periodLabel := map[string]string{
		"monthly": "1 мес.", "3months": "3 мес.", "6months": "6 мес.", "yearly": "1 год",
	}[body.Period]

	var discNoteParts []string
	if discPct > 0 {
		discNoteParts = append(discNoteParts, fmt.Sprintf("-%s%%", formatFloat(discPct)))
	}
	if discFixed > 0 {
		discNoteParts = append(discNoteParts, fmt.Sprintf("-%s₽", formatFloat(discFixed)))
	}
	discNote := ""
	if len(discNoteParts) > 0 {
		discNote = " (" + strings.Join(discNoteParts, ", ") + ")"
	}

	// Execute in transaction
	tx, err := h.db.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var newBalance float64
	err = tx.QueryRow(ctx, `
		UPDATE users SET balance=balance-$1,"pendingDiscountPct"=0,"pendingDiscountFixed"=0
		WHERE id=$2 RETURNING balance
	`, finalPrice, userID).Scan(&newBalance)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("balance update failed"))
		return
	}

	tx.Exec(ctx, `INSERT INTO transactions(id,"userId",type,amount,title,"createdAt") VALUES(gen_random_uuid(),$1,'subscription',$2,$3,NOW())`,
		userID, -finalPrice, `Подписка "`+p.Name+`" на `+periodLabel+discNote) //nolint:errcheck

	var subPlanID, subPlanName string
	var subUntil time.Time
	var subLifetime bool
	err = tx.QueryRow(ctx, `
		INSERT INTO subscriptions(id,"userId","planId","planName","activeUntil","isLifetime","createdAt","updatedAt")
		VALUES(gen_random_uuid(),$1,$2,$3,$4,false,NOW(),NOW())
		ON CONFLICT("userId") DO UPDATE SET "planId"=$2,"planName"=$3,"activeUntil"=$4,"updatedAt"=NOW()
		RETURNING "planId","planName","activeUntil","isLifetime"
	`, userID, p.ID, p.Name, activeUntil).Scan(&subPlanID, &subPlanName, &subUntil, &subLifetime)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("subscription upsert failed"))
		return
	}

	if referredByID != nil {
		commission := finalPrice * 0.2
		tx.Exec(ctx, `UPDATE users SET "referralBalance"="referralBalance"+$1 WHERE id=$2`, commission, *referredByID) //nolint:errcheck
		tx.Exec(ctx, `INSERT INTO transactions(id,"userId",type,amount,title,"createdAt") VALUES(gen_random_uuid(),$1,'referral_earning',$2,'Реферальное начисление',NOW())`, *referredByID, commission) //nolint:errcheck
	}

	if err = tx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("commit failed"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"subscription":    map[string]any{"planId": subPlanID, "planName": subPlanName, "activeUntil": subUntil.Format(time.RFC3339), "isLifetime": subLifetime},
		"newBalance":      newBalance,
		"originalPrice":   basePrice,
		"finalPrice":      finalPrice,
		"discountApplied": basePrice != finalPrice,
	})
}

// ─── Promo codes ──────────────────────────────────────────────────────────────

type promoEffect struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// activatePromo handles POST /api/user/promo/activate.
//
// @route POST /api/user/promo/activate
// @body  { "code": string }
// @access authenticated
func (h *handler) activatePromo(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	var body struct {
		Code string `json:"code"`
	}
	if !decodeBody(w, r, &body) || body.Code == "" {
		writeJSON(w, http.StatusBadRequest, errmsg("code is required"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var promoID string
	var maxActivations *int
	var effectsJSON []byte
	err := h.db.QueryRow(ctx, `
		SELECT id, "maxActivations", effects FROM promo_codes WHERE LOWER(code)=LOWER($1)
	`, body.Code).Scan(&promoID, &maxActivations, &effectsJSON)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("Промокод не найден"))
		return
	}

	var existing int
	h.db.QueryRow(ctx, `SELECT COUNT(*) FROM promo_activations WHERE "userId"=$1 AND "promoCodeId"=$2`, userID, promoID).Scan(&existing) //nolint:errcheck
	if existing > 0 {
		writeJSON(w, http.StatusConflict, errmsg("Вы уже активировали этот промокод"))
		return
	}

	if maxActivations != nil {
		var count int
		h.db.QueryRow(ctx, `SELECT COUNT(*) FROM promo_activations WHERE "promoCodeId"=$1`, promoID).Scan(&count) //nolint:errcheck
		if count >= *maxActivations {
			writeJSON(w, http.StatusUnprocessableEntity, errmsg("Лимит активаций исчерпан"))
			return
		}
	}

	var effects []promoEffect
	if err = json.Unmarshal(effectsJSON, &effects); err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("promo effects parse error"))
		return
	}

	tx, err := h.db.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tx.Exec(ctx, `INSERT INTO promo_activations(id,"userId","promoCodeId","activatedAt") VALUES(gen_random_uuid(),$1,$2,NOW())`, userID, promoID) //nolint:errcheck

	var descriptions []string
	for _, ef := range effects {
		desc := applyEffect(ctx, tx, userID, ef)
		if desc != "" {
			descriptions = append(descriptions, desc)
		}
	}

	var newBalance float64
	tx.QueryRow(ctx, `SELECT balance FROM users WHERE id=$1`, userID).Scan(&newBalance) //nolint:errcheck

	if err = tx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("commit failed"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":           true,
		"message":           "Промокод активирован",
		"rewardDescription": strings.Join(descriptions, ", "),
		"newBalance":        newBalance,
	})
}

// applyEffect применяет один эффект промокода внутри транзакции.
// Возвращает человекочитаемое описание применённого эффекта.
func applyEffect(ctx context.Context, tx pgx.Tx, userID string, ef promoEffect) string {
	switch ef.Key {
	case "add_balance":
		var amount float64
		n, _ := fmt.Sscanf(ef.Value, "%f", &amount)
		if n == 1 && amount > 0 {
			tx.Exec(ctx, `UPDATE users SET balance=balance+$1 WHERE id=$2`, amount, userID) //nolint:errcheck
			tx.Exec(ctx, `INSERT INTO transactions(id,"userId",type,amount,title,"createdAt") VALUES(gen_random_uuid(),$1,'promo_topup',$2,'Бонус по промокоду',NOW())`, userID, amount) //nolint:errcheck
			return "+" + formatFloat(amount) + " ₽ на баланс"
		}
	case "plan_discount_pct":
		var pct float64
		n, _ := fmt.Sscanf(ef.Value, "%f", &pct)
		if n == 1 && pct > 0 {
			tx.Exec(ctx, `UPDATE users SET "pendingDiscountPct"=GREATEST("pendingDiscountPct",$1) WHERE id=$2`, pct, userID) //nolint:errcheck
			return "Скидка " + formatFloat(pct) + "% на подписку"
		}
	case "plan_discount_fixed":
		var amount float64
		n, _ := fmt.Sscanf(ef.Value, "%f", &amount)
		if n == 1 && amount > 0 {
			tx.Exec(ctx, `UPDATE users SET "pendingDiscountFixed"="pendingDiscountFixed"+$1 WHERE id=$2`, amount, userID) //nolint:errcheck
			return "Скидка " + formatFloat(amount) + " ₽ на подписку"
		}
	case "free_days":
		var days int
		n, _ := fmt.Sscanf(ef.Value, "%d", &days)
		if n == 1 && days > 0 {
			activeUntil := time.Now().Add(time.Duration(days) * 24 * time.Hour)
			tx.Exec(ctx, `
				INSERT INTO subscriptions(id,"userId","planId","planName","activeUntil","isLifetime","createdAt","updatedAt")
				VALUES(gen_random_uuid(),$1,'starter','Начальный (пробный)',$2,false,NOW(),NOW())
				ON CONFLICT("userId") DO UPDATE
				  SET "activeUntil"=subscriptions."activeUntil"+($2-NOW()),"updatedAt"=NOW()
			`, userID, activeUntil) //nolint:errcheck
			return "+" + ef.Value + " дней подписки"
		}
	case "upgrade_plan":
		planID := ef.Value
		if planID == "" {
			planID = "pro"
		}
		planNames := map[string]string{"starter": "Начальный", "pro": "Продвинутый", "advanced": "Максимальный"}
		planName := planNames[planID]
		if planName == "" {
			planName = planID
		}
		tx.Exec(ctx, `UPDATE subscriptions SET "planId"=$1,"planName"=$2,"updatedAt"=NOW() WHERE "userId"=$3`, planID, planName, userID) //nolint:errcheck
		return `Апгрейд до "` + planName + `"`
	}
	return ""
}

// promoHistory handles GET /api/user/promo/history.
//
// @route GET /api/user/promo/history
// @access authenticated
func (h *handler) promoHistory(w http.ResponseWriter, r *http.Request) {
	userID   := getUserID(r)
	page     := queryInt(r, "page", 1)
	pageSize := queryInt(r, "pageSize", 10)
	skip     := (page - 1) * pageSize

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := h.db.Query(ctx, `
		SELECT pa.id, pc.code, pc.effects, pa."activatedAt"
		FROM promo_activations pa JOIN promo_codes pc ON pc.id=pa."promoCodeId"
		WHERE pa."userId"=$1 ORDER BY pa."activatedAt" DESC LIMIT $2 OFFSET $3
	`, userID, pageSize, skip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}
	defer rows.Close()

	type item struct {
		ID          string `json:"id"`
		Code        string `json:"code"`
		Description string `json:"description"`
		ActivatedAt string `json:"activatedAt"`
	}
	var items []item
	for rows.Next() {
		var it item
		var effectsJSON []byte
		var activatedAt time.Time
		if err = rows.Scan(&it.ID, &it.Code, &effectsJSON, &activatedAt); err != nil {
			continue
		}
		it.ActivatedAt = activatedAt.Format(time.RFC3339)
		var effects []promoEffect
		if json.Unmarshal(effectsJSON, &effects) == nil {
			var parts []string
			for _, e := range effects {
				switch e.Key {
				case "add_balance":
					parts = append(parts, "+"+e.Value+" ₽")
				case "free_days":
					parts = append(parts, "+"+e.Value+" дней")
				case "upgrade_plan":
					parts = append(parts, "Апгрейд: "+e.Value)
				case "plan_discount_pct":
					parts = append(parts, "Скидка "+e.Value+"%")
				case "plan_discount_fixed":
					parts = append(parts, "Скидка "+e.Value+" ₽")
				default:
					parts = append(parts, e.Key)
				}
			}
			it.Description = strings.Join(parts, ", ")
		}
		items = append(items, it)
	}

	var total int
	h.db.QueryRow(ctx, `SELECT COUNT(*) FROM promo_activations WHERE "userId"=$1`, userID).Scan(&total) //nolint:errcheck

	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total,
		"page": page, "pageSize": pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	})
}
