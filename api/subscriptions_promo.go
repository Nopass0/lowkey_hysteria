package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

type plan struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Prices    map[string]float64 `json:"prices"`
	Features  []string           `json:"features"`
	IsPopular bool               `json:"isPopular"`
}

var plans = []plan{
	{ID: "starter", Name: "Начальный", Prices: map[string]float64{"monthly": 149, "3months": 129, "6months": 99, "yearly": 79}, Features: []string{"1 устройство", "Базовая скорость", "Доступ к 5 локациям"}},
	{ID: "pro", Name: "Продвинутый", IsPopular: true, Prices: map[string]float64{"monthly": 299, "3months": 249, "6months": 199, "yearly": 149}, Features: []string{"3 устройства", "Высокая скорость", "Доступ ко всем локациям", "Kill Switch"}},
	{ID: "advanced", Name: "Максимальный", Prices: map[string]float64{"monthly": 499, "3months": 399, "6months": 349, "yearly": 249}, Features: []string{"5 устройств", "Максимальная скорость", "Доступ ко всем локациям", "Kill Switch", "Выделенный IP", "Приоритетная поддержка"}},
}

var periodDays = map[string]int{
	"monthly": 30,
	"3months": 90,
	"6months": 180,
	"yearly":  365,
}

func (h *handler) getPlans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plans)
}

func (h *handler) purchaseSubscription(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	var body struct {
		PlanID string `json:"planId"`
		Period string `json:"period"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	var selected *plan
	for i := range plans {
		if plans[i].ID == body.PlanID {
			selected = &plans[i]
			break
		}
	}
	if selected == nil {
		writeJSON(w, http.StatusNotFound, errmsg("plan not found"))
		return
	}

	pricePerMonth, ok := selected.Prices[body.Period]
	if !ok {
		writeJSON(w, http.StatusBadRequest, errmsg("invalid billing period"))
		return
	}

	days := periodDays[body.Period]
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	userDoc, err := db.FindByID(ctx, "users", userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errmsg("user not found"))
		return
	}

	balance := db.AsFloat64(userDoc, "balance")
	discPct := db.AsFloat64(userDoc, "pendingDiscountPct")
	discFixed := db.AsFloat64(userDoc, "pendingDiscountFixed")
	referredByID := db.AsString(userDoc, "referredById")

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

	newBalance := balance - finalPrice
	activeUntil := time.Now().Add(time.Duration(days) * 24 * time.Hour).UTC()

	if _, err = db.Patch(ctx, "users", userID, voidorm.Doc{
		"balance":              newBalance,
		"pendingDiscountPct":   0.0,
		"pendingDiscountFixed": 0.0,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("balance update failed"))
		return
	}

	periodLabel := map[string]string{
		"monthly": "1 мес.",
		"3months": "3 мес.",
		"6months": "6 мес.",
		"yearly":  "1 год",
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

	_, _ = db.Insert(ctx, "transactions", voidorm.Doc{
		"userId":    userID,
		"type":      "subscription",
		"amount":    -finalPrice,
		"title":     `Подписка "` + selected.Name + `" на ` + periodLabel + discNote,
		"createdAt": time.Now().UTC(),
	})

	subscription, subErr := db.FindOne(ctx, "subscriptions", voidorm.NewQuery().Where("userId", voidorm.Eq, userID))
	if subErr == nil {
		_, err = db.Patch(ctx, "subscriptions", db.AsString(subscription, "_id"), voidorm.Doc{
			"planId":      selected.ID,
			"planName":    selected.Name,
			"activeUntil": activeUntil,
			"isLifetime":  false,
			"updatedAt":   time.Now().UTC(),
		})
	} else {
		_, err = db.Insert(ctx, "subscriptions", voidorm.Doc{
			"userId":      userID,
			"planId":      selected.ID,
			"planName":    selected.Name,
			"activeUntil": activeUntil,
			"isLifetime":  false,
			"createdAt":   time.Now().UTC(),
			"updatedAt":   time.Now().UTC(),
		})
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("subscription upsert failed"))
		return
	}

	if referredByID != "" {
		refDoc, refErr := db.FindByID(ctx, "users", referredByID)
		if refErr == nil {
			commission := finalPrice * 0.2
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

	writeJSON(w, http.StatusOK, map[string]any{
		"subscription": map[string]any{
			"planId":      selected.ID,
			"planName":    selected.Name,
			"activeUntil": activeUntil.Format(time.RFC3339),
			"isLifetime":  false,
		},
		"newBalance":      newBalance,
		"originalPrice":   basePrice,
		"finalPrice":      finalPrice,
		"discountApplied": basePrice != finalPrice,
	})
}

type promoEffect struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

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

	promoRows, err := db.FindMany(ctx, "promo_codes", voidorm.NewQuery().Limit(250))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}

	var promoDoc voidorm.Doc
	for _, row := range promoRows {
		if strings.EqualFold(db.AsString(row, "code"), body.Code) {
			promoDoc = row
			break
		}
	}
	if promoDoc == nil {
		writeJSON(w, http.StatusNotFound, errmsg("Промокод не найден"))
		return
	}

	promoID := db.AsString(promoDoc, "_id")
	existing, _ := db.CountMatching(
		ctx,
		"promo_activations",
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			Where("promoCodeId", voidorm.Eq, promoID),
	)
	if existing > 0 {
		writeJSON(w, http.StatusConflict, errmsg("Вы уже активировали этот промокод"))
		return
	}

	maxActivations := db.AsInt(promoDoc, "maxActivations")
	if maxActivations > 0 {
		total, _ := db.CountMatching(ctx, "promo_activations", voidorm.NewQuery().Where("promoCodeId", voidorm.Eq, promoID))
		if total >= int64(maxActivations) {
			writeJSON(w, http.StatusUnprocessableEntity, errmsg("Лимит активаций исчерпан"))
			return
		}
	}

	var effects []promoEffect
	if err = db.UnmarshalField(promoDoc, "effects", &effects); err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("promo effects parse error"))
		return
	}

	if _, err = db.Insert(ctx, "promo_activations", voidorm.Doc{
		"userId":      userID,
		"promoCodeId": promoID,
		"activatedAt": time.Now().UTC(),
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("activation failed"))
		return
	}

	var descriptions []string
	for _, ef := range effects {
		if desc := applyEffect(ctx, userID, ef); desc != "" {
			descriptions = append(descriptions, desc)
		}
	}

	userDoc, _ := db.FindByID(ctx, "users", userID)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":           true,
		"message":           "Промокод активирован",
		"rewardDescription": strings.Join(descriptions, ", "),
		"newBalance":        db.AsFloat64(userDoc, "balance"),
	})
}

func applyEffect(ctx context.Context, userID string, ef promoEffect) string {
	userDoc, err := db.FindByID(ctx, "users", userID)
	if err != nil {
		return ""
	}

	switch ef.Key {
	case "add_balance":
		var amount float64
		if _, err := fmt.Sscanf(ef.Value, "%f", &amount); err == nil && amount > 0 {
			_, _ = db.Patch(ctx, "users", userID, voidorm.Doc{
				"balance": db.AsFloat64(userDoc, "balance") + amount,
			})
			_, _ = db.Insert(ctx, "transactions", voidorm.Doc{
				"userId":    userID,
				"type":      "promo_topup",
				"amount":    amount,
				"title":     "Бонус по промокоду",
				"createdAt": time.Now().UTC(),
			})
			return "+" + formatFloat(amount) + " ₽ на баланс"
		}
	case "plan_discount_pct":
		var pct float64
		if _, err := fmt.Sscanf(ef.Value, "%f", &pct); err == nil && pct > 0 {
			current := db.AsFloat64(userDoc, "pendingDiscountPct")
			if pct < current {
				pct = current
			}
			_, _ = db.Patch(ctx, "users", userID, voidorm.Doc{"pendingDiscountPct": pct})
			return "Скидка " + formatFloat(pct) + "% на подписку"
		}
	case "plan_discount_fixed":
		var amount float64
		if _, err := fmt.Sscanf(ef.Value, "%f", &amount); err == nil && amount > 0 {
			_, _ = db.Patch(ctx, "users", userID, voidorm.Doc{
				"pendingDiscountFixed": db.AsFloat64(userDoc, "pendingDiscountFixed") + amount,
			})
			return "Скидка " + formatFloat(amount) + " ₽ на подписку"
		}
	case "free_days":
		var days int
		if _, err := fmt.Sscanf(ef.Value, "%d", &days); err == nil && days > 0 {
			subDoc, subErr := db.FindOne(ctx, "subscriptions", voidorm.NewQuery().Where("userId", voidorm.Eq, userID))
			base := time.Now().UTC()
			if subErr == nil {
				currentUntil := db.AsTime(subDoc, "activeUntil")
				if currentUntil.After(base) {
					base = currentUntil
				}
				_, _ = db.Patch(ctx, "subscriptions", db.AsString(subDoc, "_id"), voidorm.Doc{
					"activeUntil": base.Add(time.Duration(days) * 24 * time.Hour),
					"updatedAt":   time.Now().UTC(),
				})
			} else {
				_, _ = db.Insert(ctx, "subscriptions", voidorm.Doc{
					"userId":      userID,
					"planId":      "starter",
					"planName":    "Начальный (пробный)",
					"activeUntil": base.Add(time.Duration(days) * 24 * time.Hour),
					"isLifetime":  false,
					"createdAt":   time.Now().UTC(),
					"updatedAt":   time.Now().UTC(),
				})
			}
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
		subDoc, subErr := db.FindOne(ctx, "subscriptions", voidorm.NewQuery().Where("userId", voidorm.Eq, userID))
		if subErr == nil {
			_, _ = db.Patch(ctx, "subscriptions", db.AsString(subDoc, "_id"), voidorm.Doc{
				"planId":    planID,
				"planName":  planName,
				"updatedAt": time.Now().UTC(),
			})
			return `Апгрейд до "` + planName + `"`
		}
	}
	return ""
}

func (h *handler) promoHistory(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "pageSize", 10)
	skip := (page - 1) * pageSize

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, total, err := db.QueryCount(
		ctx,
		"promo_activations",
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			OrderBy("activatedAt", voidorm.Desc).
			Skip(skip).
			Limit(pageSize),
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}

	type item struct {
		ID          string `json:"id"`
		Code        string `json:"code"`
		Description string `json:"description"`
		ActivatedAt string `json:"activatedAt"`
	}

	items := make([]item, 0, len(rows))
	for _, row := range rows {
		it := item{
			ID:          db.AsString(row, "_id"),
			ActivatedAt: db.AsTime(row, "activatedAt").Format(time.RFC3339),
		}

		promoID := db.AsString(row, "promoCodeId")
		promoDoc, promoErr := db.FindByID(ctx, "promo_codes", promoID)
		if promoErr == nil {
			it.Code = db.AsString(promoDoc, "code")
			var effects []promoEffect
			if db.UnmarshalField(promoDoc, "effects", &effects) == nil {
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
		}

		items = append(items, it)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}
