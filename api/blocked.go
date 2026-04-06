package api

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

const blockedPageTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Доступ Ограничен | Lowkey</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #06111f;
      --bg-soft: rgba(8, 26, 49, 0.88);
      --line: rgba(123, 176, 255, 0.18);
      --text: #f4f8ff;
      --muted: #9db2cc;
      --accent: #4ea4ff;
      --accent-2: #9be15d;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
      background:
        radial-gradient(circle at 20%% 0%%, rgba(78,164,255,0.28), transparent 34%%),
        radial-gradient(circle at 100%% 100%%, rgba(155,225,93,0.16), transparent 28%%),
        linear-gradient(180deg, #04101c 0%%, var(--bg) 100%%);
      color: var(--text);
    }
    .card {
      width: min(760px, 100%%);
      border: 1px solid var(--line);
      border-radius: 28px;
      background: var(--bg-soft);
      padding: 36px;
      box-shadow: 0 22px 80px rgba(0,0,0,0.38);
      backdrop-filter: blur(18px);
    }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 14px;
      margin-bottom: 28px;
    }
    .logo {
      width: 52px;
      height: 52px;
      border-radius: 16px;
      background: linear-gradient(135deg, var(--accent), #2563eb);
      display: grid;
      place-items: center;
      box-shadow: 0 14px 30px rgba(37,99,235,0.35);
      font-weight: 800;
      font-size: 22px;
      letter-spacing: 0.08em;
    }
    .brand-name {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -0.04em;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(78,164,255,0.1);
      border: 1px solid rgba(78,164,255,0.16);
      color: #b9d9ff;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }
    h1 {
      margin: 20px 0 12px;
      font-size: clamp(34px, 6vw, 56px);
      line-height: 0.96;
      letter-spacing: -0.06em;
    }
    p {
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
      font-size: 16px;
    }
    .grid {
      display: grid;
      gap: 14px;
      margin-top: 28px;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 20px;
      background: rgba(255,255,255,0.03);
      padding: 18px 20px;
    }
    .label {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: #86a4c6;
      margin-bottom: 10px;
    }
    .value {
      font-size: 19px;
      font-weight: 700;
      word-break: break-word;
    }
    .reason {
      color: var(--accent-2);
      font-size: 18px;
      line-height: 1.6;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 28px;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 48px;
      padding: 0 18px;
      border-radius: 14px;
      text-decoration: none;
      font-weight: 700;
      transition: opacity .16s ease, transform .16s ease;
    }
    .btn:hover {
      opacity: 0.92;
      transform: translateY(-1px);
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent), #2563eb);
      color: #fff;
      box-shadow: 0 16px 36px rgba(37,99,235,0.32);
    }
    .btn-secondary {
      border: 1px solid var(--line);
      color: var(--text);
      background: rgba(255,255,255,0.03);
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand">
      <div class="logo">LK</div>
      <div class="brand-name">Lowkey</div>
    </div>
    <div class="eyebrow">Blocked Domain</div>
    <h1>Сайт временно недоступен</h1>
    <p>Домен попал в список ограничений этой VPN-ноды. Если доступ нужен, обратитесь в поддержку или администратору сети.</p>

    <section class="grid">
      <div class="panel">
        <div class="label">Домен</div>
        <div class="value">%s</div>
      </div>
      <div class="panel">
        <div class="label">Причина</div>
        <div class="reason">%s</div>
      </div>
    </section>

    <div class="actions">
      <a class="btn btn-primary" href="https://lowkey.su/">Открыть Lowkey</a>
      <a class="btn btn-secondary" href="javascript:history.back()">Назад</a>
    </div>
  </main>
</body>
</html>`

func (h *handler) blockedPage(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))

	if domain == "" {
		domain = "Домен не указан"
	}
	if reason == "" {
		reason = "Доступ к этому домену ограничен правилами Lowkey."
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(
		w,
		blockedPageTemplate,
		html.EscapeString(domain),
		html.EscapeString(reason),
	)
}
