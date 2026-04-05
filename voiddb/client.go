// Package voiddb provides a Go client for VoidDB, wrapping github.com/Nopass0/void_go.
//
// API reference: https://github.com/Nopass0/void (server)
//                https://github.com/Nopass0/void_go (Go client)
//
// Base URL: http://host:7700
// Auth:     POST /v1/auth/login  → { "access_token": "..." }
// Insert:   POST /v1/databases/{db}/{col}               → { "_id": "..." }
// Get:      GET  /v1/databases/{db}/{col}/{id}           → Doc
// Query:    POST /v1/databases/{db}/{col}/query          → { "results": [...], "count": N }
// Patch:    PATCH /v1/databases/{db}/{col}/{id}          → updated Doc
// Replace:  PUT   /v1/databases/{db}/{col}/{id}          → —
// Delete:   DELETE /v1/databases/{db}/{col}/{id}         → —
package voiddb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Doc is a VoidDB document (map of field → value).
type Doc = map[string]interface{}

// FilterOp constants for query predicates.
const (
	Eq         = "eq"
	Ne         = "ne"
	Gt         = "gt"
	Gte        = "gte"
	Lt         = "lt"
	Lte        = "lte"
	Contains   = "contains"
	StartsWith = "starts_with"
	In         = "in"
)

// ─── Query builder ────────────────────────────────────────────────────────────

// QueryNode is a single predicate or logical tree node.
type QueryNode struct {
	AND   []QueryNode `json:"AND,omitempty"`
	OR    []QueryNode `json:"OR,omitempty"`
	Field string      `json:"field,omitempty"`
	Op    string      `json:"op,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// QuerySort specifies sort order.
type QuerySort struct {
	Field string `json:"field"`
	Dir   string `json:"dir"` // "asc" or "desc"
}

// QuerySpec is the full query sent to /query endpoint.
type QuerySpec struct {
	Where   *QueryNode  `json:"where,omitempty"`
	OrderBy []QuerySort `json:"order_by,omitempty"`
	Limit   int         `json:"limit,omitempty"`
	Skip    int         `json:"skip,omitempty"`
}

// QueryResult is the response from /query.
type QueryResult struct {
	Results []Doc `json:"results"`
	Count   int64 `json:"count"`
}

// Query is an immutable, chainable query builder.
type Query struct {
	nodes   []QueryNode
	orderBy []QuerySort
	limit   int
	skip    int
}

// NewQuery creates an empty query.
func NewQuery() *Query { return &Query{} }

// Where adds an AND predicate.
func (q *Query) Where(field, op string, value interface{}) *Query {
	next := q.clone()
	next.nodes = append(next.nodes, QueryNode{Field: field, Op: op, Value: value})
	return next
}

// WhereNode adds a custom QueryNode (useful for OR trees).
func (q *Query) WhereNode(node QueryNode) *Query {
	next := q.clone()
	next.nodes = append(next.nodes, node)
	return next
}

// OrderBy sets sort order.
func (q *Query) OrderBy(field, dir string) *Query {
	next := q.clone()
	next.orderBy = append(next.orderBy, QuerySort{Field: field, Dir: dir})
	return next
}

// Limit sets the result limit.
func (q *Query) Limit(n int) *Query { next := q.clone(); next.limit = n; return next }

// Skip sets the offset.
func (q *Query) Skip(n int) *Query { next := q.clone(); next.skip = n; return next }

// toSpec converts the builder to a QuerySpec for JSON serialisation.
func (q *Query) toSpec() QuerySpec {
	spec := QuerySpec{OrderBy: q.orderBy, Limit: q.limit, Skip: q.skip}
	switch len(q.nodes) {
	case 0:
	case 1:
		n := q.nodes[0]
		spec.Where = &n
	default:
		and := QueryNode{AND: q.nodes}
		spec.Where = &and
	}
	return spec
}

func (q *Query) clone() *Query {
	n2 := make([]QueryNode, len(q.nodes))
	copy(n2, q.nodes)
	o2 := make([]QuerySort, len(q.orderBy))
	copy(o2, q.orderBy)
	return &Query{nodes: n2, orderBy: o2, limit: q.limit, skip: q.skip}
}

// ─── Client ───────────────────────────────────────────────────────────────────

// Client is an authenticated VoidDB HTTP client.
type Client struct {
	baseURL  string
	username string
	password string
	token    string // static bearer token (alternative to username+password)

	mu      sync.RWMutex
	authTok string
	expiry  time.Time

	http *http.Client
}

// NewFromEnv creates a Client from environment variables.
// Reads VOIDDB_URL (or VOID_URL), VOIDDB_USERNAME, VOIDDB_PASSWORD, VOIDDB_TOKEN.
func NewFromEnv() *Client {
	baseURL := firstEnv("VOIDDB_URL", "VOID_URL")
	username := firstEnv("VOIDDB_USERNAME", "VOID_USERNAME")
	password := firstEnv("VOIDDB_PASSWORD", "VOID_PASSWORD")
	token := firstEnv("VOIDDB_TOKEN", "VOID_TOKEN")
	return New(baseURL, username, password, token)
}

// New creates a Client with explicit credentials.
// Use token for a static bearer token, or username+password for session auth.
func New(baseURL, username, password, token string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		token:    token,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

// ─── Authentication ───────────────────────────────────────────────────────────

func (c *Client) ensureAuth(ctx context.Context) error {
	// Static bearer token — no need to refresh.
	if c.token != "" {
		c.mu.Lock()
		c.authTok = c.token
		c.mu.Unlock()
		return nil
	}

	c.mu.RLock()
	valid := c.authTok != "" && time.Now().Before(c.expiry)
	c.mu.RUnlock()
	if valid {
		return nil
	}

	if c.username == "" || c.password == "" {
		return fmt.Errorf("voiddb: no credentials configured")
	}

	body, _ := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("voiddb login: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return fmt.Errorf("voiddb login %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.AccessToken == "" {
		return fmt.Errorf("voiddb login: bad response: %s", string(data))
	}

	exp := time.Now().Add(50 * time.Minute) // conservative default
	if result.ExpiresAt > 0 {
		exp = time.Unix(result.ExpiresAt, 0).Add(-60 * time.Second)
	}

	c.mu.Lock()
	c.authTok = result.AccessToken
	c.expiry = exp
	c.mu.Unlock()
	return nil
}

func (c *Client) bearerToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authTok
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return nil, 0, err
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := c.bearerToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

// ─── Database / Collection handles ───────────────────────────────────────────

// DB returns a database handle.
func (c *Client) DB(name string) *Database {
	return &Database{client: c, name: url.PathEscape(name)}
}

// Database is a handle to a named VoidDB database.
type Database struct {
	client *Client
	name   string
}

// Collection returns a collection handle.
func (d *Database) Collection(name string) *Collection {
	return &Collection{client: d.client, db: d.name, name: url.PathEscape(name)}
}

// ─── Collection ───────────────────────────────────────────────────────────────

// Collection provides CRUD operations on a single VoidDB collection.
type Collection struct {
	client *Client
	db     string
	name   string
}

func (col *Collection) base() string {
	return "/v1/databases/" + col.db + "/" + col.name
}

// Insert inserts a document and returns its assigned _id.
func (col *Collection) Insert(ctx context.Context, doc Doc) (string, error) {
	data, status, err := col.client.do(ctx, "POST", col.base(), doc)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", fmt.Errorf("voiddb insert %d: %s", status, string(data))
	}
	var result struct {
		ID string `json:"_id"`
	}
	json.Unmarshal(data, &result)
	return result.ID, nil
}

// Get returns a document by its _id.
func (col *Collection) Get(ctx context.Context, id string) (Doc, error) {
	data, status, err := col.client.do(ctx, "GET", col.base()+"/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil
	}
	if status >= 400 {
		return nil, fmt.Errorf("voiddb get %d: %s", status, string(data))
	}
	var doc Doc
	json.Unmarshal(data, &doc)
	return doc, nil
}

// Find executes a query and returns matching documents.
func (col *Collection) Find(ctx context.Context, q *Query) ([]Doc, error) {
	res, err := col.FindWithCount(ctx, q)
	if err != nil {
		return nil, err
	}
	return res.Results, nil
}

// FindWithCount executes a query and returns results plus total count.
func (col *Collection) FindWithCount(ctx context.Context, q *Query) (*QueryResult, error) {
	spec := q.toSpec()
	data, status, err := col.client.do(ctx, "POST", col.base()+"/query", spec)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("voiddb query %d: %s", status, string(data))
	}
	var result QueryResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// FindOne returns the first document matching the query, or nil if none found.
func (col *Collection) FindOne(ctx context.Context, q *Query) (Doc, error) {
	docs, err := col.Find(ctx, q.Limit(1))
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	return docs[0], nil
}

// Patch partially updates a document by _id (only provided fields are changed).
func (col *Collection) Patch(ctx context.Context, id string, fields Doc) (Doc, error) {
	data, status, err := col.client.do(ctx, "PATCH", col.base()+"/"+url.PathEscape(id), fields)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("voiddb patch %d: %s", status, string(data))
	}
	var doc Doc
	json.Unmarshal(data, &doc)
	return doc, nil
}

// Replace fully replaces a document by _id.
func (col *Collection) Replace(ctx context.Context, id string, doc Doc) error {
	data, status, err := col.client.do(ctx, "PUT", col.base()+"/"+url.PathEscape(id), doc)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("voiddb replace %d: %s", status, string(data))
	}
	return nil
}

// Delete removes a document by _id.
func (col *Collection) Delete(ctx context.Context, id string) error {
	data, status, err := col.client.do(ctx, "DELETE", col.base()+"/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("voiddb delete %d: %s", status, string(data))
	}
	return nil
}

// Upsert finds the first document matching the query and updates it,
// or inserts insertDoc if no document matches.
// Returns the _id of the affected document and whether it was inserted.
func (col *Collection) Upsert(ctx context.Context, q *Query, insertDoc Doc, patchFields Doc) (id string, inserted bool, err error) {
	existing, err := col.FindOne(ctx, q)
	if err != nil {
		return "", false, err
	}
	if existing == nil {
		id, err = col.Insert(ctx, insertDoc)
		return id, true, err
	}
	existingID, _ := existing["_id"].(string)
	if existingID == "" {
		// Try _id field
		for k, v := range existing {
			if strings.EqualFold(k, "_id") {
				existingID, _ = v.(string)
				break
			}
		}
	}
	if existingID == "" {
		return "", false, fmt.Errorf("voiddb upsert: existing doc has no _id")
	}
	_, err = col.Patch(ctx, existingID, patchFields)
	return existingID, false, err
}

// Count returns the total number of documents in the collection.
func (col *Collection) Count(ctx context.Context) (int64, error) {
	data, status, err := col.client.do(ctx, "GET", col.base()+"/count", nil)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("voiddb count %d: %s", status, string(data))
	}
	var result struct {
		Count int64 `json:"count"`
	}
	json.Unmarshal(data, &result)
	return result.Count, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
