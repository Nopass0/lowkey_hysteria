// Package db provides shared VoidDB client initialisation and small helpers
// used by the Go VPN server.
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/config"
)

const (
	// DatabaseName is the shared VoidDB database used across site, bot, and
	// the Go VPN server.
	DatabaseName = "lowkey"
)

// ErrNotFound is returned when a query expecting one document yields none.
var ErrNotFound = errors.New("document not found")

// Client is the shared authenticated VoidDB client.
var Client *voidorm.Client

var initOnce sync.Once

// Init connects to VoidDB and keeps retrying until login succeeds.
func Init(cfg *config.Config) {
	for {
		client, err := voidorm.New(voidorm.Config{
			URL:   cfg.VoidDBURL,
			Token: cfg.VoidDBToken,
		})
		if err != nil {
			log.Printf("[VoidDB] Client init failed: %v, retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if cfg.VoidDBToken == "" {
			if _, err = client.Login(ctx, cfg.VoidDBUsername, cfg.VoidDBPassword); err != nil {
				cancel()
				log.Printf("[VoidDB] Login failed: %v, retrying in 5s...", err)
				time.Sleep(5 * time.Second)
				continue
			}
		}

		if _, err = client.ListDatabases(ctx); err != nil {
			cancel()
			log.Printf("[VoidDB] Connectivity check failed: %v, retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}
		cancel()

		Client = client
		log.Println("[VoidDB] Connected successfully")
		return
	}
}

// EnsureInit is a defensive wrapper for call sites that may be reached before
// main initialises the shared client in tests or alternate entrypoints.
func EnsureInit(cfg *config.Config) {
	initOnce.Do(func() {
		if Client == nil {
			Init(cfg)
		}
	})
}

// Collection returns a handle to one collection in the shared lowkey DB.
func Collection(name string) *voidorm.Collection {
	return Client.DB(DatabaseName).Collection(name)
}

// FindOne returns the first document matching q from collection name.
func FindOne(ctx context.Context, name string, q *voidorm.Query) (voidorm.Doc, error) {
	if q == nil {
		q = voidorm.NewQuery()
	}
	rows, err := Collection(name).Find(ctx, q.Limit(1))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return rows[0], nil
}

// FindByID loads a document by its _id.
func FindByID(ctx context.Context, name, id string) (voidorm.Doc, error) {
	doc, err := Collection(name).FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, voidorm.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return doc, nil
}

// FindMany runs a query against a collection.
func FindMany(ctx context.Context, name string, q *voidorm.Query) ([]voidorm.Doc, error) {
	if q == nil {
		q = voidorm.NewQuery()
	}
	return Collection(name).Find(ctx, q)
}

// CountMatching counts docs matching q.
func CountMatching(ctx context.Context, name string, q *voidorm.Query) (int64, error) {
	if q == nil {
		return Collection(name).Count(ctx)
	}
	return Collection(name).CountMatching(ctx, q)
}

// Insert creates a document and returns its generated _id.
func Insert(ctx context.Context, name string, doc voidorm.Doc) (string, error) {
	return Collection(name).Insert(ctx, doc)
}

// Patch updates a document by id and returns the new version.
func Patch(ctx context.Context, name, id string, patch voidorm.Doc) (voidorm.Doc, error) {
	return Collection(name).Patch(ctx, id, patch)
}

// Delete removes a document by id.
func Delete(ctx context.Context, name, id string) error {
	return Collection(name).Delete(ctx, id)
}

// QueryCount runs a paginated query and returns rows plus total count.
func QueryCount(ctx context.Context, name string, q *voidorm.Query) ([]voidorm.Doc, int64, error) {
	if q == nil {
		q = voidorm.NewQuery()
	}
	result, err := Collection(name).FindWithCount(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	return result.Docs, result.Count, nil
}

// AsString extracts a string field from a document.
func AsString(doc voidorm.Doc, key string) string {
	if doc == nil {
		return ""
	}
	value, ok := doc[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", value)
	}
}

// AsBool extracts a bool field from a document.
func AsBool(doc voidorm.Doc, key string) bool {
	if doc == nil {
		return false
	}
	value := doc[key]
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}

// AsFloat64 extracts a numeric field from a document.
func AsFloat64(doc voidorm.Doc, key string) float64 {
	if doc == nil {
		return 0
	}
	value := doc[key]
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		n, _ := v.Float64()
		return n
	case string:
		n, _ := strconv.ParseFloat(v, 64)
		return n
	default:
		return 0
	}
}

// AsInt extracts an integer field from a document.
func AsInt(doc voidorm.Doc, key string) int {
	return int(AsFloat64(doc, key))
}

// AsStringSlice extracts a string slice field from a document.
func AsStringSlice(doc voidorm.Doc, key string) []string {
	if doc == nil {
		return nil
	}
	value, ok := doc[key]
	if !ok || value == nil {
		return nil
	}
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, AsString(voidorm.Doc{"v": item}, "v"))
		}
		return out
	default:
		return nil
	}
}

// AsTime parses a datetime field from a document.
func AsTime(doc voidorm.Doc, key string) time.Time {
	raw := AsString(doc, key)
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

// UnmarshalField remaps a JSON-ish document field into dst.
func UnmarshalField(doc voidorm.Doc, key string, dst any) error {
	value, ok := doc[key]
	if !ok {
		return fmt.Errorf("field %q not found", key)
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}
