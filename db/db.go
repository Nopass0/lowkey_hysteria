// Package db provides initialisation helpers for PostgreSQL (pgxpool)
// and Redis client used by the hysteria server.
package db

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"hysteria_server/config"
)

// Pool is the shared PostgreSQL connection pool.
var Pool *pgxpool.Pool

// Redis is the shared Redis client.
var Redis *redis.Client

// InitDB connects to PostgreSQL and stores the pool in the package-level Pool
// variable. The function retries indefinitely until a connection is established.
//
// @param cfg - application configuration (DatabaseURL)
func InitDB(cfg *config.Config) {
	for {
		pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
		if err != nil {
			log.Printf("[DB] Failed to connect: %v — retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}
		// Verify the connection is live.
		if err = pool.Ping(context.Background()); err != nil {
			log.Printf("[DB] Ping failed: %v — retrying in 5s...", err)
			pool.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		Pool = pool
		log.Println("[DB] Connected to PostgreSQL ✓")
		return
	}
}

// InitRedis connects to Redis and stores the client in the package-level Redis
// variable. Exits with a fatal log if the URL cannot be parsed.
//
// @param cfg - application configuration (RedisURL)
func InitRedis(cfg *config.Config) {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("[Redis] Invalid REDIS_URL: %v", err)
	}
	Redis = redis.NewClient(opt)
	log.Println("[Redis] Connected ✓")
}
