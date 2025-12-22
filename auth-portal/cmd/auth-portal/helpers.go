package main

import (
	"os"

	"github.com/dzerik/auth-portal/internal/config"
)

// getEnv returns environment variable value or default.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvironment returns the environment name based on config.
func getEnvironment(cfg *config.Config) string {
	if cfg.DevMode.Enabled {
		return "development"
	}
	return "production"
}
