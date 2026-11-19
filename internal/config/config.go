package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	DataDir     string
	HTTPAddr    string
	SSHAddr     string
	ExternalURL string
	AdminUser   string
	AdminPass   string
	SessionDays int
}

func Load() (*Config, error) {
	c := &Config{
		DataDir:     getenv("GITELAB_DATA_DIR", "/data"),
		HTTPAddr:    getenv("GITELAB_HTTP_ADDR", ":3000"),
		SSHAddr:     getenv("GITELAB_SSH_ADDR", ":2222"),
		ExternalURL: getenv("GITELAB_EXTERNAL_URL", "http://localhost:3000"),
		AdminUser:   os.Getenv("GITELAB_ADMIN_USER"),
		AdminPass:   os.Getenv("GITELAB_ADMIN_PASSWORD"),
		SessionDays: 30,
	}
	if err := os.MkdirAll(c.ReposRoot(), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (c *Config) ReposRoot() string   { return filepath.Join(c.DataDir, "repos") }
func (c *Config) DBPath() string      { return filepath.Join(c.DataDir, "gitelab.db") }
func (c *Config) HostKeyPath() string { return filepath.Join(c.DataDir, "ssh_host_ed25519") }
