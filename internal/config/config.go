package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the agent configuration
type Config struct {
	// gRPC server settings
	GRPCPort int

	// TLS settings
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string

	// WireGuard settings
	WGConfigDir         string
	BackupDir           string
	AllowedInterfaces   []string
	BackupRetentionDays int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:            getEnvInt("AGENT_GRPC_PORT", 9090),
		TLSCertPath:         getEnv("AGENT_TLS_CERT", ""),
		TLSKeyPath:          getEnv("AGENT_TLS_KEY", ""),
		TLSCAPath:           getEnv("AGENT_TLS_CA", ""),
		WGConfigDir:         getEnv("AGENT_WG_CONFIG_DIR", "/etc/wireguard"),
		BackupDir:           getEnv("AGENT_BACKUP_DIR", "/var/lib/wg-agent/backups"),
		AllowedInterfaces:   getEnvList("AGENT_ALLOWED_INTERFACES", []string{}),
		BackupRetentionDays: getEnvInt("AGENT_BACKUP_RETENTION_DAYS", 7),
	}

	// Validate TLS configuration
	if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
		return nil, fmt.Errorf("AGENT_TLS_CERT and AGENT_TLS_KEY are required for mTLS")
	}

	if cfg.TLSCAPath == "" {
		return nil, fmt.Errorf("AGENT_TLS_CA is required for mTLS client verification")
	}

	// Validate paths exist
	if _, err := os.Stat(cfg.TLSCertPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("TLS cert file not found: %s", cfg.TLSCertPath)
	}
	if _, err := os.Stat(cfg.TLSKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("TLS key file not found: %s", cfg.TLSKeyPath)
	}
	if _, err := os.Stat(cfg.TLSCAPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("TLS CA file not found: %s", cfg.TLSCAPath)
	}
	if _, err := os.Stat(cfg.WGConfigDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("WireGuard config dir not found: %s", cfg.WGConfigDir)
	}

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(cfg.BackupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup dir: %w", err)
	}

	return cfg, nil
}

// IsInterfaceAllowed checks if an interface is in the allowed list.
// If the allowed list is empty, all interfaces are allowed.
func (c *Config) IsInterfaceAllowed(iface string) bool {
	if len(c.AllowedInterfaces) == 0 {
		return true
	}
	for _, allowed := range c.AllowedInterfaces {
		if allowed == iface {
			return true
		}
	}
	return false
}

// GetConfigPath returns the full path to a WireGuard config file
func (c *Config) GetConfigPath(iface string) string {
	return fmt.Sprintf("%s/%s.conf", c.WGConfigDir, iface)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvList(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}
	return defaultValue
}
