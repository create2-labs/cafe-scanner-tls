package config

const (
	// Zerolog values from [trace, debug, info, warn, error, fatal, panic].
	LogLevel = "LOG_LEVEL"

	ServerHost = "SERVER_HOST"
	ServerPort = "SERVER_PORT"

	// Scanner health check configuration
	ScannerHealthPort = "SCANNER_HEALTH_PORT"

	// PostgreSQL configuration
	PostgreSQLHost = "POSTGRES_HOST"
	PostgreSQLPort = "POSTGRES_PORT"
	PostgreSQLUser = "POSTGRES_USER"
	// #nosec G101 -- This is a configuration key name, not a hardcoded credential
	PostgreSQLPassword = "POSTGRES_PASSWORD"
	PostgreSQLDatabase = "POSTGRES_DATABASE"
	PostgreSQLSSLMode  = "POSTGRES_SSLMODE"

	// NATS configuration
	NATSURL = "NATS_URL"

	// Redis configuration
	RedisURL = "REDIS_URL"

	// Boolean; used to register commands at development guild level or globally.
	Production = "PRODUCTION"

	// CORS configuration
	CORSAllowOrigins = "CORS_ALLOW_ORIGINS"
	CORSAllowMethods = "CORS_ALLOW_METHODS"

	// Cloudflare Turnstile configuration
	TurnstileSecretKey = "TURNSTILE_SECRET_KEY"
	TurnstileSiteKey   = "TURNSTILE_SITE_KEY"

	// JWT configuration
	// #nosec G101 -- This is a configuration key name, not a hardcoded credential
	JWTSecret = "JWT_SECRET"

	// Scan plugin version (config file: scan.plugins.tls.version)
	ScanPluginsTLSVersion = "scan.plugins.tls.version"

	defaultProduction         = true
	defaultPostgreSQLHost     = "127.0.0.1"
	defaultPostgreSQLPort     = "5432"
	defaultPostgreSQLUser     = "cafe"
	defaultPostgreSQLPassword = "cafe"
	defaultPostgreSQLDatabase = "cafe"
	defaultPostgreSQLSSLMode  = "disable"
	defaultNATSURL            = "nats://localhost:4222"
	defaultRedisURL           = "redis://localhost:6379"
	defaultServerHost         = "0.0.0.0"
	defaultServerPort         = "8080"
	defaultScannerHealthPort  = "8081"
	defaultCORSAllowOrigins   = "http://localhost:3000,http://localhost:3001,http://localhost:5173"
	defaultCORSAllowMethods   = "GET,POST,PUT,DELETE,OPTIONS"
	// Cloudflare Turnstile development keys (always pass verification)
	// These are free test keys provided by Cloudflare for development
	defaultTurnstileSecretKey = "1x0000000000000000000000000000000AA"
	defaultTurnstileSiteKey   = "1x00000000000000000000AA"
	defaultScanPluginVersion  = "1.0"
)

func GetDefaultConfigValues() map[string]any {
	return map[string]any{
		PostgreSQLHost:        defaultPostgreSQLHost,
		PostgreSQLPort:        defaultPostgreSQLPort,
		PostgreSQLUser:        defaultPostgreSQLUser,
		PostgreSQLPassword:    defaultPostgreSQLPassword,
		PostgreSQLDatabase:    defaultPostgreSQLDatabase,
		PostgreSQLSSLMode:     defaultPostgreSQLSSLMode,
		NATSURL:               defaultNATSURL,
		RedisURL:              defaultRedisURL,
		Production:            defaultProduction,
		ServerHost:            defaultServerHost,
		ServerPort:            defaultServerPort,
		ScannerHealthPort:     defaultScannerHealthPort,
		CORSAllowOrigins:      defaultCORSAllowOrigins,
		CORSAllowMethods:      defaultCORSAllowMethods,
		TurnstileSecretKey:    defaultTurnstileSecretKey,
		TurnstileSiteKey:      defaultTurnstileSiteKey,
		ScanPluginsTLSVersion: defaultScanPluginVersion,
	}
}
