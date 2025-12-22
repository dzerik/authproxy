package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dzerik/auth-portal/internal/help"
	"github.com/dzerik/auth-portal/internal/schema"
)

// cliOptions holds parsed CLI options.
type cliOptions struct {
	configPath    string
	generateNginx bool
	nginxOutput   string
	devMode       bool
	showVersion   bool
	showHelp      bool
	genSchema     bool
	schemaOutput  string
}

// parseFlags parses CLI flags and returns options.
func parseFlags() *cliOptions {
	opts := &cliOptions{}

	flag.StringVar(&opts.configPath, "config", getEnv("AUTH_PORTAL_CONFIG", "/etc/auth-portal/config.yaml"), "Path to configuration file")
	flag.BoolVar(&opts.generateNginx, "generate-nginx", false, "Generate nginx config and exit")
	flag.StringVar(&opts.nginxOutput, "output", getEnv("AUTH_PORTAL_NGINX_CONFIG", "/etc/nginx/nginx.conf"), "Output path for nginx config")
	flag.BoolVar(&opts.devMode, "dev", false, "Enable development mode")
	flag.BoolVar(&opts.showVersion, "version", false, "Show version and exit")
	flag.BoolVar(&opts.showHelp, "help", false, "Show extended help")
	flag.BoolVar(&opts.genSchema, "schema", false, "Generate JSON schema and exit")
	flag.StringVar(&opts.schemaOutput, "schema-output", "", "Output file for schema (default: stdout)")
	flag.Parse()

	return opts
}

// handleInfoCommands handles --version, --help, --schema flags.
// Returns true if command was handled and program should exit.
func handleInfoCommands(opts *cliOptions) bool {
	helpGen := help.NewGenerator(help.AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal with Keycloak OIDC integration",
		Version:     Version,
		BuildTime:   BuildTime,
		DocsURL:     "https://github.com/dzerik/auth-portal",
	}, "AUTH_PORTAL")

	if opts.showVersion {
		fmt.Print(helpGen.PrintVersion())
		return true
	}

	if opts.showHelp {
		fmt.Print(helpGen.PrintExtendedHelp())
		return true
	}

	if opts.genSchema {
		handleSchemaGeneration(opts.schemaOutput)
		return true
	}

	return false
}

// handleSchemaGeneration generates JSON schema and exits.
func handleSchemaGeneration(outputPath string) {
	gen := schema.NewGenerator()
	data, err := gen.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate schema: %v\n", err)
		os.Exit(1)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write schema: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Schema written to %s\n", outputPath)
	} else {
		fmt.Println(string(data))
	}
}
