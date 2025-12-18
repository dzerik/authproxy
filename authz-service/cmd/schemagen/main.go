// Package main provides a standalone tool to generate JSON Schemas.
//
// This tool is kept for backward compatibility. The preferred way is:
//
//	authz --schema config > configs/config.schema.json
//	authz --schema rules > configs/rules.schema.json
//
// Usage:
//
//	go run ./cmd/schemagen [config|rules]
//
// Examples:
//
//	go run ./cmd/schemagen config > configs/config.schema.json
//	go run ./cmd/schemagen rules > configs/rules.schema.json
package main

import (
	"fmt"
	"os"

	"github.com/your-org/authz-service/internal/schema"
)

func main() {
	schemaType := "config" // default
	if len(os.Args) > 1 {
		schemaType = os.Args[1]
	}

	st, ok := schema.ParseSchemaType(schemaType)
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown schema type: %s\n", schemaType)
		fmt.Fprintf(os.Stderr, "Available types: config, rules\n")
		os.Exit(1)
	}

	gen := schema.NewGenerator()
	data, err := gen.Generate(st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}
