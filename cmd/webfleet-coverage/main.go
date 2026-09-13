package main

import (
	"fmt"
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/webfleet-cv/webfleet/internal/operations"
	"os"
)

func main() {
	if err := os.MkdirAll("docs/generated", 0755); err != nil {
		panic(err)
	}
	if err := contracttest.WriteMatrixArtifacts("docs/generated/functional-coverage.json", "docs/generated/functional-coverage.md", operations.Manifest()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
