package main

import (
	"os"

	"github.com/PQCA/pqnext-cbomkit-deployment/internal/control"
)

func main() {
	os.Exit(control.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
