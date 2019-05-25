package main

import (
	"os"

	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/buztard/kubectl-htpasswd/pkg/htpasswd"
)

func main() {
	cmd := htpasswd.NewCommand(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
