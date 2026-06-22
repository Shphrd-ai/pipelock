//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package entcli provides enterprise CLI commands (license, conductor, fleet).
// The init function registers these commands with the core CLI via the
// RegisterCommand hook so the Apache-only core remains free of enterprise
// imports.
package entcli

import (
	conductorcli "github.com/Shphrd-ai/pipelock/enterprise/cli/conductor"
	fleetcli "github.com/Shphrd-ai/pipelock/enterprise/cli/fleet"
	"github.com/Shphrd-ai/pipelock/internal/cli"
)

func init() {
	cli.RegisterCommand(LicenseCmd())
	cli.RegisterCommand(conductorcli.Cmd())
	cli.RegisterCommand(fleetcli.SinkCmd())
}
