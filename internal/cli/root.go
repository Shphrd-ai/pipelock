// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the Pipelock command-line interface using cobra.
// Subpackages contain the actual command implementations; this package
// wires them into the root command.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/Shphrd-ai/pipelock/internal/cli/assess"
	"github.com/Shphrd-ai/pipelock/internal/cli/audit"
	"github.com/Shphrd-ai/pipelock/internal/cli/canary"
	"github.com/Shphrd-ai/pipelock/internal/cli/contain"
	"github.com/Shphrd-ai/pipelock/internal/cli/diag"
	clienvelope "github.com/Shphrd-ai/pipelock/internal/cli/envelope"
	"github.com/Shphrd-ai/pipelock/internal/cli/generate"
	"github.com/Shphrd-ai/pipelock/internal/cli/git"
	"github.com/Shphrd-ai/pipelock/internal/cli/hermes"
	"github.com/Shphrd-ai/pipelock/internal/cli/keys"
	"github.com/Shphrd-ai/pipelock/internal/cli/learn"
	"github.com/Shphrd-ai/pipelock/internal/cli/policy"
	"github.com/Shphrd-ai/pipelock/internal/cli/rules"
	"github.com/Shphrd-ai/pipelock/internal/cli/runtime"
	"github.com/Shphrd-ai/pipelock/internal/cli/scan"
	"github.com/Shphrd-ai/pipelock/internal/cli/selfupdate"
	"github.com/Shphrd-ai/pipelock/internal/cli/session"
	"github.com/Shphrd-ai/pipelock/internal/cli/setup"
	clisigning "github.com/Shphrd-ai/pipelock/internal/cli/signing"
	"github.com/Shphrd-ai/pipelock/internal/cli/support"
	"github.com/Shphrd-ai/pipelock/internal/cliutil"
	"github.com/Shphrd-ai/pipelock/internal/proxy"
)

// extraCommands holds commands registered by enterprise packages via init().
var extraCommands []*cobra.Command

// RegisterCommand adds a subcommand to the root command. Called by enterprise
// CLI packages during init() to register license management commands.
func RegisterCommand(cmd *cobra.Command) {
	extraCommands = append(extraCommands, cmd)
}

// Execute runs the root command.
func Execute() error {
	proxy.Version = cliutil.Version // sync so /health reports the same version as CLI
	return rootCmd().Execute()
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pipelock",
		Short: "Open-source firewall for AI agents",
		Long: `Pipelock is an application-layer firewall that controls what your AI agent
can access on the network, preventing credential exfiltration while preserving
web browsing capability.

Three modes:
  strict    - Agent can only reach allowlisted API domains (airtight)
  balanced  - Capability separation with monitored web browsing (default)
  audit     - Log everything, restrict nothing (evaluation)

Quick start:
  pipelock run
  pipelock run --config pipelock.yaml
  pipelock check --config pipelock.yaml`,
		Version:       cliutil.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(&cliutil.PipelockHome, "home", "",
		"pipelock home directory (default ~/.pipelock, or set PIPELOCK_HOME)")

	cmd.AddCommand(
		// Assess
		assess.Cmd(),
		// Policy capture/replay
		policy.Cmd(),
		// Posture capsules
		postureCmd(),
		// Audit & reporting
		audit.Cmd(),
		// Canary tokens
		canary.Cmd(),
		audit.ReportCmd(),
		audit.SimulateCmd(),
		// Containment (workstation-tier)
		contain.Cmd(),
		// Mediation envelope trust management
		clienvelope.Cmd(),
		// Diagnostics
		diag.DoctorCmd(),
		diag.DiagnoseCmd(),
		diag.DiscoverCmd(),
		diag.PreflightCmd(),
		diag.CheckCmd(),
		diag.VerifyInstallCmd(),
		diag.TestCmd(),
		diag.DemoCmd(),
		diag.LogsCmd(),
		support.Cmd(),
		// Generate
		generate.Cmd(),
		// Git
		git.Cmd(),
		// Hermes Agent (Nous Research) integration
		hermes.Cmd(),
		// Signing-key inventory
		keys.Cmd(),
		// Learn-and-lock observation pipeline
		learn.Cmd(),
		// Rules
		rules.Cmd(),
		// Runtime
		runtime.RunCmd(),
		runtime.McpCmd(),
		runtime.SandboxCmd(),
		runtime.InternalRedirectCmd(),
		runtime.HealthcheckCmd(),
		// File injection scanning (invisible-Unicode / bidi)
		scan.Cmd(),
		skillScanCmd(),
		// Session admin (airlock recovery)
		session.AdaptiveCmd(),
		session.BaselineCmd(),
		session.Cmd(),
		// Setup (IDE integrations)
		setup.InitCmd(),
		setup.ClaudeCmd(),
		setup.ClineCmd(),
		setup.CursorCmd(),
		setup.VscodeCmd(),
		setup.JetbrainsCmd(),
		setup.CodexCmd(),
		setup.OpenCodeCmd(),
		setup.ZedCmd(),
		// Signing & integrity
		clisigning.IntegrityCmd(),
		clisigning.SignCmd(),
		clisigning.VerifyCmd(),
		clisigning.KeygenCmd(),
		clisigning.TrustCmd(),
		clisigning.TlsCmd(),
		clisigning.VerifyReceiptCmd(),
		clisigning.TranscriptRootCmd(),
		clisigning.SigningSubtreeCmd(),
		// Explain a URL verdict with per-scanner remediation.
		explainCmd(),
		// Binary install helper for sidecar init containers.
		installCmd(),
		// Self-update (verified release install)
		selfupdate.Cmd(),
		// Version
		versionCmd(),
	)

	// Enterprise packages register extra commands via RegisterCommand().
	for _, extra := range extraCommands {
		cmd.AddCommand(extra)
	}

	return cmd
}
