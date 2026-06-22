//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"github.com/Shphrd-ai/pipelock/enterprise"
	_ "github.com/Shphrd-ai/pipelock/enterprise/cli"
	"github.com/Shphrd-ai/pipelock/internal/config"
	"github.com/Shphrd-ai/pipelock/internal/edition"
)

func init() {
	edition.NewEditionFunc = enterprise.NewEdition
	config.ValidateAgentsFunc = enterprise.ValidateAgents
	config.EnforceLicenseGateFunc = enterprise.EnforceLicenseGate
	config.MergeAgentProfileFunc = enterprise.MergeAgentProfile
}
