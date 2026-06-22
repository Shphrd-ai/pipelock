//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package testinit activates enterprise edition hooks for package-level tests.
// Import with blank identifier in build-tagged test files:
//
//	//go:build enterprise
//	package foo
//	import _ "github.com/Shphrd-ai/pipelock/enterprise/testinit"
package testinit

import (
	"github.com/Shphrd-ai/pipelock/enterprise"
	"github.com/Shphrd-ai/pipelock/internal/config"
	"github.com/Shphrd-ai/pipelock/internal/edition"
)

func init() {
	edition.NewEditionFunc = enterprise.NewEdition
	config.ValidateAgentsFunc = enterprise.ValidateAgents
	config.EnforceLicenseGateFunc = enterprise.EnforceLicenseGate
	config.MergeAgentProfileFunc = enterprise.MergeAgentProfile
}
