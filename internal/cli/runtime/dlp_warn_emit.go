// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"

	"github.com/Shphrd-ai/pipelock/internal/audit"
	"github.com/Shphrd-ai/pipelock/internal/config"
	"github.com/Shphrd-ai/pipelock/internal/metrics"
	"github.com/Shphrd-ai/pipelock/internal/receipt"
	"github.com/Shphrd-ai/pipelock/internal/scanner"
)

func emitDLPWarn(
	logger *audit.Logger,
	m *metrics.Metrics,
	receiptEmitter *receipt.Emitter,
	ctx context.Context,
	patternName, severity string,
) {
	wc := scanner.DLPWarnContextFromCtx(ctx)
	transport := wc.Transport
	if transport == "" {
		transport = transportUnknown
	}
	if m != nil {
		m.RecordDLPWarnMatch(patternName, transport)
	}

	lctx, lctxErr := dlpWarnLogContext(wc)
	if lctxErr != nil {
		lctx = dlpWarnFallbackLogContext(wc)
		logger.LogError(lctx, fmt.Errorf("build DLP warn audit context: %w", lctxErr))
	}

	if receiptEmitter != nil {
		if err := receiptEmitter.Emit(dlpWarnReceiptOpts(wc, patternName, severity, transport)); err != nil {
			logger.LogError(lctx, fmt.Errorf("emit DLP warn receipt: %w", err))
		}
	}

	logger.LogDLPWarn(lctx, patternName, severity, transport)
}

func dlpWarnReceiptOpts(
	wc scanner.DLPWarnContext,
	patternName, severity, transport string,
) receipt.EmitOpts {
	opts := receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionWarn,
		Layer:     scanner.ScannerDLP,
		Pattern:   patternName,
		Severity:  severity,
		Transport: transport,
		RequestID: wc.RequestID,
		Agent:     wc.Agent,
	}

	switch {
	case wc.Resource != "":
		opts.Target = wc.Resource
		opts.MCPMethod = wc.Resource
	case wc.URL != "":
		opts.Target = wc.URL
		opts.Method = wc.Method
	case wc.Target != "":
		opts.Target = wc.Target
		opts.Method = wc.Method
	default:
		opts.Target = transport
		opts.Method = wc.Method
	}

	return opts
}
