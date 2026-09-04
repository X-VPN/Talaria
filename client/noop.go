// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import "context"

type noopEventSink struct{}

func (noopEventSink) OnStateChange(context.Context, State)                      {}
func (noopEventSink) OnConnectStage(context.Context, string, map[string]string) {}
func (noopEventSink) OnError(context.Context, error)                            {}

type noopStatsSink struct{}

func (noopStatsSink) OnUploadBytes(context.Context, int)   {}
func (noopStatsSink) OnDownloadBytes(context.Context, int) {}
func (noopStatsSink) OnTunRead(context.Context, int)       {}
func (noopStatsSink) OnTunWrite(context.Context, int)      {}
