/*
 * Copyright (c) Sematext Group, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 */

package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/rabbitstack/gobpf/bcc"
)

const (
	httpGetSymbol    = "net/http.Get"
	uprobeHttpGet    = "__uprobe_http_get"
	uretprobeHttpGet = "__uretprobe_http_get"
)

const source string = `
#include <uapi/linux/ptrace.h>

#define SP_OFFSET(offset) (void *)PT_REGS_SP(ctx) + offset * 8

struct http_req {
	u32 pid;
	u64 delta;
	unsigned short len;
	char url[256];
}__attribute__((packed));

BPF_HASH(reqs, u32, struct http_req);
BPF_PERF_OUTPUT(output);

int __uprobe_http_get(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();
	struct http_req req = {
		.pid = pid,
		.delta = bpf_ktime_get_ns()
	};

    char *url;

    bpf_probe_read(&url, sizeof(url), SP_OFFSET(1));
    bpf_probe_read(&req.len, sizeof(req.len), SP_OFFSET(2));
    bpf_probe_read_str(&req.url, sizeof(req.url), (void *)url);

	reqs.update(&pid, &req);

    return 0;
}

int __uretprobe_http_get(struct pt_regs *ctx) {
    struct http_req *req;
    struct http_req req_copy = {};
    u32 pid = bpf_get_current_pid_tgid();

    req = reqs.lookup(&pid);

    if (req == 0)
        return 0;
    req_copy.delta = bpf_ktime_get_ns() - req->delta;
    req_copy.pid = pid;
    req_copy.len = req->len;

	bpf_probe_read(&req_copy.url, sizeof(req_copy.url), req->url);

    output.perf_submit(ctx, &req_copy, sizeof(req_copy));
    reqs.delete(&pid);

    return 0;
}
`

// UprobeHttpTracer deals with hooking and streaming of the events when stdlib HTTP functions are invoked.
type UprobeHttpTracer struct {
	mod *bpf.Module
}

type httpReq struct {
	Pid    uint32
	Delta  uint64
	Length uint16
	URL    [256]byte
}

type HttpReq struct {
	Pid   uint32
	Delta uint64
	URL   string
}

// NewUprobeHttpTracer produces a new instance of UprobeHttpTracer.
func NewUprobeHttpTracer() UprobeHttpTracer {
	return UprobeHttpTracer{
		mod: bpf.NewModule(source, []string{}),
	}
}

// Attach attaches uprobes on the http.Get symbol and pushes the result to the channel.
func (t *UprobeHttpTracer) Attach(name string) (chan HttpReq, error) {
	uprobe, err := t.mod.LoadUprobe(uprobeHttpGet)
	if err != nil {
		return nil, fmt.Errorf("couldn't load __uprobe_http_get: %v", err)
	}
	uretprobe, err := t.mod.LoadUprobe(uretprobeHttpGet)
	if err != nil {
		return nil, fmt.Errorf("couldn't load __uretprobe_http_get: %v", err)
	}
	if err = t.mod.AttachUprobe(name, httpGetSymbol, uprobe, -1); err != nil {
		return nil, fmt.Errorf("failed to attach __uprobe_http_get: %v", err)
	}
	if err = t.mod.AttachUretprobe(name, httpGetSymbol, uretprobe, -1); err != nil {
		return nil, fmt.Errorf("failed to attach __uretprobe_http_get: %v", err)
	}

	table := bpf.NewTable(t.mod.TableId("output"), t.mod)
	ch := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, ch)
	if err != nil {
		return nil, fmt.Errorf("couldn't init perfmap: %v", err)
	}

	reqc := make(chan HttpReq, 100)

	go func() {
		var req httpReq
		for {
			data := <-ch
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &req)
			if err != nil {
				return
			}
			reqc <- HttpReq{
				Pid:   req.Pid,
				Delta: req.Delta,
				URL:   string(req.URL[:])[0:req.Length],
			}
		}
	}()
	perfMap.Start()

	return reqc, nil
}

func (t *UprobeHttpTracer) Close() {
	t.mod.Close()
}
