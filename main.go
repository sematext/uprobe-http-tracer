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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
	t "uprobe/tracer"
)

var bin string

func main() {
	flag.StringVar(&bin, "bin", "", "full path of the target binary")
	flag.Parse()
	if bin == "" {
		panic("bin parameter must be provided")
	}
	tracer := t.NewUprobeHttpTracer()
	ch, err := tracer.Attach(bin)
	if err != nil {
		panic(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	fmt.Printf("%s\t\t%s\t%s\n", "PID", "DURATION", "URL")
	for {
		select {
		case req := <-ch:
			fmt.Printf("%d\t\t%s\t%s\n", req.Pid, time.Duration(req.Delta), req.URL)
		case <-sig:
			tracer.Close()
			return
		}
	}
}

