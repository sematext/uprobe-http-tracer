# uprobe-http-tracer

Captures all the calls to `http.Get` function and grabs the full URL from the stack area.

## Requirements

To build this tool you have to satisify the following requirements:
- have a modern Linux kernel (>4.12) that supports XDP
- linux headers
- clang
- LLVM
- libbcc
- Go >1.12

## Usage

First build the tool:

```
go build -o uprobe-http-tracer main.go
```

Write a simple program:

```
vi /tmp/main.go

package main

import "net/http"

func main() {
    urls := []string{"http://google.com", "http://reddit.com", "http://pastebin.com/tools"}
    for _, url := range urls {
       http.Get(url)
    }
}

go build /tmp/main.go
```

See it in action:

```
sudo ./uprobe-http-tracer --bin=/tmp/main
PID     URL
8274    http://google.com
8276    http://reddit.com
8286    http://pastebin.com/tools
```
