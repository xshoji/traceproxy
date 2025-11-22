# traceproxy

A lightweight HTTP proxy server that intercepts, logs, and forwards HTTP requests to a target origin. Perfect for debugging API calls and analyzing HTTP traffic.

## Features

- 🔍 Request/Response logging
- 🎯 Dynamic routing via query parameter
- 🔒 Origin restriction with prefix matching
- 📝 Flexible log output formats
- ⚡ Minimal overhead, built with Go's standard library

## Installation

```bash
git clone https://github.com/xshoji/traceproxy.git
cd traceproxy
go build -ldflags="-s -w" -trimpath -o $(basename "$PWD") main.go
```

## Quick Start

```bash
# Start the proxy on port 8888
./traceproxy

# Proxy a request to an origin
curl "http://localhost:8888/get?origin=https://httpbin.org"
```

## Command Options

```
Usage: ./traceproxy [OPTIONS]

Options:
  -p string   Listening port (default "8888")
  -s          Single-line log format
  -i          Skip logging body content
  -a string   Allowed origin URLs (comma-separated, e.g., https://example.com)
              Uses prefix matching. Empty = allow all origins.
              Falls back to ALLOWED_ORIGINS env var
```

## Examples

```bash
# Change port
./traceproxy -p 9000

# Single-line logs + ignore body
./traceproxy -s -i

# Restrict origins
./traceproxy -a "https://httpbin.org,https://example.com"

# Via environment variable
export ALLOWED_ORIGINS="https://httpbin.org"
./traceproxy
```

## How It Works

1. Client sends: `GET /path?origin=https://example.com`
2. Proxy logs the request
3. Proxy forwards to `https://example.com/path`
4. Proxy logs the response
5. Response sent back to client

## Requirements

- Go 1.16 or higher

## License

See [LICENSE](LICENSE) file for details.
