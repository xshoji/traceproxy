# traceproxy

A lightweight HTTP proxy server that intercepts, logs, and forwards HTTP requests to a target origin. Perfect for debugging API calls and analyzing HTTP traffic.

```
+--------+     +------------+     +--------+
| Client | --> | traceproxy | --> | Origin |
|        | <-- |            | <-- |        |
+--------+     +------------+     +--------+
                | Logs     | 
                | Req/Resp | 
                +----------+ 
```

## Features

- 🔍 Request/Response logging
- 🎯 Dynamic routing via query parameter or Host header
- 🌐 .localhost domain support for easy local testing
- 🔒 Origin restriction with prefix matching
- 📝 Flexible log output formats
- 🗜️ Optional compression control for readable response bodies
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

# Method 1: Proxy via query parameter
curl "http://localhost:8888/get?origin=https://httpbin.org"

# Method 2: Proxy via .localhost domain (removes .localhost suffix)
curl "http://httpbin.org.localhost:8888/get"
```

## Command Options

```plaintext
Usage: traceproxy [OPTIONS]

Description:
  HTTP trace proxy server:
  - Logs request/response details
  - Forwards to origin specified via ?origin=<URL> or Host header ending with .localhost
  - Example: Access http://example.com.localhost:8888/path to proxy to https://example.com/path
  ALLOWED_ORIGINS env var can be used to set allowed origins.

Options:
  -a <string>   List of allowed origin URLs (e.g., https://aaa,http://bbb). Empty means all origins allowed
  -d            Disable compression by overriding Accept-Encoding to identity
  -i            Skip logging body content
  -p <int>      Listening port for the HTTP trace proxy (default 8888)
  -s            Log request in a single line (compresses newlines)
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

# Disable compression for readable response bodies
./traceproxy -d

# Using .localhost domain for easy testing
curl "http://api.example.com.localhost:8888/users"
# This proxies to: https://api.example.com/users

# Access with custom headers
curl -H "Authorization: Bearer token" "http://httpbin.org.localhost:8888/headers"
```

## How It Works

### Method 1: Query Parameter
1. Client sends: `GET /path?origin=https://example.com`
2. Proxy logs the request
3. Proxy forwards to `https://example.com/path`
4. Proxy logs the response
5. Response sent back to client

### Method 2: .localhost Domain
1. Client sends: `GET http://example.com.localhost:8888/path`
2. Proxy extracts `example.com` from the Host header (removes `.localhost`)
3. Proxy logs the request
4. Proxy forwards to `https://example.com/path` (default scheme: https)
5. Proxy logs the response
6. Response sent back to client

> **Note**: The `.localhost` domain method is particularly useful for:
> - Testing with real domain names locally
> - Avoiding CORS issues during development
> - Simulating production domains without modifying /etc/hosts

## Compression Control

By default, the proxy preserves the client's `Accept-Encoding` header, allowing the origin server to return compressed responses (gzip, deflate, etc.). However, compressed responses may be difficult to read in logs.

Use the `-d` flag to disable compression:

```bash
# Force uncompressed responses for readable logging
./traceproxy -d
```

This overrides the `Accept-Encoding` header to `identity`, ensuring the origin server returns uncompressed content that can be easily inspected in the logs.

## Requirements

- Go 1.16 or higher

## License

See [LICENSE](LICENSE) file for details.
