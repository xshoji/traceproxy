# traceproxy

A lightweight HTTP proxy server that intercepts, logs, and forwards HTTP requests to a target origin. Perfect for debugging API calls, analyzing HTTP traffic, and understanding client-server communication.

## Features

- 🔍 **Request/Response Logging**: Captures and logs complete HTTP request and response details
- 🎯 **Dynamic Routing**: Route requests to any origin via query parameter
- 📝 **Flexible Output**: Single-line or multi-line log formats
- ⚡ **Lightweight**: Minimal overhead, built with Go's standard library
- 🛡️ **Body Size Limit**: Automatically truncates large bodies (10 MiB limit) to prevent memory issues

## Installation

### Build from Source

```bash
git clone https://github.com/xshoji/traceproxy.git
cd traceproxy
go build -ldflags="-s -w" -trimpath -o traceproxy main.go
```

## Usage

### Basic Usage

Start the proxy server:

```bash
./traceproxy
```

By default, the server listens on port `8888`.

### Making Requests Through the Proxy

Send requests to the proxy with the `origin` query parameter specifying your target URL:

```bash
# Example: Proxy request to httpbin.org
curl "http://localhost:8888/get?origin=https://httpbin.org"

# Example: Proxy POST request with body
curl -X POST "http://localhost:8888/post?origin=https://httpbin.org" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'

# Example: Proxy to a local service
curl "http://localhost:8888/api/users?origin=http://localhost:3000"
```

### Command Options

```
Usage: traceproxy [OPTIONS] [-h, --help]

Description:
  HTTP trace proxy server:
  - Logs request/response details
  - Forwards to origin specified via ?origin=<URL>

Options:
  -p <port>      Listening port for the HTTP trace proxy (default: 8888)
  -s             Log request in a single line (compresses newlines)
  -i             Skip logging body content
```

### Examples

**1. Change listening port:**
```bash
./traceproxy -p 9000
```

**2. Single-line log format (useful for grep/parsing):**
```bash
./traceproxy -s
```

**3. Ignore body content (headers only):**
```bash
./traceproxy -i
```

**4. Combine options:**
```bash
./traceproxy -p 9000 -s -i
```

## How It Works

1. **Start the proxy**: The server starts and listens on the specified port
2. **Send request**: Client sends a request to `http://localhost:8888/path?origin=<target-url>`
3. **Log request**: The proxy logs the incoming request details
4. **Forward**: Request is forwarded to the target origin (with `origin` param removed)
5. **Log response**: The proxy logs the response from the target
6. **Return**: Response is sent back to the client

## Use Cases

- **API Development**: Debug API calls and inspect payloads
- **Reverse Engineering**: Analyze HTTP communication patterns
- **Testing**: Validate request/response formats
- **Learning**: Understand HTTP protocol mechanics
- **Troubleshooting**: Diagnose integration issues between services

## Log Output Format

### Multi-line format (default):
```
>> GET /api/users HTTP/1.1
Host: example.com
User-Agent: curl/7.79.1
...

<< HTTP/1.1 200 OK
Content-Type: application/json
...
```

### Single-line format (`-s` flag):
```
>> GET /api/users HTTP/1.1, Host: example.com, User-Agent: curl/7.79.1, ...
<< HTTP/1.1 200 OK, Content-Type: application/json, ...
```

## Configuration

- **Max Body Size**: 10 MiB (hardcoded in `maxBodySize`)
- Bodies exceeding this limit are truncated with a warning log

## Requirements

- Go 1.16 or higher

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
