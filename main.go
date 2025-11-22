package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	// Command options (the -h and --help flags are provided by default in the flag package)
	commandDescription      = "HTTP trace proxy server:\n  - Logs request/response details\n  - Forwards to origin specified via ?origin=<URL>\n  ALLOWED_ORIGINS env var can be used to set allowed origins."
	commandOptionFieldWidth = "12" // recommended width = general: 12, bool only: 5
	optionPort              = flag.String("p", "8888", "Listening port for the HTTP trace proxy")
	optionEnabledSingleLine = flag.Bool("s", false, "Log request in a single line (compresses newlines)")
	optionEnabledIgnoreBody = flag.Bool("i", false, "Skip logging body content")
	optionAllowedOrigins    = flag.String("a", "", "List of allowed origin URLs (e.g., https://aaa,http://bbb). Empty means all origins allowed.")
)

const maxBodySize = 10 << 20 // 10 MiB

func init() {
	// Time format = datetime + microsec, output file name: true
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// Format usage
	b := new(bytes.Buffer)
	func() { flag.CommandLine.SetOutput(b); flag.Usage(); flag.CommandLine.SetOutput(os.Stderr) }()
	usage := strings.Replace(strings.Replace(b.String(), ":", " [OPTIONS] [-h, --help]\n\nDescription:\n  "+commandDescription+"\n\nOptions:\n", 1), "Usage of", "Usage:", 1)
	re := regexp.MustCompile(`[^,] +(-\S+)(?: (\S+))?\n*(\s+)(.*)\n`)
	flag.Usage = func() {
		_, _ = fmt.Fprint(flag.CommandLine.Output(), re.ReplaceAllStringFunc(usage, func(m string) string {
			return fmt.Sprintf("  %-"+commandOptionFieldWidth+"s %s\n", re.FindStringSubmatch(m)[1]+" "+strings.TrimSpace(re.FindStringSubmatch(m)[2]), re.FindStringSubmatch(m)[4])
		}))
	}
}

// Build:
// $ go build -ldflags="-s -w" -trimpath -o /tmp/$(basename "$PWD") main.go
func main() {
	flag.Parse()
	fmt.Printf("[ Command options ]\n")
	flag.VisitAll(func(a *flag.Flag) {
		fmt.Printf("  -%-"+commandOptionFieldWidth+"s %s\n", fmt.Sprintf("%s %v", a.Name, a.Value), strings.Trim(a.Usage, "\n"))
	})
	fmt.Printf("\n")

	// Get allowed origins configuration
	allowedOrigins := getConfiguredAllowedOrigins()
	if allowedOrigins != "" {
		log.Printf("Allowed origins: %s", allowedOrigins)
	} else {
		log.Printf("Allowed origins: all (no restriction)")
	}

	// Start HTTP server
	// create and reuse a single ReverseProxy instance
	proxy := newProxy()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dumpRequest(r)

		// Get origin query parameter
		origin := r.URL.Query().Get("origin")
		if origin == "" {
			fmt.Fprintf(w, "OK\n")
			return
		}

		// Validate origin against allowed list
		if !isOriginAllowed(origin, allowedOrigins) {
			log.Printf("[WARN] origin not allowed: %s", origin)
			http.Error(w, "Forbidden: origin not allowed", http.StatusForbidden)
			return
		}

		// Let the shared proxy handle the request (Director will rewrite scheme/host)
		proxy.ServeHTTP(w, r)
	})

	log.Printf("Start http://localhost:" + *optionPort)
	if err := http.ListenAndServe(":"+*optionPort, nil); err != nil {
		handleError(err, "http.ListenAndServe", true)
	}
}

// newProxy creates and returns a configured ReverseProxy instance.
// The Director rewrites the request's scheme and host using the `origin` query param,
// while preserving the original path and query. ModifyResponse logs the response.
func newProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			orig := req.URL.Query().Get("origin")
			if orig == "" {
				return
			}
			uOrigin, err := url.Parse(orig)
			if err != nil {
				log.Printf("[ERROR] failed to parse origin URL in Director: %v", err)
				return
			}
			if uOrigin.Scheme == "" {
				uOrigin.Scheme = "http"
			}
			req.URL.Scheme = uOrigin.Scheme
			req.URL.Host = uOrigin.Host
			req.Host = uOrigin.Host

			// remove origin from query so backend doesn't see it
			q := req.URL.Query()
			q.Del("origin")
			req.URL.RawQuery = q.Encode()
		},
		ModifyResponse: func(resp *http.Response) error {
			dumpResponse(resp)
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Printf("[ERROR] reverse proxy error: %v", err)
			http.Error(rw, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

// Dump HTTP request
func dumpRequest(r *http.Request) {
	// Read and preserve body (nil-safe)
	bodyBytes, truncated, err := readAndCopyBody(r.Body)
	handleError(err, "read request body", false)
	if truncated {
		log.Printf("[WARN] request body truncated after %d bytes", maxBodySize)
	}
	// ensure r.Body is set to a fresh reader for DumpRequest
	if bodyBytes != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Dump using shared helper
	_, err = logDump(
		">>",
		func() ([]byte, error) { return httputil.DumpRequest(r, !*optionEnabledIgnoreBody) },
		"httputil.DumpRequest",
	)
	if err != nil {
		return
	}

	// restore for downstream
	if bodyBytes != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
}

// Dump HTTP response
func dumpResponse(r *http.Response) {
	bodyBytes, truncated, err := readAndCopyBody(r.Body)
	handleError(err, "read response body", false)
	if truncated {
		log.Printf("[WARN] response body truncated after %d bytes", maxBodySize)
	}
	if bodyBytes != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	_, err = logDump(
		"<<",
		func() ([]byte, error) { return httputil.DumpResponse(r, !*optionEnabledIgnoreBody) },
		"httputil.DumpResponse",
	)
	if err != nil {
		return
	}
	if bodyBytes != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
}

// logDump calls the provided dump function (e.g. httputil.DumpRequest/Response),
// logs the formatted output with the given prefix and returns the raw bytes.
func logDump(prefix string, dumpFunc func() ([]byte, error), errMsg string) ([]byte, error) {
	data, err := dumpFunc()
	if err != nil {
		handleError(err, errMsg, false)
		return nil, err
	}

	adjustMessage := func(message string) string {
		if *optionEnabledSingleLine {
			message = strings.ReplaceAll(message, "\r\n", ", ")
			message = strings.ReplaceAll(message, "\n", " ")
		} else {
			// Always add one blank line after the dump output for readability
			if !strings.HasSuffix(message, "\n") {
				message = message + "\n"
			}
			message = message + "\n"
		}
		return message
	}

	log.Printf("%s %s", prefix, adjustMessage(string(data)))
	return data, nil
}

// readAndCopyBody reads up to maxBodySize bytes from the provided ReadCloser,
// returns the bytes, a boolean indicating truncation, and an error.
// It does NOT close the provided ReadCloser; caller should handle closing if needed.
func readAndCopyBody(rc io.ReadCloser) (body []byte, truncated bool, err error) {
	if rc == nil {
		return nil, false, nil
	}
	limited := io.LimitReader(rc, maxBodySize+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > maxBodySize {
		return b[:maxBodySize], true, nil
	}
	return b, false, nil
}

// Handle error
func handleError(err error, prefixErrMessage string, exitOnError bool) {
	if err != nil {
		err = fmt.Errorf("[ERROR %s]: %v", prefixErrMessage, err)
		if exitOnError {
			log.Fatalf("%v\n", err)
		} else {
			log.Printf("%v\n", err)
		}
	}
}

// getConfiguredAllowedOrigins returns the allowed origins configuration
// from command-line flag or ALLOWED_ORIGINS environment variable
func getConfiguredAllowedOrigins() string {
	origins := *optionAllowedOrigins
	if origins == "" {
		origins = os.Getenv("ALLOWED_ORIGINS")
	}
	return origins
}

// isOriginAllowed checks if the given origin URL is allowed based on the configuration.
// If allowedList is empty, all origins are allowed.
// Performs prefix matching to support multiple origins with the same scheme and host.
// Examples: "https://example.com" matches "https://example.com:8080" and "https://example.com/path"
func isOriginAllowed(originURL string, allowedList string) bool {
	if allowedList == "" {
		return true // Empty list means all origins are allowed
	}

	// Trim whitespace from the origin URL
	originURL = strings.TrimSpace(originURL)

	// Check against each allowed origin (prefix matching)
	allowed := strings.Split(allowedList, ",")
	for _, allowedOrigin := range allowed {
		allowedOrigin = strings.TrimSpace(allowedOrigin)
		if allowedOrigin == "" {
			continue
		}

		// Prefix match: the originURL must start with the allowed origin
		if strings.HasPrefix(originURL, allowedOrigin) {
			return true
		}
	}

	return false
}
