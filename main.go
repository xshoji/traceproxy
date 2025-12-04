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
	"path/filepath"
	"strings"
)

var (
	commandDescription      = "HTTP trace proxy server:\n  - Logs request/response details\n  - Forwards to origin specified via ?origin=<URL>\n  ALLOWED_ORIGINS env var can be used to set allowed origins."
	commandOptionFieldWidth = "12" // Recommended width = general: 12, bool only: 5
	// Command options (the -h and --help flags are provided by default in the flag package)
	optionPort              = defineFlagValue("p", "Listening port for the HTTP trace proxy", 8888, flag.Int)
	optionEnabledSingleLine = defineFlagValue("s", "Log request in a single line (compresses newlines)", false, flag.Bool)
	optionEnabledIgnoreBody = defineFlagValue("i", "Skip logging body content", false, flag.Bool)
	optionAllowedOrigins    = defineFlagValue("a", "List of allowed origin URLs (e.g., https://aaa,http://bbb). Empty means all origins allowed", "", flag.String)

	// Pre-parsed allowed origin URLs for validation
	allowedOriginURLs []*url.URL
)

const maxBodySize = 10 << 20 // 10 MiB

func init() {
	// Time format = datetime + microsec, output file name: true
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// Set custom usage
	flag.Usage = customUsage(os.Stderr, commandDescription, commandOptionFieldWidth)
}

// Build:
// $ go build -ldflags="-s -w" -trimpath -o /tmp/$(basename "$PWD") main.go
func main() {
	flag.Parse()
	fmt.Printf("[ Command options ]\n")
	printOptionsUsage(commandOptionFieldWidth, true)
	fmt.Println()

	// Get allowed origins configuration
	allowedOrigins := getConfiguredAllowedOrigins()
	if allowedOrigins != "" {
		allowedOriginURLs = parseAllowedOrigins(allowedOrigins)
		log.Printf("Allowed origins:\n")
		for i, u := range allowedOriginURLs {
			log.Printf("%d. Scheme:%s, Host:%s\n", i, u.Scheme, u.Host)
		}
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
		if !isOriginAllowed(origin, allowedOriginURLs) {
			log.Printf("[WARN] origin not allowed: %s", origin)
			http.Error(w, "Forbidden: origin not allowed", http.StatusForbidden)
			return
		}

		// Let the shared proxy handle the request (Director will rewrite scheme/host)
		proxy.ServeHTTP(w, r)
	})

	portString := fmt.Sprintf("%d", *optionPort)
	log.Printf("Start http://localhost:" + portString)
	if err := http.ListenAndServe(":"+portString, nil); err != nil {
		handleError(err, "http.ListenAndServe", true)
	}
}

// newProxy creates and returns a configured ReverseProxy instance.
// The Director rewrites the request's scheme and host using the `origin` query param,
// while preserving the original path and query. ModifyResponse logs the response.
func newProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originUrl := req.URL.Query().Get("origin")
			if originUrl == "" {
				return
			}
			uOrigin, err := parseURLWithDefault(originUrl, "https")
			if err != nil {
				log.Printf("[ERROR] failed to parse origin URL in Director: %v", err)
				return
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

// parseURLWithDefault parses a URL string and, if the parsed URL has no Scheme and
// defaultScheme is non-empty, sets the Scheme to defaultScheme. Returns the parsed
// *url.URL or an error.
func parseURLWithDefault(s string, defaultScheme string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" && defaultScheme != "" {
		u.Scheme = defaultScheme
	}
	return u, nil
}

// parseAllowedOrigins parses the allowed origins string into a slice of URL objects.
// Exits fatally if any origin cannot be parsed.
func parseAllowedOrigins(allowedList string) []*url.URL {
	var urls []*url.URL
	allowed := strings.Split(allowedList, ",")
	for _, ao := range allowed {
		ao = strings.TrimSpace(ao)
		if ao == "" {
			continue
		}
		u, err := url.Parse(ao)
		if err != nil {
			log.Fatalf("failed to parse allowed origin: %s", ao)
		}
		urls = append(urls, u)
	}
	return urls
}

// isOriginAllowed checks if the given origin URL is allowed based on the pre-parsed allowed URLs.
// If allowedURLs is empty, all origins are allowed.
// Parses the origin URL and compares Scheme and Host with allowed URLs.
// If an allowed URL has no Scheme, allows both http and https for that Host.
func isOriginAllowed(originURL string, allowedURLs []*url.URL) bool {
	if len(allowedURLs) == 0 {
		return true // Empty list means all origins are allowed
	}

	// Parse origin URL
	originParsed, err := parseURLWithDefault(originURL, "https")
	if err != nil {
		log.Fatalf("failed to parse origin URL: %v", err)
	}
	originScheme := originParsed.Scheme
	originHost := originParsed.Host

	// Check against each allowed URL
	for _, allowed := range allowedURLs {
		allowedScheme := allowed.Scheme
		allowedHost := allowed.Host

		if allowedScheme == "" {
			// No scheme specified: allow all schemes
			if originHost == allowedHost {
				return true
			}
		} else {
			// Scheme specified: must match exactly
			if originScheme == allowedScheme && originHost == allowedHost {
				return true
			}
		}
	}

	return false
}

// =======================================
// flag Utils
// =======================================

// Helper function for flag
func defineFlagValue[T comparable](flagName, description string, defaultValue T, flagFunc func(name string, value T, usage string) *T) *T {
	var zero T
	if defaultValue != zero {
		description = description + fmt.Sprintf(" (default %v)", defaultValue)
	}
	return flagFunc(flagName, defaultValue, description)
}

// Custom usage message
func customUsage(output io.Writer, description, fieldWidth string) func() {
	return func() {
		fmt.Fprintf(output, "Usage: %s [OPTIONS]\n\n", func() string { e, _ := os.Executable(); return filepath.Base(e) }())
		fmt.Fprintf(output, "Description:\n  %s\n\n", description)
		fmt.Fprintf(output, "Options:\n")
		printOptionsUsage(fieldWidth, false)
	}
}

// Print options usage message
func printOptionsUsage(fieldWidth string, currentValue bool) {
	flag.VisitAll(func(f *flag.Flag) {
		value := strings.NewReplacer("*flag.boolValue", "", "*flag.", "<", "Value", ">").Replace(fmt.Sprintf("%T", f.Value))
		if currentValue {
			value = f.Value.String()
		}
		format := "  -%-" + fieldWidth + "s %s\n"
		fmt.Printf(format, f.Name+" "+value, f.Usage)
	})
}
