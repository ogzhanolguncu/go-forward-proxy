package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// TODOS
// # PROXY SERVER TODO LIST
//
// ## 🔧 Improvements (Good to Have)
//
// ### 4. **Security Enhancements**
// - [ ] Add rate limiting per client IP
// - [ ] Validate request sizes (prevent DoS)
// - [ ] Add request timeout limits
// - [ ] Consider adding authentication
// - [ ] Add IP whitelisting/blacklisting
//
// ### 5. **Performance Optimizations**
// - [ ] Add connection pooling for upstream requests
// - [ ] Implement caching for frequently accessed content
// - [ ] Add concurrent limits to prevent resource exhaustion
//
// ### 6. **Better Logging**
// - [ ] Add configurable log levels (DEBUG, INFO, WARN, ERROR)
// - [ ] Implement log rotation to prevent disk filling
// - [ ] Add metrics/statistics logging
// - [ ] Add structured logging (JSON format option)
//
// ### 7. **Configuration Management**
// - [ ] Make server address configurable via flags/env vars
// - [ ] Make timeouts configurable
// - [ ] Add hot-reload for forbidden lists
// - [ ] Add configuration file support (YAML/JSON)
//
// ### 8. **Error Handling Improvements**
// - [ ] Add better client error messages
// - [ ] Implement graceful degradation for file access issues
// - [ ] Add health check endpoint (`/health`, `/status`)
// - [ ] Add proper HTTP status codes for different error types
//
// **Phase 4 (Polish - Do Eventually):**
// 7. Configuration management
// 8. Error handling improvements
// 9. Code quality improvements
//

var (
	forbiddenHostNames map[string]bool = make(map[string]bool)
	forbiddenWords     map[string]bool = make(map[string]bool)
)

const (
	proxyRequestLimit = 64 * 1024 // 64KB
	proxyHeaderLimit  = 8 * 1024  // 8KB

	forbiddenHostsFileName = "forbidden-hosts.txt"
	forbiddenWordsFileName = "banned-words.txt"
)

func forwardProxy(w http.ResponseWriter, originalReq *http.Request) {
	originalReq.Body = http.MaxBytesReader(w, originalReq.Body, proxyRequestLimit)

	startTime := time.Now()
	log.Printf("=== INCOMING REQUEST === Target: %s | Client: %s | Method: %s | UserAgent: %s",
		originalReq.Host, originalReq.RemoteAddr, originalReq.Method, originalReq.UserAgent())

	clientIP, _, err := net.SplitHostPort(originalReq.RemoteAddr)
	if err != nil {
		clientIP = originalReq.RemoteAddr
		log.Printf("WARNING: Could not parse client address %s, using full address", originalReq.RemoteAddr)
	}

	log.Printf("CLIENT_INFO: IP=%s | URL_PATH=%s | QUERY=%s", clientIP, originalReq.URL.Path, originalReq.URL.RawQuery)

	hostToCheck := originalReq.Host
	if colonIndex := strings.LastIndex(hostToCheck, ":"); colonIndex != -1 {
		hostToCheck = hostToCheck[:colonIndex]
	}
	if checkForBannedHosts(hostToCheck) {
		duration := time.Since(startTime)

		if originalReq.Method == http.MethodConnect {
			if hijacker, ok := w.(http.Hijacker); ok {
				if clientConn, _, err := hijacker.Hijack(); err == nil {
					clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					clientConn.Close()
				}
			}
		} else {
			http.Error(w, "Website not allowed", http.StatusForbidden)
		}

		log.Printf("BLOCKED_HOST: Host=%s | Client=%s | Duration=%v | Method=%s",
			originalReq.Host, clientIP, duration, originalReq.Method)
		return
	}

	if originalReq.Method == http.MethodConnect {
		handleConnect(w, originalReq, clientIP, startTime)
		return
	}

	handleHTTP(w, originalReq, clientIP, startTime)
}

func handleHTTP(w http.ResponseWriter, originalReq *http.Request, clientIP string, startTime time.Time) {
	defer originalReq.Body.Close()
	client := &http.Client{}
	proxyReqUrl := fmt.Sprintf("http://%s%s", originalReq.Host, originalReq.URL.RequestURI())
	log.Printf("PROXY_REQUEST_START: URL=%s | Client=%s", proxyReqUrl, clientIP)

	proxyReq, err := http.NewRequest(originalReq.Method, proxyReqUrl, originalReq.Body)
	if err != nil {
		duration := time.Since(startTime)
		log.Printf("ERROR_REQUEST_CREATION: Client=%s | URL=%s | Error=%v | Duration=%v",
			clientIP, proxyReqUrl, err, duration)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	proxyReq.Header.Set("X-Forwarded-For", originalReq.RemoteAddr)
	headerCount := 0
	for name, values := range originalReq.Header {
		if !isHopByHop(name) {
			proxyReq.Header[name] = values
			headerCount++
		}
	}
	log.Printf("HEADERS_PROCESSED: Client=%s | ForwardedHeaders=%d | TotalOriginalHeaders=%d",
		clientIP, headerCount, len(originalReq.Header))

	upstreamStart := time.Now()
	res, err := client.Do(proxyReq)
	upstreamDuration := time.Since(upstreamStart)

	if err != nil {
		totalDuration := time.Since(startTime)
		log.Printf("ERROR_UPSTREAM_REQUEST: Client=%s | URL=%s | Error=%v | UpstreamDuration=%v | TotalDuration=%v",
			clientIP, proxyReqUrl, err, upstreamDuration, totalDuration)
		http.Error(w, "Proxy request failed", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()

	log.Printf("UPSTREAM_RESPONSE: Client=%s | StatusCode=%d | ContentLength=%s | ContentType=%s | UpstreamDuration=%v",
		clientIP, res.StatusCode, res.Header.Get("Content-Length"), res.Header.Get("Content-Type"), upstreamDuration)

	contentCheckStart := time.Now()
	newBody, err := checkForBannedWords(res.Body, w, clientIP)
	contentCheckDuration := time.Since(contentCheckStart)

	if err != nil {
		totalDuration := time.Since(startTime)
		log.Printf("BLOCKED_CONTENT: Client=%s | URL=%s | ContentCheckDuration=%v | TotalDuration=%v | Reason=banned_words",
			clientIP, proxyReqUrl, contentCheckDuration, totalDuration)
		return
	}
	log.Printf("CONTENT_CHECK_PASSED: Client=%s | ContentCheckDuration=%v", clientIP, contentCheckDuration)

	res.Body = newBody

	responseHeaderCount := 0
	for name, values := range res.Header {
		if !isHopByHop(name) {
			w.Header()[name] = values
			responseHeaderCount++
		}
	}
	w.WriteHeader(res.StatusCode)

	copyStart := time.Now()
	bytesWritten, err := io.Copy(w, res.Body)
	copyDuration := time.Since(copyStart)
	totalDuration := time.Since(startTime)

	if err != nil {
		log.Printf("ERROR_RESPONSE_COPY: Client=%s | BytesWritten=%d | CopyDuration=%v | Error=%v | TotalDuration=%v",
			clientIP, bytesWritten, copyDuration, err, totalDuration)
	} else {
		log.Printf("SUCCESS_PROXY_COMPLETE: Client=%s | StatusCode=%d | BytesWritten=%d | ResponseHeaders=%d | UpstreamDuration=%v | CopyDuration=%v | TotalDuration=%v",
			clientIP, res.StatusCode, bytesWritten, responseHeaderCount, upstreamDuration, copyDuration, totalDuration)
	}
}

func handleConnect(w http.ResponseWriter, originalReq *http.Request, clientIP string, startTime time.Time) {
	log.Printf("CONNECT_REQUEST: Host=%s | Client=%s", originalReq.Host, clientIP)

	// Hijack the connection FIRST - before any response
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("ERROR_HIJACK_UNSUPPORTED: Client=%s", clientIP)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		duration := time.Since(startTime)
		log.Printf("ERROR_HIJACK_FAILED: Client=%s | Error=%v | Duration=%v",
			clientIP, err, duration)
		return
	}
	defer clientConn.Close()

	// Now establish connection to target server
	targetConn, err := net.DialTimeout("tcp", originalReq.Host, 30*time.Second)
	if err != nil {
		duration := time.Since(startTime)
		log.Printf("ERROR_CONNECT_DIAL: Host=%s | Client=%s | Error=%v | Duration=%v",
			originalReq.Host, clientIP, err, duration)
		// Send error response through hijacked connection
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established through hijacked connection
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Printf("ERROR_CONNECT_RESPONSE: Client=%s | Error=%v", clientIP, err)
		return
	}

	log.Printf("CONNECT_TUNNEL_ESTABLISHED: Host=%s | Client=%s", originalReq.Host, clientIP)

	done := make(chan struct{}, 2)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("CONNECT_TUNNEL_PANIC: client->target panic: %v", r)
			}
			done <- struct{}{}
		}()
		_, err := io.Copy(clientConn, targetConn)
		if err != nil {
			log.Printf("CONNECT_TUNNEL_ERROR: client->target error: %v", err)
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("CONNECT_TUNNEL_PANIC: target->client panic: %v", r)
			}
			done <- struct{}{}
		}()
		_, err := io.Copy(targetConn, clientConn)
		if err != nil {
			log.Printf("CONNECT_TUNNEL_ERROR: target->client error: %v", err)
		}
	}()

	<-done
	<-done

	duration := time.Since(startTime)
	log.Printf("CONNECT_TUNNEL_CLOSED: Host=%s | Client=%s | Duration=%v",
		originalReq.Host, clientIP, duration)
}

func main() {
	logFile := setupLogging()
	defer logFile.Close()

	log.Printf("=== PROXY SERVER STARTING ===")
	log.Printf("CONFIG: ForbiddenHostsFile=%s | ForbiddenWordsFile=%s", forbiddenHostsFileName, forbiddenWordsFileName)

	loadForbiddenWordsAndHosts()

	server := &http.Server{
		Addr:         "127.0.0.1:8090",
		Handler:      http.HandlerFunc(forwardProxy),
		ReadTimeout:  15 * time.Second, // Time to read request headers + body
		WriteTimeout: 15 * time.Second, // Time to write response
		IdleTimeout:  60 * time.Second, // Keep-alive timeout
		// Prevent Slowloris attacks
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    proxyHeaderLimit,
	}

	log.Printf("SERVER_CONFIG: Address=%s | ReadTimeout=%v | WriteTimeout=%v | IdleTimeout=%v | ReadHeaderTimeout=%v",
		server.Addr, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout, server.ReadHeaderTimeout)

	// Start server in goroutine
	go func() {
		log.Printf("SERVER_LISTENING: Address=%s | PID=%d", server.Addr, os.Getpid())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("SERVER_FATAL_ERROR: Address=%s | Error=%v", server.Addr, err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	signal := <-quit

	log.Printf("SHUTDOWN_INITIATED: Signal=%v | Time=%v", signal, time.Now())

	// Give server 30 seconds to finish ongoing requests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shutdownStart := time.Now()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("SHUTDOWN_FORCED: Error=%v | Duration=%v", err, time.Since(shutdownStart))
	} else {
		log.Printf("SHUTDOWN_GRACEFUL: Duration=%v", time.Since(shutdownStart))
	}

	log.Printf("=== PROXY SERVER STOPPED ===")
}

func setupLogging() *os.File {
	file, err := os.OpenFile("proxy.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("LOG_SETUP_FATAL: Cannot open log file: %v", err)
	}

	// log.SetOutput(file)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("=== LOGGING INITIALIZED === LogFile=proxy.log | PID=%d | StartTime=%v",
		os.Getpid(), time.Now())

	return file
}

func isHopByHop(header string) bool {
	hopByHop := map[string]bool{
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"proxy-connection":    true,
		"te":                  true,
		"trailers":            true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}
	return hopByHop[strings.ToLower(header)]
}

func checkForBannedHosts(host string) bool {
	if _, found := forbiddenHostNames[host]; found {
		log.Printf("FILE_CHECK_MATCH: File=%s | CheckedHost=%s", forbiddenHostsFileName, host)
		return true
	}

	return false
}

func bannedWordLookup(word string) bool {
	if _, found := forbiddenWords[word]; found {
		log.Printf("FILE_CHECK_MATCH: File=%s | CheckedWord=%s", forbiddenWordsFileName, word)
		return true
	}
	return false
}

func checkForBannedWords(body io.ReadCloser, w http.ResponseWriter, clientIP string) (io.ReadCloser, error) {
	log.Printf("CONTENT_SCAN_START: Client=%s", clientIP)

	bodyClone := &bytes.Buffer{}
	tee := io.TeeReader(body, bodyClone)

	newBody := &bytes.Buffer{}
	bytesRead, err := io.Copy(newBody, tee)
	if err != nil {
		log.Printf("ERROR_BODY_COPY: Client=%s | BytesRead=%d | Error=%v", clientIP, bytesRead, err)
		return nil, err
	}
	body.Close()

	log.Printf("CONTENT_SCAN_PROGRESS: Client=%s | BytesScanned=%d", clientIP, bytesRead)

	scanner := bufio.NewScanner(bodyClone)
	scanner.Split(bufio.ScanWords)
	wordCount := 0

	for scanner.Scan() {
		wordCount++
		word := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if word == "" {
			continue
		}

		if bannedWordLookup(word) {
			w.WriteHeader(403)
			w.Write([]byte("Website content not allowed."))
			log.Printf("BLOCKED_WORD_FOUND: Client=%s | WordPosition=%d | TotalBytesScanned=%d",
				clientIP, wordCount, bytesRead)
			return nil, fmt.Errorf("banned word found at position %d", wordCount)
		}
	}

	log.Printf("CONTENT_SCAN_COMPLETE: Client=%s | WordsScanned=%d | BytesProcessed=%d | Result=allowed",
		clientIP, wordCount, bytesRead)

	return io.NopCloser(bytes.NewReader(newBody.Bytes())), nil
}

func loadForbiddenWordsAndHosts() {
	file, err := os.Open(forbiddenHostsFileName)
	if err != nil {
		log.Printf("ERROR_FILE_OPEN: File=%s | Error=%v", forbiddenHostsFileName, err)
		log.Fatalf("FATAL_FILE_ACCESS: Cannot continue without access to %s", forbiddenHostsFileName)
	}

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if err := scanner.Err(); err != nil {
			log.Printf("ERROR_FILE_SCAN: File=%s | Line=%d | Error=%v", forbiddenHostsFileName, lineCount, err)
			log.Fatalf("FATAL_FILE_SCAN: Cannot scan file %s", forbiddenHostsFileName)
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		forbiddenHostNames[line] = true
	}
	file.Close()

	file, err = os.Open(forbiddenWordsFileName)
	if err != nil {
		log.Printf("ERROR_FILE_OPEN: File=%s | Error=%v", forbiddenWordsFileName, err)
		log.Fatalf("FATAL_FILE_ACCESS: Cannot continue without access to %s", forbiddenWordsFileName)
	}

	scanner = bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	wordCount := 0
	for scanner.Scan() {
		wordCount++
		if err := scanner.Err(); err != nil {
			log.Printf("ERROR_FILE_SCAN: File=%s | Line=%d | Error=%v", forbiddenWordsFileName, wordCount, err)
			log.Fatalf("FATAL_FILE_SCAN: Cannot scan file %s", forbiddenWordsFileName)
		}

		word := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if word == "" {
			continue
		}
		forbiddenWords[word] = true
	}
	file.Close()

	log.Printf("FORBIDDEN_UPDATE: Forbidden words and hosts loaded into memory")
}
