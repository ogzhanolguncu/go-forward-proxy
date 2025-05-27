package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

const (
	forbiddenHostsFileName = "forbidden-hosts.txt"
	forbiddenWordsFileName = "banned-words.txt"
)

func forwardProxy(w http.ResponseWriter, originalReq *http.Request) {
	startTime := time.Now()
	log.Printf("=== INCOMING REQUEST === Target: %s | Client: %s | Method: %s | UserAgent: %s",
		originalReq.Host, originalReq.RemoteAddr, originalReq.Method, originalReq.UserAgent())

	clientIP, _, err := net.SplitHostPort(originalReq.RemoteAddr)
	if err != nil {
		clientIP = originalReq.RemoteAddr
		log.Printf("WARNING: Could not parse client address %s, using full address", originalReq.RemoteAddr)
	}

	log.Printf("CLIENT_INFO: IP=%s | URL_PATH=%s | QUERY=%s", clientIP, originalReq.URL.Path, originalReq.URL.RawQuery)

	if shouldPreventProxy(originalReq.Host, forbiddenHostsFileName) {
		duration := time.Since(startTime)
		w.WriteHeader(403)
		w.Write([]byte("Website not allowed: facebook.com"))
		log.Printf("BLOCKED_HOST: Host=%s | Client=%s | Duration=%v | Reason=forbidden_hosts_list",
			originalReq.Host, clientIP, duration)
		return
	}

	client := &http.Client{}

	proxyReqUrl := fmt.Sprintf("http://%s%s", originalReq.Host, originalReq.URL.Path)
	log.Printf("PROXY_REQUEST_START: URL=%s | Client=%s", proxyReqUrl, clientIP)

	proxyReq, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", originalReq.Host, originalReq.URL.Path), nil)
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

	if headerBytes, err := json.MarshalIndent(proxyReq.Header, "", "  "); err == nil {
		log.Printf("PROXY_HEADERS_DETAIL: Client=%s | Headers=\n%s", clientIP, string(headerBytes))
	} else {
		log.Printf("WARNING_HEADER_MARSHAL: Client=%s | Headers=%v | MarshalError=%v",
			clientIP, proxyReq.Header, err)
	}

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

func main() {
	logFile := setupLogging()
	defer logFile.Close()

	log.Printf("=== PROXY SERVER STARTING ===")
	log.Printf("CONFIG: ForbiddenHostsFile=%s | ForbiddenWordsFile=%s", forbiddenHostsFileName, forbiddenWordsFileName)

	mux := http.NewServeMux()
	mux.HandleFunc("/", forwardProxy)

	server := &http.Server{
		Addr:         "127.0.0.1:8090",
		Handler:      mux,
		ReadTimeout:  15 * time.Second, // Time to read request headers + body
		WriteTimeout: 15 * time.Second, // Time to write response
		IdleTimeout:  60 * time.Second, // Keep-alive timeout
		// Prevent Slowloris attacks
		ReadHeaderTimeout: 5 * time.Second,
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

	log.SetOutput(file)
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

func shouldPreventProxy(host, bannedHostsOrWords string) bool {
	file, err := os.Open(bannedHostsOrWords)
	if err != nil {
		log.Printf("ERROR_FILE_OPEN: File=%s | Error=%v", bannedHostsOrWords, err)
		log.Fatalf("FATAL_FILE_ACCESS: Cannot continue without access to %s", bannedHostsOrWords)
	}
	defer file.Close()

	log.Printf("FILE_CHECK_START: File=%s | CheckingFor=%s", bannedHostsOrWords, host)

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()
		if line == host {
			log.Printf("FILE_CHECK_MATCH: File=%s | Line=%d | Match=%s", bannedHostsOrWords, lineCount, line)
			return true
		}

		if err := scanner.Err(); err != nil {
			log.Printf("ERROR_FILE_SCAN: File=%s | Line=%d | Error=%v", bannedHostsOrWords, lineCount, err)
			log.Fatalf("FATAL_FILE_SCAN: Cannot scan file %s", bannedHostsOrWords)
		}
	}

	log.Printf("FILE_CHECK_COMPLETE: File=%s | LinesChecked=%d | Match=false", bannedHostsOrWords, lineCount)
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
		word := scanner.Text()
		if shouldPreventProxy(word, forbiddenWordsFileName) {
			w.WriteHeader(403)
			w.Write([]byte("Website content not allowed."))
			log.Printf("BLOCKED_WORD_FOUND: Client=%s | Word=%s | WordPosition=%d | TotalBytesScanned=%d",
				clientIP, word, wordCount, bytesRead)
			return nil, fmt.Errorf("banned word found: %s", word)
		}
	}

	log.Printf("CONTENT_SCAN_COMPLETE: Client=%s | WordsScanned=%d | BytesProcessed=%d | Result=allowed",
		clientIP, wordCount, bytesRead)

	return io.NopCloser(bytes.NewReader(newBody.Bytes())), nil
}
