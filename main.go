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
	log.Printf("Request made. Target: %s Client: %s", originalReq.Host, originalReq.RemoteAddr)

	clientIP, _, err := net.SplitHostPort(originalReq.RemoteAddr)
	if err != nil {
		clientIP = originalReq.RemoteAddr
	}

	log.Printf("ClientIP %s\n", clientIP)
	if shouldPreventProxy(originalReq.Host, forbiddenHostsFileName) {
		w.WriteHeader(403)
		w.Write([]byte("Website not allowed: facebook.com"))
		log.Printf("Found a banned host %s for client %s\n", originalReq.Host, clientIP)
		return
	}

	client := &http.Client{}

	proxyReqUrl := fmt.Sprintf("http://%s%s", originalReq.Host, originalReq.URL.Path)
	log.Printf("Constructing proxy request for %s\n", proxyReqUrl)
	proxyReq, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", originalReq.Host, originalReq.URL.Path), nil)
	if err != nil {
		log.Printf("failed to create request: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	proxyReq.Header.Set("X-Forwarded-For", originalReq.RemoteAddr)
	for name, values := range originalReq.Header {
		if !isHopByHop(name) {
			proxyReq.Header[name] = values
		}
	}
	if headerBytes, err := json.MarshalIndent(proxyReq.Header, "", "  "); err == nil {
		log.Printf("Proxy request headers:\n%s", string(headerBytes))
	} else {
		log.Printf("Proxy request headers: %v (failed to marshal: %v)", proxyReq.Header, err)
	}

	res, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("proxy request failed: %v", err)
		http.Error(w, "Proxy request failed", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()

	newBody, err := checkForBannedWords(res.Body, w, clientIP)
	if err != nil {
		return
	}
	res.Body = newBody

	for name, values := range res.Header {
		if !isHopByHop(name) {
			w.Header()[name] = values
		}
	}
	w.WriteHeader(res.StatusCode)

	log.Printf("Proxy request successfully made for client: %s and status is %d", clientIP, res.StatusCode)
	_, err = io.Copy(w, res.Body)
	if err != nil {
		log.Printf("failed to copy response body: %v", err)
	}
}

func main() {
	logFile := setupLogging()
	defer logFile.Close()

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

	// Start server in goroutine
	go func() {
		log.Printf("Starting proxy server on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("Shutting down server...")

	// Give server 30 seconds to finish ongoing requests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Printf("Server stopped")
}

func setupLogging() *os.File {
	file, err := os.OpenFile("proxy.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Cannot open log file: %v", err)
	}

	log.SetOutput(file)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

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
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == host {
			return true
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("error reading file: %s", err)
		}
	}
	return false
}

func checkForBannedWords(body io.ReadCloser, w http.ResponseWriter, clientIP string) (io.ReadCloser, error) {
	bodyClone := &bytes.Buffer{}
	tee := io.TeeReader(body, bodyClone)

	newBody := &bytes.Buffer{}
	_, err := io.Copy(newBody, tee)
	if err != nil {
		return nil, err
	}
	body.Close()

	scanner := bufio.NewScanner(bodyClone)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		word := scanner.Text()
		if shouldPreventProxy(word, forbiddenWordsFileName) {
			w.WriteHeader(403)
			w.Write([]byte("Website content not allowed."))
			log.Printf("Found a banned word %s for client %s\n", word, clientIP)
			return nil, fmt.Errorf("banned word found")
		}
	}

	return io.NopCloser(bytes.NewReader(newBody.Bytes())), nil
}
