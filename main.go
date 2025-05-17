package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	port := os.Args[1]

	proxy := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%s", port),
		Handler: http.HandlerFunc(proxyHandler),
	}

	fmt.Printf("Starting proxy server on %s\n", proxy.Addr)
	err := proxy.ListenAndServe()
	if err != nil {
		fmt.Println("Server error:", err)
		os.Exit(1)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	currentTime := time.Now().Format("15:04:05")
	client := r.RemoteAddr
	host := r.Host

	fmt.Printf("[%s] New request received\n   Target: %s   Client: %s\n",
		currentTime, host, client)

	targetURL := &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		fmt.Printf("Failed to create request: %v\n", err)
		return
	}

	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	req.Header.Add("X-Forwarded-For", client)

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		fmt.Printf("Failed to connect to %s: %v\n", host, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Successfully connected to %s (status: %s)\n", host, resp.Status)

	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	bytesLen, err := io.Copy(w, resp.Body)
	if err != nil {
		fmt.Printf("Failed to copy response body: %v\n", err)
		return
	}

	fmt.Printf("Forwarded %d bytes from %s to %s\n", bytesLen, host, client)
}
