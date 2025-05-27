package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	forbiddenHostsFileName = "forbidden-hosts.txt"
	forbiddenWordsFileName = "banned-words.txt"
)

func forwardProxy(w http.ResponseWriter, originalReq *http.Request) {
	log.Printf("Request made. Target: %s Client: %s", originalReq.Host, originalReq.RemoteAddr)

	// Prevent banned hosts
	if shouldPreventProxy(originalReq.Host, forbiddenHostsFileName) {
		w.WriteHeader(403)
		w.Write([]byte("Website not allowed: facebook.com"))
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

	clientIP, _, err := net.SplitHostPort(originalReq.RemoteAddr)
	if err != nil {
		clientIP = originalReq.RemoteAddr
	}
	log.Printf("ClientIP %s\n", clientIP)

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

	newBody, err := checkForBannedWords(res.Body, w)
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

	_, err = io.Copy(w, res.Body)
	if err != nil {
		log.Printf("failed to copy response body: %v", err)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", forwardProxy)

	log.Printf("Starting proxy server on 127.0.0.1:8090")
	http.ListenAndServe("localhost:8090", mux)
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

func checkForBannedWords(body io.ReadCloser, w http.ResponseWriter) (io.ReadCloser, error) {
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
			return nil, fmt.Errorf("banned word found")
		}
	}

	return io.NopCloser(bytes.NewReader(newBody.Bytes())), nil
}
