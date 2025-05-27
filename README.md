# HTTP/HTTPS Proxy Server

Go proxy server with content filtering, rate limiting, and comprehensive logging.

## Features

- HTTP/HTTPS support (CONNECT method for HTTPS)
- Host and content filtering via text files
- Per-IP rate limiting (5 req/sec)
- Detailed logging with performance metrics
- Health check endpoint (`/health`)
- Graceful shutdown

## Quick Start

### Prerequisites

- Go 1.19+
- Create two filter files (can be empty):

**forbidden-hosts.txt**

```
facebook.com
twitter.com
# Comments allowed
```

**banned-words.txt**

```
spam
malware
```

### Run

```bash
go build -o proxy main.go
./proxy
```

Server starts on `127.0.0.1:8090`

## Usage

```bash
# Set as HTTP proxy
export HTTP_PROXY=http://127.0.0.1:8090
export HTTPS_PROXY=http://127.0.0.1:8090

# Test with curl
curl -x http://127.0.0.1:8090 http://example.com

# Health check
curl http://127.0.0.1:8090/health
```

## Configuration

| Setting          | Value            | Description         |
| ---------------- | ---------------- | ------------------- |
| Address          | `127.0.0.1:8090` | Server bind address |
| Rate Limit       | 5 req/sec        | Per-IP limit        |
| Request Timeout  | 30s              | Upstream timeout    |
| Max Request Size | 64KB             | Body size limit     |

## Filtering

- **Host blocking**: Edit `forbidden-hosts.txt` (one domain per line)
- **Content filtering**: Edit `banned-words.txt` (case-insensitive)
- Returns HTTP 403 when blocked

## Logging

All activity logged to `proxy.log`:

```
SUCCESS_PROXY_COMPLETE: Client=192.168.1.100 | StatusCode=200 | BytesWritten=1234 | TotalDuration=155ms
```

## Error Codes

- `403`: Blocked host/content
- `429`: Rate limit exceeded
- `502`: Upstream connection failed
- `504`: Upstream timeout

## Troubleshooting

- Ensure filter files exist (can be empty)
- Check `proxy.log` for detailed errors
- Verify write permissions for log file
