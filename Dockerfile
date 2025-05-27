FROM golang:1.24.3-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o proxy main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=builder /app/proxy .
COPY forbidden-hosts.txt banned-words.txt ./
EXPOSE 8090
CMD ["./proxy"]
