# STAGE 1: Build the binary
FROM golang:1.25.5-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/main.go

# STAGE 2: Final small image
FROM alpine:latest
WORKDIR /root/
# Copy only the compiled binary from the builder
COPY --from=builder /app/main .
EXPOSE 8000
# Run the binary directly (No "go run")
CMD ["./main"]