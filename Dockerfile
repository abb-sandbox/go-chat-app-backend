FROM golang:1.25.5-alpine

WORKDIR /app

FROM golang:1.25.5-alpine
RUN apk add --no-cache git build-base
RUN go install github.com/air-verse/air@latest
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENTRYPOINT ["air", \
    "--build.cmd", "go build -o ./tmp/main ./cmd/main.go", \
    "--build.bin", "./tmp/main", \
    "--build.stop_on_error", "false"]