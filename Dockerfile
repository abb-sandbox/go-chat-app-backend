FROM golang:1.25.5-alpine

WORKDIR /app

# Install Air for hot reloading
RUN go install github.com/air-verse/air@latest

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Inside your Dockerfile
ENTRYPOINT ["air", \
    "--build.cmd", "go build -o ./tmp/main ./cmd/main.go", \
    "--build.entrypoint", "./tmp/main", \
    "--build.stop_on_error", "false"]