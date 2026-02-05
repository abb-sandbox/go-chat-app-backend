FROM golang:1.25.5-alpine

WORKDIR /app

# Install Air for hot reloading
RUN go install github.com/air-verse/air@latest

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Run Air and tell it exactly where your main file is
# We use flags to avoid needing an air.toml file
ENTRYPOINT ["air", \
    "--build.cmd", "go build -o /tmp/main ./cmd/main.go", \
    "--build.bin", "/tmp/main", \
    "--build.include_ext", "go,env", \
    "--build.stop_on_error", "false"]