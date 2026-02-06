FROM golang:1.25.5-alpine

WORKDIR /app

FROM golang:1.25.5-alpine

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
EXPOSE 8000
CMD ["go run ./cmd/main.go"]