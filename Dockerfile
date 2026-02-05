# Go 1.25.5 is container-native and very efficient
FROM golang:1.25.5-bookworm

WORKDIR /app

# 1. Install Air for hot reloading
RUN go install github.com/air-verse/air@latest

# 2. Cache Dependencies (The "Speed" part)
# Only re-runs if go.mod or go.sum changes
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# 3. Copy the rest of the code
COPY . .

# Air will handle the building and running
CMD ["air"]