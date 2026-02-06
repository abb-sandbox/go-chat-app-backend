Here is the complete **`CHEATSHEET.md`** content in a single, pure Markdown block for easy copy-pasting into your project.


# 🐳 Go-Docker 2026 Masterpiece Cheatsheet

## 🏗️ 1. Dockerfile Logic (Internal Commands)
| Instruction | Purpose | Senior Tip |
| :--- | :--- | :--- |
| **FROM** | Base OS + Language(golang:1.25.5-alpine) | Use `alpine` versions for smaller, faster images. |
| **WORKDIR** | Set home directory(mkdir+cd) | Always use `/app`. Prevents cluttering the root `/`. |
| **RUN** | Build-time execution(one-timeexecution) | Use for installing tools like `air` or `go mod download`. |
| **COPY** | Move files from Host to Image ( . .) | Copy `go.mod` first to take advantage of layer caching. |
| **ENTRYPOINT**| The main process | Use this for `air` so the container stays focused on watching. |
| **EXPOSE** | Documentation | Tells others which port the app intends to use. |

---

## 💻 2. CLI Commands (External Controls)

### **Development (Local Learning)**

# BUILD: Create the image
docker build -t go-backend-dev .

# RUN: Start the container with hot-reload
```
docker run -it --rm \
  -p 8000:8000 \
  -v "$(pwd):/app" \
  --name backend-dev \
  go-backend-dev

```

### **Maintenance**

```
docker ps                # List running containers
docker stop <name/id>    # Stop a container
docker logs -f <name>    # Follow logs (See Air output)
docker system prune -f   # Delete unused data (Keep disk clean)
```


---

## 🛠️ 3. Air Platform Logic (Windows vs. Linux)

| Setting | **Windows (Native)** | **Linux / Docker / Cloud** |
| --- | --- | --- |
| **Slashes** | Backslash `\\` | Forward slash `/` |
| **Binary Name** | `main.exe` | `main` |
| **Build Cmd** | `go build -o ./tmp/main.exe ./cmd/main.go` | `go build -o ./tmp/main ./cmd/main.go` |
| **Air Flag** | `--build.bin "tmp\\main.exe"` | `--build.bin "tmp/main"` |

---

## 🚦 4. Development vs. Production

### **Development Mode**

* **Goal:** Developer Experience (DX).
* **Setup:** Single-stage Dockerfile + `air`.
* **Deployment:** Uses **Volumes** to sync code changes instantly.
* **Environment:** Includes full Go SDK and build tools.

### **Production Mode**

* **Goal:** Performance and Security.
* **Setup:** **Multi-Stage Build**.
* **Deployment:** No source code included; only the compiled binary.
* **Environment:** Minimal Alpine OS (reduces attack surface).

---

## 🧠 5. Important Concepts

* **Build Context (`.`):** Everything in the folder where you run `docker build` is sent to Docker. Keep your `.git` and `node_modules` out of it using a `.dockerignore`.
* **Port Mapping (`-p 8000:8000`):** Bridge from `Host:Container`. Your Go code listens on `0.0.0.0:8000` inside Docker to be reachable.
* **Layer Caching:** Docker remembers steps. If you don't change `go.mod`, Docker skips `go mod download` to save time.

---

## 🚀 6. The "No-Config" Dockerfile (Alpine + Air)

```dockerfile
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

```

