
# 🚀 2026 DEVOPS & YAML MASTER CHEATSHEET
### Focus: Go Backend | Flutter Integration | Windows Environment

---

## 🏗️ 1. YAML LOGIC & SYNTAX (The "Senior" Essentials)
YAML is **declarative**. You describe the *Goal*, not the *Steps*.

* **Indentation:** Always **2 spaces**. Never Tabs.
* **The List (-):** Used for things that are "one of many" (Env vars, ports, tasks).
* **The Map (key: value):** Used for specific attributes.
* **Comments (#):** Use them to explain *why* a limit is set, especially for your Canadian collaborators.
* **Multi-line Strings (|):** Use the pipe symbol for long scripts or RSA keys.

---

## 🐋 2. DOCKER COMPOSE (Local Development Pillar)
*File: docker-compose.yml*

| Key | Logic / Purpose | Go Developer Context |
| :--- | :--- | :--- |
| `services` | Container definitions | Your Go API, DB, and Redis go here. |
| `build: .` | Build local code | Points to the folder with your `Dockerfile`. |
| `image` | Pull external code | Use for `postgres:16-alpine` or `redis:7-alpine`. |
| `ports` | `Host:Container` | Go apps usually map `"8080:8080"`. |
| `env_file` | Secret management | Load `.env` files here to keep YAML clean. |
| `depends_on` | Sequence | Ensures the DB container starts before the Go binary. |
| `networks` | Isolation | Allows Go to find DB via hostname `http://db:5432`. |

### 💡 Pro-Tip: Service Discovery
In a network called `backend`, your Go code connects to Postgres using:
`dsn := "postgres://user:pass@db:5432/dbname"` (where `db` is the service name).

---

## ☸️ 3. KUBERNETES (Production Orchestration Pillar)
*File: deployment.yaml / service.yaml*

### A. The Deployment (The "How many?")
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chat-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: go-api # This MUST match the template label
  template:
    metadata:
      labels:
        app: go-api
    spec:
      containers:
      - name: server
        image: go-chat:v1.0.1
        resources: # Critical for Interview: Resource Quotas
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "256Mi"

```

### B. The Service (The "Access Point")

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-service
spec:
  selector:
    app: go-api # Finds pods with this label
  ports:
    - protocol: TCP
      port: 80      # External port
      targetPort: 8080 # Internal Go app port
  type: ClusterIP # Internal only (standard for backends)

```

---

## 🤖 4. GITHUB ACTIONS & CI/CD (Automation Pillar)

*File: .github/workflows/main.yml*

| Keyword | Logic |
| --- | --- |
| `on:` | The Trigger (push, pull_request). |
| `jobs:` | Groups of tasks (build, test, deploy). |
| `runs-on:` | The OS (ubuntu-latest is cheapest/fastest for Go). |
| `steps:` | The "To-Do List" (Checkout code -> Setup Go -> Run Tests). |
| `uses:` | Reusable actions (e.g., `actions/setup-go@v5`). |

---

## 🏛️ 5. INTERVIEW "BULLSEYE" ANSWERS

**Q: "How do you handle sensitive data in YAML?"**

> **A:** "I never hardcode secrets. For local dev, I use a `.gitignore`ed `.env` file with Docker Compose. For production, I use **Kubernetes Secrets** or **HashiCorp Vault**, injecting them as environment variables at runtime."

**Q: "What is the difference between `ports` and `expose` in Compose?"**

> **A:** "`ports` opens a gate to the outside world (host machine). `expose` only opens a gate to other containers on the same network. I use `expose` for my DB and `ports` only for my API gateway."

**Q: "Your Go pod is crashing in K8s (CrashLoopBackOff). What do you check?"**

> **A:** "I check the **Events** with `kubectl describe pod` to see if it's a resource limit issue (OOMKilled), then I check the **Logs** with `kubectl logs` to see if the Go binary failed to connect to the DB or missed an Env var."

---

## 🛠️ 6. 2026 CLI SURVIVAL KIT

* `docker compose up --build` - Recompile Go and restart.
* `kubectl get pods -w` - Watch pods come to life.
* `kubectl apply -f .` - The "Magic" command to sync all local YAMLs to the cloud.
* `docker system prune` - Clean up Windows disk space from old images.

```

**Next Step:** Would you like to try a **"Fix the YAML"** challenge where I give you a file with 3 intentional logic errors to see if you can find them?

```