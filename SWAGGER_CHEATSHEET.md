Since you have decided to stick with **Gin** and **Swag**, consistency is your best friend. In the "manual" world of Swagger comments, small typos can break the generation or mislead your Flutter developer.

Here is a comprehensive, production-ready "Cheat Sheet" that covers the specific scenarios you asked for: returning raw HTML, empty statuses, and complex JSON responses.

---

### 🏛️ The "Standard" Master Template

Keep this at the top of your `SWAGGERTEMPLATE.MD`.

```go
// @Summary      [Short Action Name]
// @Description  [Longer explanation of the logic]
// @Tags         [Category/Module Name]
// @Accept       json, mpfd, plain
// @Produce      json, html, xml, plain
// @Param        [Name] [Location] [DataType] [Required] "[Comment]" [Options]
// @Success      [Code] {[Type]} [ResponseType] "[Comment]"
// @Failure      [Code] {[Type]} [ErrorType]    "[Comment]"
// @Router       /[path] [[Method]]

```

---

### 🚀 Specialized Documentation Patterns

#### 1. When you return ONLY a Status Code (No Body)

Use `string` as the type and leave the description as the only content.

```go
// @Success 204 "No Content - Resource deleted successfully"
// @Success 200 "OK - Heartbeat pulse"

```

#### 2. When you return Raw HTML (Server Side Rendering)

If you are sending a dashboard or a login page directly from Go:

```go
// @Produce html
// @Success 200 {string} string "Returns the raw HTML of the login page"

```

#### 3. When you return a Generic JSON Wrapper (Success/Status)

Instead of creating a new struct for every simple "OK" response:

```go
// @Success 200 {object} map[string]interface{} "{"status": "success", "data": null}"
// @Success 201 {object} object{id=string,msg=string} "Inline object definition"

```

#### 4. Multiple Possible Responses (Dynamic Success)

If an endpoint can return different shapes based on a query param:

```go
// @Success 200 {object} UserProfile "Standard profile view"
// @Success 200 {object} UserAdminView "Admin-only detailed view"

```

---

### 🏛️ Variable Options & Constraints

| Option | Values | Use Case |
| --- | --- | --- |
| **`[Location]`** | `query`, `path`, `header`, `body`, `formData` | Where the input lives. |
| **`[DataType]`** | `string`, `integer`, `number`, `boolean`, `file`, `array` | The variable type. |
| **`[Required]`** | `true`, `false` | Is the field mandatory? |
| **`[Produce]`** | `json`, `html`, `plain`, `xml` | What the Flutter app receives. |

---

### 🏛️ Real-World Example (The "utilizable" version)

This shows how to document a **Password Reset** flow where you might return different types (HTML vs JSON).

```go
// RequestPasswordReset godoc
// @Summary      Request Password Reset
// @Description  Sends an email or returns an HTML success page based on the Accept header.
// @Tags         Auth
// @Accept       json
// @Produce      json,html
// @Param        email  body      string  true  "User email address"  example(user@example.com)
// @Success      200    {string}  string  "Returns HTML success message if requested"
// @Success      202    {object}  map[string]string "{"message": "email_sent"}"
// @Failure      400    {object}  app_errors.ErrorResponse "Invalid email format"
// @Failure      404    {object}  app_errors.ErrorResponse "User not found"
// @Router       /auth/reset-password [post]
func (h *Handler) RequestReset(c *gin.Context) {
    // Logic...
}

```

---

### 🛡️ Pro-Tips for Gin & Swag Integration

* **Struct Tags:** Use the `example:"..."` tag in your Go structs. Swag reads these and creates the "Try it out" data for your Flutter dev automatically.
```go
type User struct {
    ID   string `json:"id" example:"user_2n8A..."`
    Name string `json:"name" example:"John Doe"`
}

```


* **Recursive Structs:** If you have an array of items, use the `{array}` notation:
`// @Success 200 {array} models.Product`
* **The "Docs" Import:** Always remember to import your generated docs in `main.go` so the UI actually updates:
`_ "github.com/your-username/your-repo/docs"`

---

### 🚀 CLI Maintenance Command

To keep your comments "pretty" and ensure your Swagger UI is always synced, run this after every change:

```bash
# Formats comments and generates files
swag fmt && swag init

```
