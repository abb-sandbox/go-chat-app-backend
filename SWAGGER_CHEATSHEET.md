To avoid headaches during your refactor, here is the "Cheat Sheet" for your `SWAGGERTEMPLATE.MD`.

I have listed every possible variation for the tricky parts of the `@Param` and `@Success` annotations, so you can simply pick the one that fits your logic.

---

### 🏛️ The Master Template (Placeholders)

```go
// @Summary      [Action Title]
// @Description  [Detailed Action Description]
// @Tags         [Category]
// @Accept       [MimeType]
// @Produce      [MimeType]
// @Param        [Name] [Location] [DataType] [Required] "[Comment]"
// @Success      [Code] {[Type]} [ResponseType] "[Comment]"
// @Failure      [Code] {[Type]} [ErrorType]    "[Comment]"
// @Router       /[path] [[Method]]

```

---

### 🚀 Possible Variations (The "Pick List")

#### 1. `[Location]` (Where is the data coming from?)

* **`query`**: For URL filters (e.g., `/users?id=123`).
* **`path`**: For variables in the URL (e.g., `/users/{id}`).
* **`body`**: For JSON/XML payloads (usually `POST`, `PUT`).
* **`header`**: For authentication tokens or custom headers.
* **`formData`**: For file uploads or classic form submissions.

#### 2. `[DataType]` (What is the variable type?)

* **`string`**: For text, IDs, or dates.
* **`integer`**: For counts or numeric IDs.
* **`number`**: For floats/decimals.
* **`boolean`**: For true/false flags.
* **`object`**: Used if you are referencing a struct.
* **`array`**: Used for lists (e.g., `[]string`).
* **`file`**: Specifically for `formData` uploads.

#### 3. `[MimeType]` (Standard formats)

* **`json`**: The most common (maps to `application/json`).
* **`mpfd`**: For file uploads (`multipart/form-data`).
* **`x-www-form-urlencoded`**: For standard forms.
* **`plain`**: For raw text.

#### 4. `[[Method]]` (HTTP Verbs)

* **`[get]`**, **`[post]`**, **`[put]`**, **`[delete]`**, **`[patch]`**

---

### 🏛️ Real Version (Full Go Implementation)

This example shows exactly how your **User Authentication** logic should look for the Feb 15th refactor.

```go
// AuthResponse is what you send back to Flutter
type AuthResponse struct {
    AccessToken  string `json:"access_token" example:"eyJhbG..."`
    RefreshToken string `json:"refresh_token" example:"abc123..."`
}

// ErrorResponse is a generic error handler
type ErrorResponse struct {
    Code    int    `json:"code" example:"401"`
    Message string `json:"message" example:"token_expired"`
}

// @Summary      Log Out User
// @Description  Revokes the session in Redis using the shared JTI
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer {access_token}"
// @Param        device_id      query     string  false "Optional: Device ID to target"
// @Success      200            {object}  map[string]string "{"status": "ok"}"
// @Failure      401            {object}  ErrorResponse
// @Router       /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
    // Logic here...
}

```

---

### 🛡️ Senior Refactor Tip

When using **`header`** for the `Authorization` param, remember that Swagger UI will usually display a little "Lock" icon if you set up Global Security instead. But for individual route testing, the `header` param above is the easiest way for your Flutter developer to manually paste a token.

**Would you like the CLI command to automatically format all your comments to make them look pretty and aligned?**