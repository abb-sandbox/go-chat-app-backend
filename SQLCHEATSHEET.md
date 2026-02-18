# Actio and the SQL Commands
---
## Create:
    "INSERT INTO users (email, password) VALUES ($1, $2);"
## Read: 
    SELECT * FROM users WHERE id = $1;
## Update: 
    UPDATE users SET is_active = true WHERE id = $1;
## Delete:
    UPDATE users SET deleted_at = NOW() WHERE id = $1; (Soft delete)


    # 🐘 Postgres SQL Master Reference

## 1. Data Type Mapping (Go ↔ Postgres)
This table shows you exactly which Postgres type to use for your Go struct fields.

| Go Type | Postgres Type | Usage | Note |
| :--- | :--- | :--- | :--- |
| `uuid.UUID` | `UUID` | Primary Keys | Better for security than incrementing IDs. |
| `string` | `TEXT` | Emails, Messages | No performance penalty; use by default. |
| `string` | `VARCHAR(n)` | Fixed codes | Use for OTPs/Codes (e.g., `VARCHAR(6)`). |
| `int64` | `BIGINT` | Counters | Standard for large numbers. |
| `bool` | `BOOLEAN` | Flags | Stores `TRUE`, `FALSE`, or `NULL`. |
| `time.Time` | `TIMESTAMPTZ` | Timestamps | **MUST** use this to include time zones. |
| `[]byte` | `BYTEA` | Binaries | Password hashes (bcrypt). |
| `map`, `struct`| `JSONB` | Metadata | Flexible storage for settings. |

---

## 2. Table Constraints (The Rules)
Constraints are the "guardrails" that keep your data clean and consistent.

* **`PRIMARY KEY`**: The unique "home address" for a row. Cannot be NULL or duplicated.
* **`UNIQUE`**: Prevents duplicate data (e.g., two users with the same email).
* **`NOT NULL`**: Field **MUST** contain a value.
* **`DEFAULT`**: Automatically sets a value if you don't provide one (e.g., `is_active DEFAULT false`).
* **`REFERENCES` (Foreign Key)**: Connects tables. Ensures a message can't exist without a valid user.
* **`CHECK`**: Logic validation (e.g., `CHECK (length(code) = 6)`).



---

## 3. SQL Command Library (The "Big Four")

### **Creation (DDL - Data Definition Language)**
```sql
-- Create Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT FALSE,
    activation_code VARCHAR(6),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Delete Table (Caution!)
DROP TABLE users;