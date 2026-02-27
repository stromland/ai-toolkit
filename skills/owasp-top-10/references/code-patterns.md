# OWASP Top 10:2025 — Insecure vs Secure Code Patterns

Side-by-side examples for the most frequently encountered vulnerability types. Use these when
explaining findings or suggesting fixes during code reviews. Adapt to the user's actual language
and framework as needed.

---

## A01: Broken Access Control

### IDOR — Missing Ownership Check

**❌ Insecure (JavaScript / Express)**
```javascript
// User can access any order by changing the ID in the URL
app.get('/orders/:id', async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  res.json(order);
});
```

**✅ Secure**
```javascript
app.get('/orders/:id', async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  if (!order || order.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
});
```

---

### Missing Authorization on Admin Endpoint

**❌ Insecure (Python / Flask)**
```python
@app.route('/admin/users')
def list_users():
    # No auth check — any logged-in user can access admin data
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])
```

**✅ Secure**
```python
@app.route('/admin/users')
@login_required
@require_role('admin')          # enforce role server-side
def list_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])
```

---

### SSRF — Unvalidated URL Fetch

**❌ Insecure (JavaScript)**
```javascript
app.post('/fetch-preview', async (req, res) => {
  // Attacker can send: { url: "http://169.254.169.254/latest/meta-data/" }
  const response = await fetch(req.body.url);
  res.send(await response.text());
});
```

**✅ Secure**
```javascript
const ALLOWED_HOSTS = new Set(['example.com', 'api.partner.com']);

app.post('/fetch-preview', async (req, res) => {
  const parsed = new URL(req.body.url);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    return res.status(400).json({ error: 'Host not permitted' });
  }
  const response = await fetch(req.body.url);
  res.send(await response.text());
});
```

---

## A04: Cryptographic Failures

### Password Stored with Weak Hash

**❌ Insecure (Python)**
```python
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()   # MD5 is broken; no salt
user.password_hash = hashed
```

**✅ Secure**
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
user.password_hash = hashed
# Verify: bcrypt.checkpw(password.encode(), user.password_hash)
```

---

### Hardcoded Secret / Key

**❌ Insecure (JavaScript)**
```javascript
const jwt = require('jsonwebtoken');
const token = jwt.sign(payload, 'mysecretkey123');  // hardcoded in source
```

**✅ Secure**
```javascript
const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET;              // loaded from environment
if (!secret) throw new Error('JWT_SECRET not set');
const token = jwt.sign(payload, secret, { expiresIn: '15m' });
```

---

### Sensitive Data Transmitted in Cleartext URL

**❌ Insecure**
```
GET /reset?token=abc123&email=user@example.com HTTP/1.1
```
Tokens and emails in query strings appear in server logs, browser history, and referrer headers.

**✅ Secure**
```
POST /reset HTTP/1.1
Content-Type: application/json

{ "token": "abc123", "email": "user@example.com" }
```
Keep sensitive data in the request body over HTTPS, not in the URL.

---

## A05: Injection

### SQL Injection via String Concatenation

**❌ Insecure (Python)**
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
# Attacker input: ' OR '1'='1  → returns all users
```

**✅ Secure**
```python
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

---

### SQL Injection via String Interpolation (JavaScript / Node)

**❌ Insecure**
```javascript
const result = await db.query(`SELECT * FROM products WHERE id = ${req.params.id}`);
```

**✅ Secure**
```javascript
const result = await db.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
```

---

### Stored XSS — Unescaped Output

**❌ Insecure (JavaScript / React-like pseudocode)**
```javascript
// Renders raw HTML from user-supplied content
element.innerHTML = userComment;
```

**✅ Secure**
```javascript
// Use textContent for plain text — browser won't interpret it as HTML
element.textContent = userComment;

// Or in React, never use dangerouslySetInnerHTML unless sanitized first:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userComment) }} />
```

---

### OS Command Injection

**❌ Insecure (Python)**
```python
import os
os.system(f"convert {filename} output.png")   # attacker controls filename
# Malicious input: "foo.jpg; rm -rf /"
```

**✅ Secure**
```python
import subprocess
subprocess.run(['convert', filename, 'output.png'], check=True)
# List form never passes input to a shell; no injection possible
```

---

## A07: Authentication Failures

### No Rate Limiting on Login

**❌ Insecure (JavaScript / Express)**
```javascript
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  // No rate limiting — attacker can try millions of passwords
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: generateToken(user) });
});
```

**✅ Secure**
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                    // max 10 attempts per IP per window
  message: { error: 'Too many login attempts. Try again later.' },
});

app.post('/login', loginLimiter, async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.regenerate(() => {               // rotate session ID on login
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});
```

---

### Session Not Invalidated on Logout

**❌ Insecure (Python / Flask)**
```python
@app.route('/logout')
def logout():
    session.pop('user_id', None)    # clears client cookie, server session persists
    return redirect('/')
```

**✅ Secure**
```python
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()                 # clear all session data
    # If using server-side sessions (Redis, DB), also delete the session record:
    db.sessions.delete(session.sid)
    return redirect('/')
```

---

## A10: Mishandling of Exceptional Conditions

### Fail-Open Access Control

**❌ Insecure (JavaScript)**
```javascript
async function hasPermission(userId, resource) {
  try {
    const perms = await db.permissions.find({ userId, resource });
    return perms.length > 0;
  } catch (err) {
    // DB error → defaults to true → attacker triggers DB errors to gain access
    return true;
  }
}
```

**✅ Secure**
```javascript
async function hasPermission(userId, resource) {
  try {
    const perms = await db.permissions.find({ userId, resource });
    return perms.length > 0;
  } catch (err) {
    logger.error({ err, userId, resource }, 'Permission check failed — denying access');
    return false;   // fail closed: deny on error
  }
}
```

---

### Generic Exception Handler Around Security Logic

**❌ Insecure (Python)**
```python
try:
    token_data = jwt.decode(token, SECRET, algorithms=['HS256'])
    user = get_user(token_data['sub'])
    process_request(user, data)
except Exception:
    # Catches JWT errors, expired tokens, user-not-found, and everything else
    # If JWT validation throws, process_request might still execute in some code paths
    pass
```

**✅ Secure**
```python
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

try:
    token_data = jwt.decode(token, SECRET, algorithms=['HS256'])
except ExpiredSignatureError:
    return error_response(401, 'Token expired')
except InvalidTokenError:
    return error_response(401, 'Invalid token')

# Only reaches here if token is valid
user = get_user(token_data['sub'])
process_request(user, data)
```

---

### Missing Timeout on External Call

**❌ Insecure (JavaScript)**
```javascript
const response = await fetch(externalServiceUrl);  // hangs indefinitely if service is slow
```

**✅ Secure**
```javascript
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 5000);  // 5-second timeout

try {
  const response = await fetch(externalServiceUrl, { signal: controller.signal });
  return await response.json();
} catch (err) {
  if (err.name === 'AbortError') {
    throw new ServiceUnavailableError('External service timed out');
  }
  throw err;
} finally {
  clearTimeout(timeout);
}
```
