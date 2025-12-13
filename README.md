# gun-authd v3: Deterministic Authentication for GunDB

**gun-authd** is a specialized extension for [GunDB](https://gun.eco/) that enables purely deterministic user authentication using **Argon2id** and **HKDF**.

It allows users to generate their SEA (Security, Encryption, Authorization) key pairs locally based solely on their username, password, and optional **PIN**, **without needing to fetch a random salt from the network**.

> 🚀 **What's new in v3:** Optional **PIN support** (4-8 digits) for three-factor key derivation, **rate limiting** to prevent brute-force attacks, **stricter password validation** (12 chars, 40 bits entropy), and **secure memory wipe** for better security.

---

## 📋 Table of Contents

- [The Problem](#-the-problem-with-standard-gun-auth)
- [The Solution](#-the-gun-authd-solution)
- [Security Assessment](#️-security-assessment)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [TypeScript Support](#-typescript-support)
- [How It Works](#️-how-it-works-under-the-hood)
- [Important Trade-offs](#️-important-trade-offs)
- [Who Should Use This](#-who-should-use-this)
- [Dependencies](#-dependencies)

---

## 🚨 The Problem with Standard Gun Auth

By default, `gun.user().create()` works like this:
1. Generates a random cryptographic **salt**.
2. Stores this salt publicly in the graph.
3. To log in (`.auth()`), the client must first **download** this salt to verify the password.

**The Drawbacks:**
* **Network Dependency:** You cannot log in on a fresh device without internet access or peer connectivity.
* **Censorship Risk:** If a node blocks access to your salt data, you cannot compute your keys to log in.
* **Single Point of Failure:** The relay holding your salt becomes critical infrastructure.

---

## ✅ The gun-authd Solution

**gun-authd** removes the random salt. Instead, it uses **Argon2id + HKDF** to mathematically derive your keys.

* **Zero Lookup:** Login is instant. No network request needed to "find" the user first.
* **Deterministic:** `Username` + `Password` (+ optional `PIN`) will *always* generate the exact same Private Key.
* **Three-Factor Support:** Optional PIN (4-8 digits) adds a third factor to key derivation.
* **Rate Limiting:** Built-in protection against brute-force attacks (5 attempts, progressive delay).
* **Graph Compatible:** It manually handles the `~@alias` -> `~pubkey` linking, so your user is still discoverable by others in the Gun network.
* **Memory-Hard:** Argon2id is resistant to GPU/ASIC attacks unlike PBKDF2.
* **Secure Memory Wipe:** Sensitive key material is securely cleared after use.
* **Username Protection:** Automatically prevents login if username already exists with a different password.

---

## 🛡️ Security Assessment

### ✅ Strengths

| Aspect | Details |
|--------|---------|
| **Offline-First** | Full authentication without network access |
| **Censorship Resistant** | No central salt storage = no censorship point |
| **Memory-Hard KDF** | Argon2id with **64 MB memory** (resistant to GPU/ASIC attacks) |
| **Domain Separation** | HKDF ensures signing and encryption keys are cryptographically independent |
| **Standard Cryptography** | ECDSA/ECDH P-256 (NIST curves), SHA-256, AES-GCM |
| **Audited Libraries** | Uses `@noble/curves`, `@noble/hashes`, `hash-wasm` |
| **Password Validation** | Stricter requirements: 12 chars, 40 bits entropy, blocks common passwords |
| **PIN Support** | Optional 4-8 digit PIN as third factor for key derivation |
| **Rate Limiting** | 5 attempts max, progressive delay (30s-5min) |
| **Secure Memory Wipe** | Sensitive buffers cleared after use |
| **Deterministic Recovery** | Can regenerate identity on any device with username/password/PIN |

### ⚠️ Weaknesses & Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **No Password Reset** | 🔴 High | Cannot be mitigated - by design |
| **Weak Password Vulnerability** | 🟡 Medium | Built-in password validation |
| **Password = Identity** | 🟡 Medium | Educate users: losing password = losing identity forever |

### Cryptographic Details

```
┌─────────────────────────────────────────────────────────────┐
│                    KEY DERIVATION FLOW                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Password + Username                                        │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────────────────────────────────────┐           │
│  │              ARGON2ID                        │           │
│  │  - Memory:      64 MB (memory-hard)         │           │
│  │  - Iterations:  4                            │           │
│  │  - Parallelism: 4 threads                    │           │
│  │  - Output:      256 bits                     │           │
│  └─────────────────────────────────────────────┘           │
│         │                                                   │
│         ▼                                                   │
│     Master Key (256 bits)                                   │
│         │                                                   │
│    ┌────┴────┐                                             │
│    ▼         ▼                                             │
│  ┌─────┐  ┌─────┐                                          │
│  │HKDF │  │HKDF │   (Domain Separation)                    │
│  │sign │  │enc  │                                          │
│  └─────┘  └─────┘                                          │
│    │         │                                              │
│    ▼         ▼                                              │
│  Signing   Encryption                                       │
│  Private   Private                                          │
│  Key       Key                                              │
│    │         │                                              │
│    ▼         ▼                                              │
│  ┌─────────────────┐                                       │
│  │    P-256 ECDSA  │  (NIST standard curve)                │
│  │    P-256 ECDH   │  (128-bit security level)             │
│  └─────────────────┘                                       │
│         │                                                   │
│         ▼                                                   │
│  SEA Pair { pub, priv, epub, epriv }                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why Argon2id over PBKDF2?

| Aspect | PBKDF2 (v1) | Argon2id (v2) |
|--------|-------------|---------------|
| **GPU Resistance** | ❌ Weak | ✅ Strong (memory-hard) |
| **ASIC Resistance** | ❌ Weak | ✅ Strong |
| **Memory Usage** | ~0 MB | 64 MB |
| **Modern Standard** | ❌ 2000 | ✅ 2015 (PHC winner) |

---

## ⚠️ Important Warnings

> [!CAUTION]
> **NO PASSWORD RECOVERY**: If you forget your password, your identity is **permanently lost**. There is no "forgot password" feature. This is a fundamental property of deterministic key derivation, not a bug.

> [!WARNING]
> **BREAKING CHANGE v3**: This version uses different salt format than v2. Users from v2 cannot login with the same credentials - they will get a different key pair.

> [!WARNING]
> **PASSWORD STRENGTH IS CRITICAL**: Built-in validation requires minimum **12 characters** with 40 bits entropy. It also blocks common passwords and repetitive patterns. Disable with `opt.skipValidation = true` (not recommended).

> [!TIP]
> **NEW: PIN SUPPORT**: Add an optional PIN (4-8 digits) for stronger security: `gun.user().auth(user, pass, cb, { pin: "1234" })`

> [!IMPORTANT]
> **PASSWORD CHANGE = NEW IDENTITY**: Changing your password creates a completely different public key. You would need to migrate all your data to a new user identity.

---

## 📦 Installation

### Option 1: NPM (Node.js / Bundlers)

```bash
npm install gun gun-authd
```

### Option 2: Browser (CDN)

Configure an **importmap** to resolve the `gun` module specifier:

```html
<!-- Load Gun and SEA first -->
<script src="https://cdn.jsdelivr.net/npm/gun/gun.js"></script>
<script src="https://cdn.jsdelivr.net/npm/gun/sea.js"></script>

<!-- Configure importmap to resolve 'gun' module specifier -->
<script type="importmap">
{
    "imports": {
        "gun": "data:text/javascript;charset=utf-8,export default window.Gun;",
        "gun/sea.js": "data:text/javascript;charset=utf-8,export default window.SEA;"
    }
}
</script>

<!-- Now import gun-authd -->
<script type="module">
    import "https://cdn.jsdelivr.net/npm/gun-authd/dist/gun-authd.min.js";
    
    const gun = Gun({
        peers: ['https://your-relay.com/gun']
    });
    
    gun.user().auth("username", "MyStr0ng!Password#2024", (ack) => {
        if (ack.err) {
            console.error("Auth failed:", ack.err);
            return;
        }
        console.log("Logged in as:", ack.alias);
    });
</script>
```

**Important:** The `importmap` must be defined **before** any `<script type="module">` that imports `gun-authd`.

---

## 🚀 Usage

`gun-authd` extends GunDB's native `gun.user().auth()` method to support deterministic authentication.

### Basic Usage

```javascript
import Gun from "gun";
import "gun/sea";
import "gun-authd"; // Import the extension - auto-mounts to Gun

const gun = Gun();

const username = "alice";
const password = "correct-horse-battery-staple!"; // Use strong passwords!

// Use the standard GunDB API - now with deterministic auth!
gun.user().auth(username, password, (ack) => {
    if (ack.err) {
        console.error("Authentication failed:", ack.err);
        return;
    }

    // Success!
    console.log("Logged in as:", ack.alias);
    console.log("Public Key:", ack.pub);
    console.log("SEA Pair:", ack.sea);
    
    // You can now write to the graph
    gun.user().get('status').put("I am fully deterministic!");
});
```

### Authentication with PIN (v3 Feature)

Add a PIN for three-factor key derivation:

```javascript
// With optional PIN (4-8 digits)
gun.user().auth(username, password, (ack) => {
    if (ack.err) {
        console.error("Auth failed:", ack.err);
        return;
    }
    console.log("Logged in with PIN!", ack.alias);
}, { pin: "1234" });

// The same username/password WITHOUT the PIN creates a DIFFERENT identity!
// This is by design - the PIN is part of the key derivation.
```

> ⚠️ **Important:** If a user authenticates with a PIN, they MUST use the same PIN every time. Different PIN = different identity.
```

### Debug Mode

Enable debug logging to see what's happening:

```javascript
// Option 1: Via auth options
gun.user().auth(username, password, callback, { debug: true });

// Option 2: Via Gun.authd namespace
Gun.authd.enableDebug(true);
gun.user().auth(username, password, callback);

// Option 3: Via ES module import
import { enableDebug } from "gun-authd";
enableDebug(true);
```

### Verify Password (Without Full Auth)

Useful for UI validation before committing to auth:

```javascript
// Check if password matches stored public key
const isValid = await gun.verifyPassword(storedPub, "alice", "password!");

if (isValid) {
    // Proceed with auth
    gun.user().auth("alice", "password!", callback);
} else {
    console.error("Wrong password");
}
```

### Username Protection & Account Security

**gun-authd** automatically protects existing usernames from unauthorized access:

* **Existing Username Check:** Before authenticating, `gun-authd` checks if the username already exists in the graph.
* **Password Verification:** If the username exists, it verifies that the provided password generates the same public key as the existing account.
* **Access Denied:** If the password doesn't match, authentication fails with error: `"Wrong password for this username"`.
* **New Account Creation:** If the username doesn't exist, a new account is created automatically.

This prevents:
- Unauthorized access attempts to existing accounts
- Accidental account overwrites
- Security vulnerabilities from weak password reuse

> [!NOTE]
> **Alias Check Limitation:** The alias collision detection requires either local cache (`radata`) or a responsive relay. On a fresh device with a slow/unresponsive relay, the check may timeout and proceed with registration. For best results, ensure your relay has persistence enabled.

**Example:**

```javascript
// First time - creates new account
gun.user().auth("alice", "password123", (ack) => {
    console.log("Account created:", ack.pub);
});

// Later - correct password, login succeeds
gun.user().auth("alice", "password123", (ack) => {
    console.log("Login successful:", ack.alias);
});

// Wrong password - access denied
gun.user().auth("alice", "wrong-password", (ack) => {
    if (ack.err) {
        console.error(ack.err); // "Wrong password for this username"
    }
});
```

### Disable Password Validation

If you want to handle password validation yourself:

```javascript
gun.user().auth(username, password, callback, { skipValidation: true });
```

### Using Legacy `.authd()` Method

For backward compatibility:

```javascript
gun.authd(username, password, (ack) => {
    if (ack.err) {
        console.error("Authentication failed:", ack.err);
        return;
    }
    console.log("Logged in as:", ack.alias);
});
```

---

## 📚 API Reference

### Gun Chain Methods (Auto-mounted)

| Method | Description |
|--------|-------------|
| `gun.user().auth(username, password, cb, opt)` | Deterministic authentication (overrides standard) |
| `gun.authd(username, password, cb, opt)` | Legacy convenience method |
| `gun.verifyPassword(pub, username, password)` | Verify password without full auth |

### Auth Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pin` | string | `null` | Optional PIN (4-8 digits) for three-factor auth |
| `skipValidation` | boolean | `false` | Skip password strength validation |
| `skipPinValidation` | boolean | `false` | Skip PIN format validation |
| `skipRateLimit` | boolean | `false` | Skip rate limiting check |
| `debug` | boolean | `false` | Enable debug logging |
| `remember` | boolean | `false` | Store pair in sessionStorage |

### Gun.authd Namespace

Access utilities directly via `Gun.authd`:

```javascript
console.log(Gun.authd.version);  // "3.0.0"
console.log(Gun.authd.config);   // { argon2, password, pin, rateLimit }

// Generate pair directly (with optional PIN)
const pair = await Gun.authd.generatePair("alice", "strongPassword!");
const pairWithPin = await Gun.authd.generatePair("alice", "strongPassword!", "1234");

// Validate password strength
try {
    Gun.authd.validatePassword("weak");
} catch (e) {
    console.error(e.message); // "Password must be at least 12 characters"
}

// Validate PIN format
try {
    Gun.authd.validatePin("1234"); // OK
    Gun.authd.validatePin("0000"); // Throws - too simple
} catch (e) {
    console.error(e.message);
}

// Check/reset rate limit
try {
    Gun.authd.checkRateLimit("alice");
} catch (e) {
    console.error(e.message); // "Too many attempts..."
}
Gun.authd.resetRateLimit("alice"); // Clear on success

// Verify password with optional PIN
const isValid = await Gun.authd.verifyPassword(storedPub, "alice", "password!", "1234");

// Enable debug
Gun.authd.enableDebug(true);
```

### ES Module Exports

```javascript
import { 
    generateDeterministicPair,
    validatePasswordStrength,
    validatePin,
    verifyPassword,
    checkRateLimit,
    resetRateLimit,
    enableDebug,
    secureWipe,
    ARGON2_CONFIG,
    PASSWORD_CONFIG,
    PIN_CONFIG,
    RATE_LIMIT_CONFIG,
    GunAuthd  // default export with all utilities
} from "gun-authd";

// Generate pair programmatically (with optional PIN)
const pair = await generateDeterministicPair("alice", "strongPassword123!");
const pairWithPin = await generateDeterministicPair("alice", "strongPassword123!", "1234");
console.log(pair.pub);  // Public key
console.log(pair.priv); // Private key (keep secret!)
```

---

## 📘 TypeScript Support

Full TypeScript support is included:

```typescript
import Gun from "gun";
import "gun-authd";
import type { SEAPair } from "gun-authd";

const gun = Gun();

// Types are inferred
gun.user().auth("alice", "password!", (ack) => {
    if (ack.err) return;
    const pair: SEAPair = ack.sea;
    console.log(pair.pub);
});

// Direct import with types
import { generateDeterministicPair, ARGON2_CONFIG } from "gun-authd";

const pair: SEAPair = await generateDeterministicPair("alice", "password!");
console.log(ARGON2_CONFIG.memorySize); // 65536 (64 MB)
```

---

## 🧪 Testing

Run the unit tests:

```bash
npm test
```

Tests cover:
- ✅ Determinism (same input = same output)
- ✅ Uniqueness (different input = different output)
- ✅ Key format validation
- ✅ Domain separation (signing ≠ encryption keys)
- ✅ Password verification
- ✅ String normalization (whitespace, unicode NFC)

---

## ⚙️ How it works (Under the Hood)

### 1. Argon2id Key Derivation

Takes the `password` and derives a master key using Argon2id:

```javascript
const ARGON2_CONFIG = {
  parallelism: 4,      // 4 parallel threads
  iterations: 4,       // Time cost (increased in v3)
  memorySize: 65536,   // 64 MB memory
  hashLength: 32,      // 256-bit output
};

const PASSWORD_CONFIG = {
  minLength: 12,       // Minimum password length
  minEntropy: 40,      // Minimum entropy bits
};

const PIN_CONFIG = {
  minLength: 4,
  maxLength: 8,
  pattern: /^\d+$/,    // Digits only
};

const RATE_LIMIT_CONFIG = {
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
  baseDelayMs: 30 * 1000,   // 30 seconds
  maxDelayMs: 5 * 60 * 1000,// 5 minutes
};
```

### 2. HKDF Domain Separation

The master key is expanded using HKDF to derive separate keys:

```javascript
signingKey    = HKDF(masterKey, "signing-key")
encryptionKey = HKDF(masterKey, "encryption-key")
```

This ensures that even if one key is compromised, the other remains secure.

### 3. P-256 Key Generation

The derived keys are used as private key scalars for P-256 curves:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| **Sign Keys** | ECDSA P-256 | Signing data, proving identity |
| **Encrypt Keys** | ECDH P-256 | Deriving shared secrets for encryption |

### 4. Username Protection & Verification

Before authenticating, `gun-authd` performs a security check:

1. **Check Username Existence:** Queries the `~@username` node to see if the username is already registered
2. **Password Verification:** If username exists, generates the deterministic pair and compares the public key:
   - ✅ **Match:** Password is correct, proceed with authentication
   - ❌ **Mismatch:** Password is wrong, return error `"Wrong password for this username"`
3. **New Account:** If username doesn't exist, creates a new account automatically

This prevents:
- Unauthorized access to existing accounts
- Accidental account overwrites
- Security vulnerabilities from password reuse

### 5. Graph Registration

When authentication succeeds:

1. `~@username` is linked to `~your_public_key` (alias index) - only if new account
2. User node is populated with `pub` and `epub` keys
3. Other users can now discover you and send encrypted messages

---

## ⏱️ Performance

Approximate key derivation times:

| Device | Time |
|--------|------|
| Desktop (8GB+ RAM) | ~200-400ms |
| Laptop (4GB RAM) | ~400-600ms |
| Mobile (modern) | ~500-800ms |
| Low-end device | ~1-2s |

The majority of time is spent in Argon2id (intentionally slow for security).

---

## ⚠️ Important Trade-offs

| Standard Gun Auth | gun-authd v3 |
|-------------------|--------------|
| ✅ Random salt protects weak passwords | ⚠️ Stricter validation + optional PIN |
| ✅ Password can be changed | ❌ Password/PIN change = new identity |
| ❌ Requires network to login | ✅ Fully offline login |
| ❌ Salt can be censored | ✅ No censorship point |
| ❌ Salt loss = identity loss | ✅ Identity always recoverable |
| ❌ PBKDF2 vulnerable to GPU | ✅ Argon2id memory-hard |
| ❌ No brute-force protection | ✅ Rate limiting built-in |

---

## 👥 Who Should Use This

### ✅ Recommended For

- **Crypto-native applications** where users already manage seed phrases
- **Mesh networks / offline-first** systems
- **Censorship-resistant** platforms
- **Developer tools** and technical user bases
- **Decentralized identity** (DID) systems
- **IoT devices** that may have intermittent connectivity

### ❌ NOT Recommended For

- Consumer apps with mainstream users who expect "forgot password"
- Systems where password reset is a legal/compliance requirement
- Applications where users frequently change credentials
- Children's apps or accessibility-focused platforms

---

## 🛠 Dependencies

| Package | Purpose |
|---------|---------|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | P-256 elliptic curve operations |
| [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) | SHA-256, HKDF |
| [`hash-wasm`](https://github.com/nicoth-in/wasm-hash) | Argon2id (WebAssembly) |

These libraries are:
- ✅ Audited by security firms
- ✅ Used in production by major projects
- ✅ Zero/minimal dependencies
- ✅ Browser and Node.js compatible

---

## 🔄 Migration

### From v2 to v3

> [!WARNING]
> v3 uses a different salt format. This is a **breaking change**.

If you have existing v2 users, they will need to create new accounts. The same username/password will generate a **different** key pair in v3.

**There is no migration path** - this is by design, as the whole point of deterministic auth is that the keys are derived purely from the credentials.

### From v1 to v3

Same as above - v1 users will need new accounts.

---

## 📄 License

MIT

---

## 🤝 Contributing

Issues and PRs welcome! Please ensure any cryptographic changes are well-reasoned and don't reduce the security guarantees.

```bash
# Run tests
npm test

# Build
npm run build
```

---

## 📚 Related Projects

- [GunDB](https://github.com/amark/gun) - The decentralized database this extends
- [SEA](https://gun.eco/docs/SEA) - Security, Encryption, Authorization module for Gun
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password Hashing Competition winner