# gun-authd: Deterministic Authentication for GunDB

**gun-authd** is a specialized extension for [GunDB](https://gun.eco/) that enables purely deterministic user authentication.

It allows users to generate their SEA (Security, Encryption, Authorization) key pairs locally based solely on their username and password, **without needing to fetch a random salt from the network**.

> 🚀 **Why this matters:** This enables true **offline-first login** on new devices. If you know your username and password, you can recover your identity instantly, even if the relay node holding your metadata is down or unreachable.

---

## 📋 Table of Contents

- [The Problem](#-the-problem-with-standard-gun-auth)
- [The Solution](#-the-gun-authd-solution)
- [Security Assessment](#-security-assessment)
- [Installation](#-installation)
- [Usage](#-usage)
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

**gun-authd** removes the random salt. Instead, it uses **PBKDF2** (Username + Password) to mathematically derive your keys.

* **Zero Lookup:** Login is instant. No network request needed to "find" the user first.
* **Deterministic:** `Username` + `Password` will *always* generate the exact same Private Key.
* **Graph Compatible:** It manually handles the `~@alias` -> `~pubkey` linking, so your user is still discoverable by others in the Gun network.

---

## 🛡️ Security Assessment

### ✅ Strengths

| Aspect | Details |
|--------|---------|
| **Offline-First** | Full authentication without network access |
| **Censorship Resistant** | No central salt storage = no censorship point |
| **Strong KDF** | PBKDF2 with **300,000 iterations** (computationally expensive to brute-force) |
| **Standard Cryptography** | ECDSA/ECDH P-256 (NIST curves), SHA-256, AES-GCM |
| **Audited Libraries** | Uses `@noble/curves` by Paul Miller (widely audited) |
| **Deterministic Recovery** | Can regenerate identity on any device with just username/password |

### ⚠️ Weaknesses & Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **No Password Reset** | 🔴 High | Cannot be mitigated - by design |
| **Rainbow Table Attacks** | 🟡 Medium | 300k PBKDF2 iterations make precomputation expensive |
| **Weak Password Vulnerability** | 🟡 Medium | Enforce strong passwords in your application |
| **Password = Identity** | 🟡 Medium | Educate users: losing password = losing identity forever |

### Cryptographic Details

```javascript
// Key Derivation Function
PBKDF2-HMAC-SHA256
  - Iterations: 300,000 (high cost factor)
  - Output: 256 bits

// Signing Keys (for data signatures)
ECDSA P-256 (secp256r1)
  - NIST standard curve
  - 128-bit security level

// Encryption Keys (for private data)
ECDH P-256 + AES-256-GCM
  - Authenticated encryption
  - Forward secrecy capable
```

---

## ⚠️ Important Warnings

> [!CAUTION]
> **NO PASSWORD RECOVERY**: If you forget your password, your identity is **permanently lost**. There is no "forgot password" feature. This is a fundamental property of deterministic key derivation, not a bug.

> [!WARNING]
> **PASSWORD STRENGTH IS CRITICAL**: Since there is no random salt protecting against rainbow tables, weak passwords like `123456` or `password` are extremely vulnerable. Enforce minimum password requirements in your application.

> [!WARNING]
> **PASSWORD CHANGE = NEW IDENTITY**: Changing your password creates a completely different public key. You would need to migrate all your data to a new user identity.

> [!IMPORTANT]
> **This is NOT a drop-in replacement for all use cases.** Standard Gun auth with random salt is still more appropriate for consumer applications where users expect password reset functionality.

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
    
    gun.user().auth("username", "strong-password-here", (ack) => {
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

`gun-authd` extends GunDB's native `gun.user().auth()` method to support deterministic authentication. You can use the standard GunDB API directly, or use the convenience method `.authd()`.

### Method 1: Using `gun.user().auth()` (Recommended)

After importing `gun-authd`, the native `gun.user().auth()` method automatically supports deterministic authentication when called with username and password:

```javascript
import Gun from "gun";
import "gun/sea";
import "gun-authd"; // Import the extension

const gun = Gun();

const username = "alice";
const password = "correct-horse-battery-staple"; // Use strong passwords!

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

**Note:** If you pass a complete SEA pair (with `priv` and `epriv`), `gun.user().auth()` will use the original GunDB authentication method, maintaining full compatibility.

### Method 2: Using `gun.authd()` (Legacy/Convenience)

For backward compatibility, you can also use the `.authd()` convenience method:

```javascript
// usage: gun.authd(username, password, callback)
gun.authd(username, password, (ack) => {
    if (ack.err) {
        console.error("Authentication failed:", ack.err);
        return;
    }

    // Success!
    console.log("Logged in as:", ack.alias);
    console.log("SEA Pair:", ack.sea);
});
```

---

## ⚙️ How it works (Under the Hood)

### 1. Entropy Generation

Takes the `username` and `password`, normalizes them (NFC, trimmed), and runs them through **PBKDF2-HMAC-SHA256** with **300,000 iterations**.

```
Input:  password || username (concatenated bytes)
Salt:   "signing-v1" or "encryption-v1" (domain separation)
Output: 256-bit deterministic entropy
```

### 2. Key Derivation

The resulting entropy is used as a private key seed:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| **Sign Keys** | ECDSA P-256 | Signing data, proving identity |
| **Encrypt Keys** | ECDH P-256 | Deriving shared secrets for encryption |

### 3. Graph Registration

When you call `gun.user().auth()`:

1. `~@username` is linked to `~your_public_key` (alias index)
2. User node is populated with `pub` and `epub` keys
3. Other users can now discover you and send encrypted messages

All of this happens transparently - you just use `gun.user().auth()` as you normally would!

---

## ⚠️ Important Trade-offs

| Standard Gun Auth | gun-authd |
|-------------------|-----------|
| ✅ Random salt protects weak passwords | ❌ No salt = weak passwords more vulnerable |
| ✅ Password can be changed | ❌ Password change = new identity |
| ❌ Requires network to login | ✅ Fully offline login |
| ❌ Salt can be censored | ✅ No censorship point |
| ❌ Salt loss = identity loss | ✅ Identity always recoverable |

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

This project relies on the robust cryptography libraries from [Paul Miller](https://github.com/paulmillr):

* [`@noble/curves`](https://github.com/paulmillr/noble-curves) - P-256 elliptic curve operations
* [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) - SHA-256, HMAC (used internally)

These libraries are:
- ✅ Audited by multiple security firms
- ✅ Used in production by major blockchain projects
- ✅ Zero dependencies themselves
- ✅ TypeScript native

---

## 📄 License

MIT

---

## 🤝 Contributing

Issues and PRs welcome! Please ensure any cryptographic changes are well-reasoned and don't reduce the security guarantees.

## 📚 Related Projects

- [GunDB](https://github.com/amark/gun) - The decentralized database this extends
- [SEA](https://gun.eco/docs/SEA) - Security, Encryption, Authorization module for Gun