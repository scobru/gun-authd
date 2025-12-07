# gun-authd: Deterministic Authentication for GunDB

**gun-authd** is a specialized extension for [GunDB](https://gun.eco/) that enables purely deterministic user authentication. 

It allows users to generate their SEA (Security, Encryption, Authorization) key pairs locally based solely on their username and password, **without needing to fetch a random salt from the network**.

> 🚀 **Why this matters:** This enables true **offline-first login** on new devices. If you know your username and password, you can recover your identity instantly, even if the relay node holding your metadata is down or unreachable.

---

## 🚨 The Problem with Standard Gun Auth

By default, `gun.user().create()` works like this:
1.  Generates a random cryptographic **salt**.
2.  Stores this salt publicly in the graph.
3.  To log in (`.auth()`), the client must first **download** this salt to verify the password.

**The Drawbacks:**
* **Network Dependency:** You cannot log in on a fresh device without internet access or peer connectivity.
* **Censorship Risk:** If a node blocks access to your salt data, you cannot compute your keys to log in.

## ✅ The gun-authd Solution

**gun-authd** removes the random salt. Instead, it uses **PBKDF2** (User + Password) to mathematically derive your keys.

* **Zero Lookup:** Login is instant. No network request needed to "find" the user first.
* **Deterministic:** `User` + `Password` will *always* generate the exact same Private Key.
* **Graph Compatible:** It manually handles the `~@alias` -> `~pubkey` linking, so your user is still discoverable by others in the Gun network.

---

## 📦 Installation

### Option 1: NPM (Node.js / Bundlers)
First, install the package and the required crypto dependencies:

```bash
npm install gun gun-authd
```

### Option 2: Browser (CDN)
If you are using it directly in the browser via ES Modules, you need to configure an **importmap** to resolve the `gun` module specifier. This is required because `gun-authd` uses ES6 imports that reference `gun` and `gun/sea.js`, which need to be mapped to the global `window.Gun` and `window.SEA` objects.

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
    
    // Your code here
    const gun = Gun({
        peers: ['https://your-relay.com/gun']
    });
    
    gun.user().auth("username", "password", (ack) => {
        if (ack.err) {
            console.error("Auth failed:", ack.err);
            return;
        }
        console.log("Logged in as:", ack.alias);
    });
</script>
```

**Important:** The `importmap` must be defined **before** any `<script type="module">` that imports `gun-authd`. This allows the browser to resolve the `gun` and `gun/sea.js` module specifiers correctly.

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
const password = "correct-horse-battery-staple";

// Use the standard GunDB API - now with deterministic auth!
gun.user().auth(username, password, (ack) => {
    if (ack.err) {
        console.error("Authentication failed:", ack.err);
        return;
    }

    // Success!
    console.log("Logged in as:", ack.alias);
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

**Note:** `gun.authd()` is just a convenience wrapper that calls `gun.user().auth()` internally.

---

## ⚙️ How it works (Under the Hood)

1.  **Entropy Generation:** It takes the `username` and `password`, normalizes them, and runs them through **PBKDF2-HMAC-SHA256** with **300,000 iterations**. This makes brute-forcing computationally expensive.
    
2.  **Key Derivation:**
    The resulting entropy is used to seed the generation of:
    * **Sign Keys:** ECDSA (P-256) for signing data.
    * **Encrypt Keys:** ECDH for encrypting data.

3.  **Graph Registration:**
    Standard Gun `create()` uses random keys. `gun-authd` bypasses this by automatically handling the graph registration when you call `gun.user().auth()`:
    * `~@username` points to `~your_public_key`.
    * Populates the user node with `pub` and `epub` keys so other users can send encrypted messages.
    * All of this happens transparently - you just use `gun.user().auth()` as you normally would!

---

## ⚠️ Important Trade-offs

Because the keys are mathematically derived directly from the password:

1.  **NO Password Reset:** You cannot change your password. Changing the password results in a completely different Public Key (a new identity). To "change" a password, you must migrate your data to a new user.
2.  **Password Strength:** Since there is no random salt to protect against pre-computed Rainbow Tables (globally), users should be encouraged to use **strong, unique passwords**. (However, the 300k PBKDF2 iterations provide significant protection against brute force).

---

## 🛠 Dependencies

This project relies on the robust cryptography libraries from [Paul Miller](https://github.com/paulmillr):
* `@noble/curves` (P-256, secp256k1)
* `@noble/hashes` (SHA256, HMAC)

---

## License

MIT