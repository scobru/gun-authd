import Gun from "gun";
import "gun/sea.js";
import { p256 } from "@noble/curves/p256";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { argon2id } from "hash-wasm";

// --- CONFIGURATION ---
const ARGON2_CONFIG = {
  parallelism: 4,      // Number of parallel threads
  iterations: 4,       // Time cost (higher = slower but more secure) - increased from 3
  memorySize: 65536,   // Memory in KB (64 MB) - memory-hard protection
  hashLength: 32,      // Output 256 bits
};

const KEY_VERSION = "v3"; // Version identifier for key derivation (v3 = with PIN support)
const LIB_VERSION = "3.0.0";

// Password validation config
const PASSWORD_CONFIG = {
  minLength: 12,       // Minimum password length (increased from 8)
  minEntropy: 40,      // Minimum entropy bits (increased from 28)
};

// PIN validation config  
const PIN_CONFIG = {
  minLength: 4,
  maxLength: 8,
  pattern: /^\d+$/,    // Only digits allowed
};

// Rate limiting config
const RATE_LIMIT_CONFIG = {
  maxAttempts: 5,           // Max attempts before lockout
  windowMs: 15 * 60 * 1000, // 15 minute window
  baseDelayMs: 30 * 1000,   // 30 second base delay
  maxDelayMs: 5 * 60 * 1000,// 5 minute max delay
};

// Common passwords to block (lowercase)
const COMMON_PASSWORDS = new Set([
  'password123', 'password1234', '12345678', '123456789', '1234567890',
  'qwerty1234', 'qwertyuiop', 'letmein123', 'welcome123', 'monkey1234',
  'dragon1234', 'master1234', 'iloveyou12', 'trustno123', 'sunshine12',
  'princess12', 'football12', 'baseball12', 'shadow1234', 'michael123',
  'password!1', 'passw0rd12', 'p@ssword12', 'admin12345', 'root123456',
]);

// --- HELPERS ---
const TEXT_ENCODER = new TextEncoder();

function normalizeString(str) {
  return str.normalize("NFC").trim();
}

/**
 * Convert bytes to base64url format (RFC 4648)
 * This matches the format used by Web Crypto JWK export in Gun SEA
 * @param {Uint8Array|ArrayBuffer} buf - The bytes to encode
 * @returns {string} Base64url encoded string
 */
function arrayBufToBase64UrlEncode(buf) {
  const bytes = new Uint8Array(buf);
  // Use a chunk-based approach for large arrays to avoid stack overflow
  let binary = '';
  const chunkSize = 0x8000; // 32KB chunks
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode.apply(null, chunk);
  }
  // Convert to base64, then to base64url format
  // Order: + → - , / → _ , remove padding =
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}


function keyBufferToJwk(publicKeyBuffer) {
  if (publicKeyBuffer[0] !== 4) throw new Error("Invalid public key format");
  return [
    arrayBufToBase64UrlEncode(publicKeyBuffer.slice(1, 33)),
    arrayBufToBase64UrlEncode(publicKeyBuffer.slice(33, 65)),
  ].join(".");
}

// --- DEBUG LOGGING ---
let debugEnabled = false;

function debugLog(...args) {
  if (debugEnabled) {
    console.log("[gun-authd]", ...args);
  }
}

function enableDebug(enable = true) {
  debugEnabled = enable;
}

// --- KEY DERIVATION (Argon2id + HKDF) ---

/**
 * Derives a key using Argon2id (memory-hard KDF)
 * Much more resistant to GPU/ASIC attacks than PBKDF2
 */
async function argon2Derive(password, salt) {
  debugLog("Running Argon2id with config:", ARGON2_CONFIG);
  const startTime = Date.now();
  
  const hash = await argon2id({
    password: password,
    salt: salt,
    parallelism: ARGON2_CONFIG.parallelism,
    iterations: ARGON2_CONFIG.iterations,
    memorySize: ARGON2_CONFIG.memorySize,
    hashLength: ARGON2_CONFIG.hashLength,
    outputType: "binary",
  });
  
  debugLog(`Argon2id completed in ${Date.now() - startTime}ms`);
  return new Uint8Array(hash);
}

/**
 * Expands key material using HKDF for domain separation
 * This ensures signing and encryption keys are cryptographically independent
 */
function hkdfExpand(ikm, info, length = 32) {
  const salt = TEXT_ENCODER.encode(`gun-authd-${KEY_VERSION}`);
  return hkdf(sha256, ikm, salt, info, length);
}

// --- SECURE MEMORY WIPE ---

/**
 * Securely wipes a buffer by overwriting with random data then zeros
 * Helps prevent memory side-channel attacks
 * @param {Uint8Array} buffer - Buffer to wipe
 */
function secureWipe(buffer) {
  if (buffer instanceof Uint8Array && buffer.length > 0) {
    try {
      // First pass: overwrite with random data
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(buffer);
      }
      // Second pass: fill with zeros
      buffer.fill(0);
    } catch (e) {
      // Fallback: just fill with zeros
      buffer.fill(0);
    }
  }
}

// --- KEY GENERATION ---

/**
 * Generates a deterministic SEA key pair from username, password, and optional PIN
 * @param {string} username - The username
 * @param {string} password - The password
 * @param {string|null} pin - Optional PIN (4-8 digits) for additional security
 * @returns {Promise<{pub: string, priv: string, epub: string, epriv: string}>}
 */
async function generateDeterministicPair(username, password, pin = null) {
  debugLog("Generating pair for:", username, pin ? "(with PIN)" : "(no PIN)");
  
  const normalizedUser = normalizeString(username);
  const normalizedPass = normalizeString(password);
  const normalizedPin = pin ? normalizeString(pin) : "";
  
  // Combine password and username for Argon2 input
  const passwordBytes = TEXT_ENCODER.encode(normalizedPass);
  
  // Build salt: include PIN if provided (this makes keys unique per PIN)
  // Format: gun-authd-v3-salt-{username}[-pin-{pin}]
  const saltSuffix = normalizedPin ? `-pin-${normalizedPin}` : "";
  const argonSalt = TEXT_ENCODER.encode(`gun-authd-${KEY_VERSION}-salt-${normalizedUser}${saltSuffix}`);
  
  // Track buffers for secure cleanup
  let masterKey = null;
  let signingPrivateKey = null;
  let encryptionPrivateKey = null;
  
  try {
    // Derive master key using Argon2id (memory-hard)
    masterKey = await argon2Derive(passwordBytes, argonSalt);
    
    // Use HKDF to derive separate keys for signing and encryption
    const signingInfo = TEXT_ENCODER.encode("signing-key");
    const encryptionInfo = TEXT_ENCODER.encode("encryption-key");
    
    signingPrivateKey = hkdfExpand(masterKey, signingInfo, 32);
    encryptionPrivateKey = hkdfExpand(masterKey, encryptionInfo, 32);
    
    // Generate P-256 public keys from private keys
    const signingPublicKey = p256.getPublicKey(signingPrivateKey, false);
    const encryptionPublicKey = p256.getPublicKey(encryptionPrivateKey, false);
    
    const pair = {
      pub: keyBufferToJwk(signingPublicKey),
      priv: arrayBufToBase64UrlEncode(signingPrivateKey),
      epub: keyBufferToJwk(encryptionPublicKey),
      epriv: arrayBufToBase64UrlEncode(encryptionPrivateKey),
    };
    
    debugLog("Generated pub:", pair.pub.slice(0, 20) + "...");
    return pair;
  } finally {
    // Secure cleanup of sensitive key material
    if (masterKey) secureWipe(masterKey);
    if (signingPrivateKey) secureWipe(signingPrivateKey);
    if (encryptionPrivateKey) secureWipe(encryptionPrivateKey);
  }
}

// --- PASSWORD VALIDATION ---

/**
 * Validates password strength with stricter requirements
 * @param {string} password - The password to validate
 * @returns {boolean} - True if valid
 * @throws {Error} - If password is too weak
 */
function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') {
    throw new Error("Password must be a non-empty string");
  }
  
  // Check minimum length
  if (password.length < PASSWORD_CONFIG.minLength) {
    throw new Error(`Password must be at least ${PASSWORD_CONFIG.minLength} characters`);
  }
  
  // Check for common passwords
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    throw new Error("This password is too common. Please choose a unique password.");
  }
  
  // Check for repetitive patterns (e.g., "aaaa" or "1111")
  if (/(.)\1{3,}/.test(password)) {
    throw new Error("Password contains too many repeated characters.");
  }
  
  // Check for sequential patterns
  if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
    throw new Error("Password contains sequential characters. Mix it up more.");
  }
  
  // Calculate entropy estimate
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);
  
  const charsetSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + 
                      (hasNumber ? 10 : 0) + (hasSpecial ? 32 : 0);
  const entropy = password.length * Math.log2(charsetSize || 1);
  
  if (entropy < PASSWORD_CONFIG.minEntropy) {
    throw new Error("Password is too weak. Use a longer password with letters, numbers, and symbols.");
  }
  
  return true;
}

/**
 * Validates PIN format
 * @param {string} pin - The PIN to validate
 * @returns {boolean} - True if valid
 * @throws {Error} - If PIN format is invalid
 */
function validatePin(pin) {
  if (!pin || typeof pin !== 'string') {
    throw new Error("PIN must be a non-empty string");
  }
  
  const trimmedPin = pin.trim();
  
  if (trimmedPin.length < PIN_CONFIG.minLength) {
    throw new Error(`PIN must be at least ${PIN_CONFIG.minLength} digits`);
  }
  
  if (trimmedPin.length > PIN_CONFIG.maxLength) {
    throw new Error(`PIN must be at most ${PIN_CONFIG.maxLength} digits`);
  }
  
  if (!PIN_CONFIG.pattern.test(trimmedPin)) {
    throw new Error("PIN must contain only digits (0-9)");
  }
  
  // Block obvious PINs
  const obviousPins = ['0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
                       '1234', '4321', '0123', '9876', '1212', '2020', '1111', '0000'];
  if (obviousPins.includes(trimmedPin)) {
    throw new Error("PIN is too simple. Please choose a less obvious PIN.");
  }
  
  return true;
}

// --- RATE LIMITING ---

const rateLimitStore = new Map(); // { alias: { count, lastAttempt, lockedUntil } }

/**
 * Checks rate limit for an alias and throws if exceeded
 * @param {string} alias - The username/alias
 * @throws {Error} - If rate limit exceeded
 */
function checkRateLimit(alias) {
  const now = Date.now();
  const record = rateLimitStore.get(alias) || { count: 0, lastAttempt: 0, lockedUntil: 0 };
  
  // Check if currently locked
  if (record.lockedUntil > now) {
    const waitSeconds = Math.ceil((record.lockedUntil - now) / 1000);
    throw new Error(`Too many attempts. Please wait ${waitSeconds} seconds before trying again.`);
  }
  
  // Reset if window expired
  if (now - record.lastAttempt > RATE_LIMIT_CONFIG.windowMs) {
    record.count = 0;
    record.lockedUntil = 0;
  }
  
  // Check if exceeded max attempts
  if (record.count >= RATE_LIMIT_CONFIG.maxAttempts) {
    // Calculate delay: increases with each lockout
    const lockoutMultiplier = Math.floor(record.count / RATE_LIMIT_CONFIG.maxAttempts);
    const delay = Math.min(
      RATE_LIMIT_CONFIG.baseDelayMs * lockoutMultiplier,
      RATE_LIMIT_CONFIG.maxDelayMs
    );
    record.lockedUntil = now + delay;
    rateLimitStore.set(alias, record);
    
    const waitSeconds = Math.ceil(delay / 1000);
    throw new Error(`Too many attempts. Please wait ${waitSeconds} seconds before trying again.`);
  }
  
  // Increment attempt counter
  record.count++;
  record.lastAttempt = now;
  rateLimitStore.set(alias, record);
}

/**
 * Resets rate limit for an alias (on successful auth)
 * @param {string} alias - The username/alias
 */
function resetRateLimit(alias) {
  rateLimitStore.delete(alias);
}

/**
 * Verify if a password (and optional PIN) matches an expected public key
 * Useful for UI validation without full auth
 * @param {string} expectedPub - The expected public key
 * @param {string} username - The username
 * @param {string} password - The password to verify
 * @param {string|null} pin - Optional PIN
 * @returns {Promise<boolean>}
 */
async function verifyPassword(expectedPub, username, password, pin = null) {
  try {
    const pair = await generateDeterministicPair(username, password, pin);
    return pair.pub === expectedPub;
  } catch (e) {
    return false;
  }
}

// --- OVERRIDE GUN.USER().AUTH() ---

function parseAuthArgs(...args) {
  const pair = typeof args[0] === 'object' && (args[0].pub || args[0].epub) 
    ? args[0] 
    : typeof args[1] === 'object' && (args[1].pub || args[1].epub) 
      ? args[1] 
      : null;
  const alias = !pair && typeof args[0] === 'string' ? args[0] : null;
  const pass = (alias || (pair && !(pair.priv && pair.epriv))) && typeof args[1] === 'string' 
    ? args[1] 
    : null;
  const cb = args.filter(arg => typeof arg === 'function')[0] || null;
  const opt = args && args.length > 1 && typeof args[args.length-1] === 'object' && !args[args.length-1].pub 
    ? args[args.length-1] 
    : {};
  
  return { pair, alias, pass, cb, opt };
}

let originalAuth = null;
let overrideApplied = false;

function applyAuthOverride() {
  if (overrideApplied) return true;
  
  let GunObj, User;
  try {
    if (typeof Gun !== 'undefined') GunObj = Gun;
    else if (typeof window !== 'undefined' && window.Gun) GunObj = window.Gun;
    else if (typeof global !== 'undefined' && global.Gun) GunObj = global.Gun;
    else if (typeof globalThis !== 'undefined' && globalThis.Gun) GunObj = globalThis.Gun;
    
    if (GunObj && GunObj.User) {
      User = GunObj.User;
    }
  } catch(e) {
    // Silently ignore
  }
  
  if (!User || !User.prototype || !User.prototype.auth) {
    return false;
  }
  
  if (User.prototype.auth.__authdOverridden) {
    overrideApplied = true;
    return true;
  }
  
  originalAuth = User.prototype.auth;
  
  User.prototype.auth = function(...args) {
    const gun = this;
    const cat = gun._;
    const root = gun.back(-1);
    const noop = function(){};
    const Gun = User.GUN;
    
    const { pair, alias, pass, cb, opt } = parseAuthArgs(...args);
    
    // Enable debug if requested
    if (opt.debug) {
      enableDebug(true);
    }
    
    // If a complete pair is passed, use original method
    if (pair && pair.priv && pair.epriv) {
      debugLog("Using original auth (pair provided)");
      return originalAuth.call(this, ...args);
    }
    
    // If no alias/pass, use original method
    if (!alias || !pass) {
      debugLog("Using original auth (no alias/pass)");
      return originalAuth.call(this, ...args);
    }
    
    // Extract PIN from options (new feature)
    const pin = opt.pin || null;
    
    debugLog("Using deterministic auth for:", alias, pin ? "(with PIN)" : "(no PIN)");
    
    // Check rate limiting (unless disabled)
    if (!opt.skipRateLimit) {
      try {
        checkRateLimit(alias);
      } catch (e) {
        debugLog("Rate limit exceeded:", e.message);
        if (cb) cb({ err: e.message });
        return gun;
      }
    }
    
    // Check for concurrent calls
    if (cat.ing) {
      (cb || noop)({ err: Gun.log("User is already being created or authenticated!"), wait: true });
      return gun;
    }
    cat.ing = true;
    
    // Validate password strength (optional - can be disabled via opt.skipValidation)
    if (!opt.skipValidation) {
      try {
        validatePasswordStrength(pass);
      } catch (e) {
        cat.ing = false;
        debugLog("Password validation failed:", e.message);
        if (cb) cb({ err: e.message });
        return gun;
      }
    }
    
    // Validate PIN if provided (optional - can be disabled via opt.skipPinValidation)
    if (pin && !opt.skipPinValidation) {
      try {
        validatePin(pin);
      } catch (e) {
        cat.ing = false;
        debugLog("PIN validation failed:", e.message);
        if (cb) cb({ err: e.message });
        return gun;
      }
    }
    
    // Generate deterministic pair with optional PIN
    generateDeterministicPair(alias, pass, pin).then((deterministicPair) => {
      // Check if alias already exists in the network
      const aliasNode = root.get('~@' + alias);
      const userNode = root.get('~' + deterministicPair.pub);
      let checksDone = 0;
      let aliasExists = false;  // Explicit flag: does alias exist in network?
      let existingPub = null;    // Public key associated with existing alias
      let userNodeHasData = false;
      let checkTimeout = null;
      
      // Helper to proceed when all checks are done
      function checkComplete() {
        checksDone++;
        if (checksDone < 2) return; // Wait for both checks
        
        if (checkTimeout) clearTimeout(checkTimeout);
        
        // First check: Does the alias exist in the network?
        if (aliasExists) {
          // Alias exists - verify if it belongs to this user or another
          if (existingPub !== deterministicPair.pub) {
            // Alias exists but belongs to a different user (different credentials)
            cat.ing = false;
            const errorMsg = `Alias "${alias}" exists but credentials do not match. The alias may be registered with different credentials or belong to another user.`;
            debugLog(`Alias "${alias}" exists with pub ${existingPub?.substring(0, 20)}... but generated pub is ${deterministicPair.pub?.substring(0, 20)}...`);
            if (cb) cb({ err: errorMsg });
            return;
          }
          // Alias exists and belongs to this user - proceed with login
          debugLog("Alias exists and matches this user, proceeding with auth");
          proceedWithAuth(deterministicPair, existingPub);
        } else if (userNodeHasData) {
          // User node exists but alias index doesn't - user exists, just missing index
          debugLog("User node exists but alias index missing, proceeding with auth and writing index");
          proceedWithAuth(deterministicPair, null); // Pass null to write index
        } else {
          // Alias does not exist in network - create new account
          debugLog("Alias does not exist in network, creating new user");
          proceedWithAuth(deterministicPair, null);
        }
      }
      
      // Set timeout for alias check (5 seconds - increased for slow networks)
      checkTimeout = setTimeout(() => {
        if (checksDone < 2) {
          debugLog(`Alias check timeout reached for "${alias}" - proceeding without network confirmation`);
          checksDone = 2;
          checkComplete();
        }
      }, 5000);
      
      // Check if alias exists in the network (alias index)
      // Use .on() with unsubscribe to wait for network sync
      let aliasCheckAttempts = 0;
      const maxAliasCheckAttempts = 3;
      const aliasCheckInterval = 1000; // 1 second between retries
      
      function performAliasCheck() {
        aliasCheckAttempts++;
        debugLog(`Alias check attempt ${aliasCheckAttempts}/${maxAliasCheckAttempts} for "${alias}"`);
        
        aliasNode.once((data) => {
          if (checksDone >= 2) return;
          
          debugLog(`Alias node check for "${alias}" returned:`, data ? Object.keys(data) : 'null');
          
          // Check if alias exists and extract associated public key
          if (data && typeof data === 'object') {
            // Gun stores data as { "~pubkey": { "#": "~pubkey" } }
            const keys = Object.keys(data);
            for (const key of keys) {
              // Skip Gun internal keys
              if (key === '_' || key.startsWith('_')) continue;
              // Extract public key (remove ~ prefix)
              if (key.startsWith('~')) {
                aliasExists = true;  // Alias exists in network
                existingPub = key.replace('~', '');
                debugLog(`Found existing alias "${alias}" with pub: ${existingPub?.substring(0, 20)}...`);
                break;
              }
            }
          }
          
          // If alias found OR max attempts reached, complete
          if (aliasExists || aliasCheckAttempts >= maxAliasCheckAttempts) {
            if (!aliasExists) {
              debugLog(`Alias "${alias}" not found after ${aliasCheckAttempts} attempts`);
            }
            checkComplete();
          } else {
            // Retry after delay
            debugLog(`Alias not found, retrying in ${aliasCheckInterval}ms...`);
            setTimeout(performAliasCheck, aliasCheckInterval);
          }
        });
      }
      
      // Start alias check
      performAliasCheck();
      
      // Also check if user node exists (in case index hasn't been written yet)
      userNode.once((data) => {
        if (checksDone >= 2) return;
        
        // Check if user node has any data (means user exists)
        if (data && typeof data === 'object') {
          const keys = Object.keys(data);
          // If there are keys other than Gun internals, user exists
          const hasData = keys.some(key => key !== '_' && !key.startsWith('_'));
          if (hasData) {
            userNodeHasData = true;
          }
        }
        
        checkComplete();
      });
    }).catch((e) => {
      cat.ing = false;
      console.error("Key generation error:", e);
      if (cb) cb({ err: "Internal error: " + e.message });
    });
    
    // Helper function to proceed with authentication after username check
    function proceedWithAuth(deterministicPair, existingPublicKey) {
      const user = (root._).user;
      const at_old = (user._);
      const upt = at_old.opt;
      
      const at = user._ = root.get('~' + deterministicPair.pub)._;
      at.opt = upt;
      
      user.is = {
        pub: deterministicPair.pub,
        epub: deterministicPair.epub,
        alias: alias || deterministicPair.pub
      };
      at.sea = deterministicPair;
      cat.ing = false;
      
      const ack = at;
      if (!ack.sea) ack.sea = deterministicPair;
      if (!ack.alias) ack.alias = alias;
      if (!ack.pub) ack.pub = deterministicPair.pub;
      
      // Handle sessionStorage
      const SEA = User.SEA;
      if (SEA && SEA.window && ((gun.back('user')._).opt || opt).remember) {
        try {
          const sS = SEA.window.sessionStorage;
          sS.recall = true;
          sS.pair = JSON.stringify(deterministicPair);
        } catch (e) {}
      }
      
      // Emit auth event
      try {
        if (root._.tag && root._.tag.auth) {
          root._.on('auth', at);
        } else {
          setTimeout(function() { root._.on('auth', at); }, 1);
        }
      } catch (e) {
        Gun.log("Your 'auth' callback crashed with:", e);
      }
      
      debugLog("Auth successful, pub:", deterministicPair.pub.slice(0, 20) + "...");
      
      // Reset rate limit on successful auth
      resetRateLimit(alias);
      
      if (cb) cb(ack);
      
      // Write global index and user profile (background)
      // Write index if username doesn't exist yet (new account or missing index)
      if (!existingPublicKey) {
        const userSoul = "~" + deterministicPair.pub;
        const gunUser = root.user();
        
        const aliasNode = {};
        aliasNode[userSoul] = { '#': userSoul };
        
        root.get('~@' + alias).put(aliasNode, (ackGlobal) => {
          if (ackGlobal.err) console.warn("Index warning:", ackGlobal.err);
          
          gunUser.put({ 
            alias: alias,
            pub: deterministicPair.pub, 
            epub: deterministicPair.epub
          }, (ackPut) => {
            debugLog("User profile written");
          });
        });
      }
    }
    
    return gun;
  };
    
  User.prototype.auth.__authdOverridden = true;
  overrideApplied = true;
  debugLog("Auth override applied successfully");
  
  return true;
}

// --- AUTO-MOUNT: Apply override immediately ---
applyAuthOverride();

// Retry with delay if not applied (for async loading scenarios)
if (!overrideApplied && typeof setTimeout !== 'undefined') {
  const intervals = [0, 10, 50, 100, 200, 500];
  intervals.forEach(delay => {
    setTimeout(() => {
      if (!overrideApplied) {
        applyAuthOverride();
      }
    }, delay);
  });
}

// --- GUN CHAIN METHODS ---

// Legacy convenience method
Gun.chain.authd = async function(user, pass, cb, opt) {
  const gun = this.back(-1);
  const gunUser = gun.user();
  return gunUser.auth(user, pass, cb, opt);
};

// Verify password against expected pub key
Gun.chain.verifyPassword = async function(expectedPub, username, password) {
  return verifyPassword(expectedPub, username, password);
};

/**
 * Check if an alias already exists in the network
 * @param {string} alias - The alias to check
 * @param {number} timeout - Timeout in ms (default: 2000)
 * @param {function} cb - Callback function (err, exists, pub)
 * @returns {Promise<{exists: boolean, pub: string|null}>} - Object with exists flag and associated pub key
 */
Gun.chain.checkAliasExists = function(alias, timeout = 2000, cb) {
  const gun = this.back(-1);
  const root = gun.back(-1);
  
  if (!alias || typeof alias !== 'string' || !alias.trim()) {
    const error = "Alias must be a non-empty string";
    if (cb) cb(error, false, null);
    return Promise.resolve({ exists: false, pub: null });
  }
  
  const normalizedAlias = normalizeString(alias);
  const aliasNode = root.get('~@' + normalizedAlias);
  
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const result = { exists: false, pub: null };
      if (cb) cb(null, false, null);
      resolve(result);
    }, timeout);
    
    aliasNode.once((data) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      
      let existingPub = null;
      if (data && typeof data === 'object') {
        const keys = Object.keys(data);
        for (const key of keys) {
          if (key === '_' || key.startsWith('_')) continue;
          if (key.startsWith('~')) {
            existingPub = key.replace('~', '');
            break;
          }
        }
      }
      
      const exists = !!existingPub;
      const result = { exists, pub: existingPub };
      if (cb) cb(null, exists, existingPub);
      resolve(result);
    });
  });
};

// --- HELPER FUNCTION FOR ALIAS CHECK ---

/**
 * Check if an alias exists in the network (standalone function)
 * @param {Gun} gunInstance - Gun instance
 * @param {string} alias - The alias to check
 * @param {number} timeout - Timeout in ms (default: 2000)
 * @returns {Promise<{exists: boolean, pub: string|null}>}
 */
async function checkAliasExists(gunInstance, alias, timeout = 2000) {
  if (!alias || typeof alias !== 'string' || !alias.trim()) {
    return { exists: false, pub: null };
  }
  
  const root = gunInstance.back(-1);
  const normalizedAlias = normalizeString(alias);
  const aliasNode = root.get('~@' + normalizedAlias);
  
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ exists: false, pub: null });
    }, timeout);
    
    aliasNode.once((data) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      
      let existingPub = null;
      if (data && typeof data === 'object') {
        const keys = Object.keys(data);
        for (const key of keys) {
          if (key === '_' || key.startsWith('_')) continue;
          if (key.startsWith('~')) {
            existingPub = key.replace('~', '');
            break;
          }
        }
      }
      
      resolve({ exists: !!existingPub, pub: existingPub });
    });
  });
}

// --- NAMESPACE EXPORT ---
const GunAuthd = {
  // Core functions
  generatePair: generateDeterministicPair,
  validatePassword: validatePasswordStrength,
  validatePin: validatePin,
  verifyPassword: verifyPassword,
  checkAliasExists: checkAliasExists,
  
  // Rate limiting
  checkRateLimit: checkRateLimit,
  resetRateLimit: resetRateLimit,
  
  // Utilities
  enableDebug: enableDebug,
  secureWipe: secureWipe,  
  
  // Configuration
  config: {
    argon2: ARGON2_CONFIG,
    password: PASSWORD_CONFIG,
    pin: PIN_CONFIG,
    rateLimit: RATE_LIMIT_CONFIG,
  },
  version: LIB_VERSION,
};

// Attach to Gun for easy access
Gun.authd = GunAuthd;

// ES Module exports (for direct import)
export { 
  generateDeterministicPair, 
  validatePasswordStrength,
  validatePin,
  verifyPassword,
  checkAliasExists,
  checkRateLimit,
  resetRateLimit,
  enableDebug,
  secureWipe,
  ARGON2_CONFIG,
  PASSWORD_CONFIG,
  PIN_CONFIG,
  RATE_LIMIT_CONFIG,
  GunAuthd as default
};
