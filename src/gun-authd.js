import Gun from "gun";
import "gun/sea.js";
import { p256 } from "@noble/curves/p256";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { argon2id } from "hash-wasm";

// --- CONFIGURATION ---
const ARGON2_CONFIG = {
  parallelism: 4,      // Number of parallel threads
  iterations: 3,       // Time cost (higher = slower but more secure)
  memorySize: 65536,   // Memory in KB (64 MB) - memory-hard protection
  hashLength: 32,      // Output 256 bits
};

const KEY_VERSION = "v2"; // Version identifier for key derivation
const LIB_VERSION = "2.0.0";

// --- HELPERS ---
const TEXT_ENCODER = new TextEncoder();

function normalizeString(str) {
  return str.normalize("NFC").trim();
}

function arrayBufToBase64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\//g, "_").replace(/=/g, "").replace(/\+/g, "-");
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

// --- KEY GENERATION ---

/**
 * Generates a deterministic SEA key pair from username and password
 * @param {string} username - The username
 * @param {string} password - The password
 * @returns {Promise<{pub: string, priv: string, epub: string, epriv: string}>}
 */
async function generateDeterministicPair(username, password) {
  debugLog("Generating pair for:", username);
  
  const normalizedUser = normalizeString(username);
  const normalizedPass = normalizeString(password);
  
  // Combine password and username for Argon2 input
  const passwordBytes = TEXT_ENCODER.encode(normalizedPass);
  const usernameBytes = TEXT_ENCODER.encode(normalizedUser);
  
  // Use username as salt for Argon2 (deterministic)
  const argonSalt = TEXT_ENCODER.encode(`gun-authd-salt-${normalizedUser}`);
  
  // Derive master key using Argon2id (memory-hard)
  const masterKey = await argon2Derive(passwordBytes, argonSalt);
  
  // Use HKDF to derive separate keys for signing and encryption
  const signingInfo = TEXT_ENCODER.encode("signing-key");
  const encryptionInfo = TEXT_ENCODER.encode("encryption-key");
  
  const signingPrivateKey = hkdfExpand(masterKey, signingInfo, 32);
  const encryptionPrivateKey = hkdfExpand(masterKey, encryptionInfo, 32);
  
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
}

// --- PASSWORD VALIDATION ---

/**
 * Validates password strength
 * @param {string} password - The password to validate
 * @returns {boolean} - True if valid
 * @throws {Error} - If password is too weak
 */
function validatePasswordStrength(password) {
  const minLength = 8;
  
  if (!password || typeof password !== 'string') {
    throw new Error("Password must be a non-empty string");
  }
  
  if (password.length < minLength) {
    throw new Error(`Password must be at least ${minLength} characters`);
  }
  
  // Calculate basic entropy estimate
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);
  
  const charsetSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + 
                      (hasNumber ? 10 : 0) + (hasSpecial ? 32 : 0);
  const entropy = password.length * Math.log2(charsetSize || 1);
  
  if (entropy < 28) { // ~28 bits minimum (very basic threshold)
    throw new Error("Password is too weak. Use a mix of letters, numbers, and symbols.");
  }
  
  return true;
}

/**
 * Verify if a password matches an expected public key
 * Useful for UI validation without full auth
 * @param {string} expectedPub - The expected public key
 * @param {string} username - The username
 * @param {string} password - The password to verify
 * @returns {Promise<boolean>}
 */
async function verifyPassword(expectedPub, username, password) {
  try {
    const pair = await generateDeterministicPair(username, password);
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
    
    debugLog("Using deterministic auth for:", alias);
    
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
    
    // Generate deterministic pair using Argon2id + HKDF
    generateDeterministicPair(alias, pass).then((deterministicPair) => {
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
      if (cb) cb(ack);
      
      // Write global index and user profile (background)
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
    }).catch((e) => {
      cat.ing = false;
      console.error("Key generation error:", e);
      if (cb) cb({ err: "Internal error: " + e.message });
    });
    
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

// --- NAMESPACE EXPORT ---
const GunAuthd = {
  generatePair: generateDeterministicPair,
  validatePassword: validatePasswordStrength,
  verifyPassword: verifyPassword,
  enableDebug: enableDebug,
  config: ARGON2_CONFIG,
  version: LIB_VERSION,
};

// Attach to Gun for easy access
Gun.authd = GunAuthd;

// ES Module exports (for direct import)
export { 
  generateDeterministicPair, 
  validatePasswordStrength, 
  verifyPassword,
  enableDebug,
  ARGON2_CONFIG,
  GunAuthd as default
};
