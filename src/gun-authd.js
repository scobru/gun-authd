import Gun from "gun";
import "gun/sea.js";
import { p256 } from "@noble/curves/p256";

// --- HELPERS (Invariati) ---
const TEXT_ENCODER = new TextEncoder();
function normalizeString(str) { return str.normalize("NFC").trim(); }
function arrayBufToBase64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\//g, "_").replace(/=/g, "").replace(/\+/g, "-");
}
function keyBufferToJwk(publicKeyBuffer) {
  if (publicKeyBuffer[0] !== 4) throw new Error("Formato chiave pubblica non valido");
  return [
    arrayBufToBase64UrlEncode(publicKeyBuffer.slice(1, 33)),
    arrayBufToBase64UrlEncode(publicKeyBuffer.slice(33, 65)),
  ].join(".");
}
async function stretchKey(input, salt) {
  const baseKey = await crypto.subtle.importKey("raw", input, { name: "PBKDF2" }, false, ["deriveBits"]);
  // Usa un numero di iterazioni adeguato (es. 300k)
  const keyBits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 300000, hash: "SHA-256" }, baseKey, 256);
  return new Uint8Array(keyBits);
}

// --- GENERAZIONE CHIAVI ---
async function generateDeterministicPair(username, password) {
  const pwdBytes = TEXT_ENCODER.encode(normalizeString(password));
  const userBytes = TEXT_ENCODER.encode(normalizeString(username));
  const combinedInput = new Uint8Array(pwdBytes.length + userBytes.length);
  combinedInput.set(pwdBytes);
  combinedInput.set(userBytes, pwdBytes.length);

  const version = "v1";
  const keys = {};
  const salts = [
    { label: "signing", type: "pub/priv" },
    { label: "encryption", type: "epub/epriv" },
  ];

  await Promise.all(
    salts.map(async ({ label }) => {
      const salt = TEXT_ENCODER.encode(`${label}-${version}`);
      const privateKey = await stretchKey(combinedInput, salt);
      const publicKey = p256.getPublicKey(privateKey, false);
      
      if (label === 'signing') {
        keys.pub = keyBufferToJwk(publicKey);
        keys.priv = arrayBufToBase64UrlEncode(privateKey);
      } else {
        keys.epub = keyBufferToJwk(publicKey);
        keys.epriv = arrayBufToBase64UrlEncode(privateKey);
      }
    })
  );

  return { pub: keys.pub, priv: keys.priv, epub: keys.epub, epriv: keys.epriv };
}

// --- OVERRIDE GUN.USER().AUTH() ---

// Funzione helper per determinare i parametri (compatibile con la logica nativa)
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

// Override diretto - applica l'override quando Gun.User è disponibile
// Usiamo un approccio che funziona sia con import ES6 che con require
let originalAuth = null;
let overrideApplied = false;

function applyAuthOverride() {
  if (overrideApplied) return true;
  
  // Accedi a Gun in modo dinamico
  let GunObj, User;
  try {
    // Prova vari modi per accedere a Gun
    if (typeof Gun !== 'undefined') GunObj = Gun;
    else if (typeof window !== 'undefined' && window.Gun) GunObj = window.Gun;
    else if (typeof global !== 'undefined' && global.Gun) GunObj = global.Gun;
    else if (typeof globalThis !== 'undefined' && globalThis.Gun) GunObj = globalThis.Gun;
    
    if (GunObj && GunObj.User) {
      User = GunObj.User;
    }
  } catch(e) {
    // Ignora errori silenziosamente
  }
  
  if (!User || !User.prototype || !User.prototype.auth) {
    return false;
  }
  
  // Evita di applicare l'override più volte
  if (User.prototype.auth.__authdOverridden) {
    overrideApplied = true;
    return true;
  }
  
  // Salva il metodo originale
  originalAuth = User.prototype.auth;
  
  // Override di User.prototype.auth
  User.prototype.auth = function(...args) {
    const gun = this;
    const cat = gun._;
    const root = gun.back(-1);
    const noop = function(){};
    const Gun = User.GUN;
    
    const { pair, alias, pass, cb, opt } = parseAuthArgs(...args);
    
    // Se viene passato un pair completo (con priv ed epriv), usa il metodo originale
    if (pair && pair.priv && pair.epriv) {
      return originalAuth.call(this, ...args);
    }
    
    // Se non c'è alias/pass, usa il metodo originale (gestisce altri casi)
    if (!alias || !pass) {
      return originalAuth.call(this, ...args);
    }
    
    // Controllo per chiamate concorrenti (come nel metodo originale)
    if (cat.ing) {
      (cb || noop)({ err: Gun.log("User is already being created or authenticated!"), wait: true });
      return gun;
    }
    cat.ing = true;
    
    // Genera il pair deterministico (async)
    generateDeterministicPair(alias, pass).then((deterministicPair) => {
      // Replica la logica di act.g dal metodo originale per impostare lo stato dell'utente
      // Questo bypassa la validazione del salt che il metodo originale farebbe
      const user = (root._).user;
      const at_old = (user._);
      const tmp = at_old.tag;
      const upt = at_old.opt;
      
      // Imposta il nodo utente nel grafo (come fa il metodo originale alla riga 72)
      const at = user._ = root.get('~' + deterministicPair.pub)._;
      at.opt = upt;
      
      // Aggiungi le credenziali in-memory solo all'istanza root user (riga 75)
      user.is = {
        pub: deterministicPair.pub,
        epub: deterministicPair.epub,
        alias: alias || deterministicPair.pub
      };
      at.sea = deterministicPair;
      cat.ing = false;
      
      // L'ack è il nodo utente (at), come nel metodo originale (riga 79)
      // Aggiungiamo le proprietà che potrebbero essere necessarie
      const ack = at;
      if (!ack.sea) ack.sea = deterministicPair;
      if (!ack.alias) ack.alias = alias;
      if (!ack.pub) ack.pub = deterministicPair.pub;
      
      // Gestione sessionStorage (come nel metodo originale, righe 80-87)
      const SEA = User.SEA;
      if (SEA && SEA.window && ((gun.back('user')._).opt || opt).remember) {
        try {
          const sS = SEA.window.sessionStorage;
          sS.recall = true;
          sS.pair = JSON.stringify(deterministicPair);
        } catch (e) {}
      }
      
      // Emetti evento auth (come nel metodo originale, righe 88-95)
      try {
        if (root._.tag && root._.tag.auth) {
          root._.on('auth', at);
        } else {
          setTimeout(function() { root._.on('auth', at); }, 1);
        }
      } catch (e) {
        Gun.log("Your 'auth' callback crashed with:", e);
      }
      
      // Chiama il callback immediatamente (come nel metodo originale, riga 79)
      // Nota: opt.change gestisce il cambio password, ma non lo supportiamo qui
      if (cb) cb(ack);
      
      // SCRITTURA INDICE GLOBALE E PROFILO UTENTE (in background, dopo il callback)
      const userSoul = "~" + deterministicPair.pub;
      const gunUser = root.user();
      
      // SCRITTURA INDICE GLOBALE (~@alias -> ~pubkey)
      const aliasNode = {};
      aliasNode[userSoul] = { '#': userSoul };
      
      root.get('~@' + alias).put(aliasNode, (ackGlobal) => {
        if (ackGlobal.err) console.warn("Index warning:", ackGlobal.err);
        
        // POPOLAMENTO PROFILO UTENTE (FIX PER NODO VUOTO)
        gunUser.put({ 
          alias: alias,
          pub: deterministicPair.pub, 
          epub: deterministicPair.epub
        }, (ackPut) => {
          // Completato in background
        });
      });
    }).catch((e) => {
      cat.ing = false;
      console.error("Errore generazione chiavi:", e);
      if (cb) cb({ err: "Errore interno: " + e.message });
    });
    
    return gun;
  };
    
  // Marca l'override come applicato
  User.prototype.auth.__authdOverridden = true;
  overrideApplied = true;
  
  return true;
}

// Prova ad applicare l'override immediatamente
applyAuthOverride();

// Se non è stato applicato, riprova con delay
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

// Manteniamo anche authd per retrocompatibilità
Gun.chain.authd = async function(user, pass, cb, opt) {
  const gun = this.back(-1);
  const gunUser = gun.user();
  return gunUser.auth(user, pass, cb, opt);
};
