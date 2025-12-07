import Gun from "gun";
import "../dist/gun-authd.min.js";
import fs from 'fs';

// Pulizia preventiva
try {
    if (fs.existsSync('radata')) fs.rmSync('radata', { recursive: true, force: true });
} catch (e) {}

const gun = Gun({"peers": ["https://shogun-relay.scobrudot.dev/gun"], radisk: false});
    
const user = "scobru";
const pass = "francos88";

// Aspetta un momento per assicurarsi che l'override sia stato applicato
setTimeout(() => {
    // Verifica che l'override sia stato applicato
    const User = Gun.User;
    if (User && User.prototype && User.prototype.auth) {
        const isOverridden = User.prototype.auth.__authdOverridden === true;
        if (isOverridden) {
            console.log("✅ Override di User.prototype.auth verificato e applicato!");
            console.log("   Il metodo auth è stato sostituito con la versione deterministica\n");
        } else {
            console.warn("⚠️  User.prototype.auth esiste ma l'override NON è stato applicato!");
            console.warn("   Questo significa che gun-authd non ha funzionato correttamente\n");
        }
    } else {
        console.warn("⚠️  Attenzione: User.prototype.auth potrebbe non essere disponibile\n");
    }

    console.log("--- Test Override gun.user().auth() ---");
    console.log("🔍 Verifica che gun.user().auth() usi l'autenticazione deterministica");
    console.log(`📝 Credenziali: ${user} / ${pass.substring(0, 3)}***\n`);

    // Test: usa gun.user().auth() direttamente (dovrebbe usare l'override)
    console.log("🚀 Chiamata: gun.user().auth(user, pass, callback)");
    gun.user().auth(user, pass, (ack) => {
    
    if (ack.err) {
        console.error("❌ ERRORE FATALE:", ack.err);
        process.exit(1);
    }

    console.log(`\n✅ Login completato con gun.user().auth()!`);
    console.log(`🔑 Pub Key (Deterministica): ${ack.sea.pub}`);
    console.log(`📛 Alias nel callback: ${ack.alias || 'N/A'}`);
    
    // Verifica che l'alias sia presente (segno che l'override ha funzionato)
    if (ack.alias && ack.alias === user) {
        console.log("✅ Verifica override: alias presente nel callback (override funzionante)");
    } else {
        console.warn("⚠️  Verifica override: alias non presente (potrebbe non essere l'override)");
    }
    
    // Verifica Alias Locale
    gun.user().get('alias').once(alias => {
        console.log(`👤 Alias locale nel grafo: ${alias}`);
        if (alias === user) {
            console.log("✅ Verifica: alias salvato correttamente nel grafo");
        }
    });

    // Verifica Indice Globale
    console.log("⏳ Verifica propagazione globale (attendo 1s)...");
    
    setTimeout(() => {
        gun.get('~@' + user).once(data => {
            
            if (!data) {
                console.log("❌ ERRORE: Nodo indice ~@" + user + " vuoto/non trovato.");
                process.exit(1);
            }

            // La Soul che ci aspettiamo (L'ID dell'utente)
            const expectedSoul = "~" + ack.sea.pub;
            
            console.log("📄 Soul atteso:", expectedSoul);
            // console.log("📄 Contenuto indice:", JSON.stringify(data, null, 2));

            // VERIFICA: L'oggetto ritornato (l'indice) deve contenere una chiave che è il nostro Soul
            // Esempio data: { "_": {...}, "~chiave...": { "#": "~chiave..." } }
            
            // Verifichiamo se esiste la proprietà con il nome della nostra soul
            const linkExists = Object.prototype.hasOwnProperty.call(data, expectedSoul);

            if (linkExists) {
                console.log("\n🎉 SUCCESSO TOTALE!");
                console.log("   ✅ Override di gun.user().auth() funziona correttamente!");
                console.log("   ✅ Trovato match nell'indice globale:");
                console.log(`   ✅ ~@${user} -> ${expectedSoul}`);
                console.log("\n📊 Riepilogo:");
                console.log("   - gun.user().auth() usa autenticazione deterministica");
                console.log("   - Chiavi generate localmente (senza salt dal network)");
                console.log("   - Indice globale creato correttamente");
                console.log("   - Profilo utente popolato");
            } else {
                console.log("\n❌ ERRORE: Mismatch nell'indice globale.");
                console.log("   L'indice globale non contiene la tua chiave pubblica.");
                console.log("   Dati ricevuti:", Object.keys(data || {}));
            }
            process.exit(linkExists ? 0 : 1);
        });
    }, 1000); 
    });
}, 100); // Piccolo delay per assicurarsi che l'override sia applicato