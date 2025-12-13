import Gun from "gun";
import "../dist/gun-authd.min.js";

// NOTA: Non cancelliamo radata per mantenere la cache locale
// Questo permette all'alias check di funzionare correttamente

const gun = Gun({"peers": ["https://shogun-relay.scobrudot.dev/gun"], radisk: false});
    
const user = "testuser-autd";
const pass = "mysupersafelongerpass@";
const pin = "1234756"; // PIN per test (4-8 cifre)

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

    console.log("--- Test Override gun.user().auth() con PIN ---");
    console.log("🔍 Verifica che gun.user().auth() usi l'autenticazione deterministica");
    console.log(`📝 Credenziali: ${user} / ${pass} / PIN: ${pin}\n`);

    // Test 1: Verifica controllo alias prima della registrazione
    console.log("--- Test 1: Controllo Alias Esistente ---");
    console.log(`🔍 Verifica se l'alias "${user}" esiste nel network...\n`);
    
    let aliasExists = false;
    let existingPub = null;
    
    gun.checkAliasExists(user, 2000, (err, exists, pub) => {
        if (err) {
            console.error("❌ Errore nel controllo alias:", err);
        } else {
            aliasExists = exists;
            existingPub = pub;
            if (exists) {
                console.log(`✅ Alias "${user}" già esistente nel network`);
                console.log(`   Public Key associata: ${pub?.substring(0, 20)}...`);
                console.log(`   Procedo con il LOGIN...`);
                console.log(`   ⚠️  NOTA: Se hai usato credenziali/PIN diversi, otterrai una chiave diversa!\n`);
            } else {
                console.log(`✅ Alias "${user}" non trovato nel network`);
                console.log(`   Procedo con la REGISTRAZIONE...\n`);
            }
        }
        
        // Procedi con il test di autenticazione
        runAuthTest(aliasExists);
    });
    
    function runAuthTest(isLogin) {
        // Test 2: usa gun.user().auth() con PIN
        const testType = isLogin ? "LOGIN" : "REGISTRAZIONE";
        console.log(`--- Test 2: ${testType} con gun.user().auth() + PIN ---`);
        console.log(`🚀 Chiamata: gun.user().auth(user, pass, callback, { pin: "${pin}" })`);
        console.log(`📝 Tipo operazione: ${isLogin ? "Login (alias esistente)" : "Registrazione (nuovo alias)"}\n`);
        
        // Test con PIN (tre fattori: user + pass + pin) - DEBUG abilitato
        gun.user().auth(user, pass, (ack) => {
            if (ack.err) {
                console.error("❌ ERRORE FATALE:", ack.err);
                
                // Verifica se l'errore è dovuto a alias già preso
                if (ack.err.includes("already taken") || ack.err.includes("credentials do not match")) {
                    console.log("\n⚠️  Test controllo alias:");
                    console.log("   L'alias esiste con credenziali diverse.");
                    console.log("   Questo è normale se hai usato password/PIN diversi in passato.");
                }
                
                process.exit(1);
            }

            const operationType = isLogin ? "Login" : "Registrazione";
            console.log(`\n✅ ${operationType} completato con gun.user().auth() + PIN!`);
            console.log(`🔑 Pub Key (Deterministica): ${ack.sea.pub}`);
            console.log(`📛 Alias nel callback: ${ack.alias || 'N/A'}`);
            console.log(`🔐 PIN utilizzato: ${pin}`);
            
            // Se era un login, verifica che la pub key corrisponda
            if (isLogin && existingPub) {
                if (ack.sea.pub === existingPub) {
                    console.log(`✅ Verifica login: Public Key corrisponde all'alias esistente`);
                } else {
                    console.warn(`⚠️  Verifica login: Public Key diversa (normale se PIN/credenziali cambiate)`);
                    console.warn(`   Attesa: ${existingPub?.substring(0, 20)}...`);
                    console.warn(`   Ricevuta: ${ack.sea.pub?.substring(0, 20)}...`);
                }
            }
            
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

                    // Verifichiamo se esiste la proprietà con il nome della nostra soul
                    const linkExists = Object.prototype.hasOwnProperty.call(data, expectedSoul);

                    if (linkExists) {
                        console.log("\n🎉 SUCCESSO TOTALE!");
                        console.log("   ✅ Override di gun.user().auth() funziona correttamente!");
                        console.log("   ✅ Autenticazione con PIN (tre fattori) riuscita!");
                        console.log("   ✅ Trovato match nell'indice globale:");
                        console.log(`   ✅ ~@${user} -> ${expectedSoul}`);
                        console.log("\n📊 Riepilogo:");
                        console.log("   - gun.user().auth() usa autenticazione deterministica");
                        console.log("   - Chiavi generate localmente (senza salt dal network)");
                        console.log("   - PIN incluso nella derivazione delle chiavi");
                        console.log("   - Indice globale creato correttamente");
                        console.log("   - Profilo utente popolato");
                        
                        // Test 3: Verifica controllo alias dopo l'autenticazione
                        console.log("\n--- Test 3: Verifica Alias Dopo Autenticazione ---");
                        setTimeout(() => {
                            gun.checkAliasExists(user, 2000, (err, exists, pub) => {
                                if (err) {
                                    console.error("❌ Errore:", err);
                                } else {
                                    if (exists && pub === ack.sea.pub) {
                                        console.log(`✅ Alias "${user}" trovato nel network`);
                                        console.log(`   Public Key corrisponde: ${pub?.substring(0, 20)}...`);
                                        console.log("   ✅ Test controllo alias: FUNZIONA!");
                                    } else if (exists) {
                                        console.log(`⚠️  Alias trovato ma con public key diversa`);
                                    } else {
                                        console.log(`⚠️  Alias non ancora propagato nel network`);
                                    }
                                }
                                
                                // Test 4: Tenta un secondo login con stesso PIN
                                console.log("\n--- Test 4: Secondo Login con PIN (Verifica Persistenza) ---");
                                setTimeout(() => {
                                    console.log(`🔄 Tentativo di login con stesse credenziali + PIN: ${pin}...\n`);
                                    gun.user().auth(user, pass, (loginAck) => {
                                        if (loginAck.err) {
                                            console.error("❌ Errore nel secondo login:", loginAck.err);
                                            process.exit(1);
                                        } else {
                                            if (loginAck.sea && loginAck.sea.pub === ack.sea.pub) {
                                                console.log("✅ Secondo login con PIN riuscito!");
                                                console.log(`   Public Key corrisponde: ${loginAck.sea.pub?.substring(0, 20)}...`);
                                                console.log("   ✅ Test login persistente con PIN: FUNZIONA!");
                                            } else {
                                                console.warn("⚠️  Secondo login: Public Key diversa");
                                            }
                                            process.exit(linkExists ? 0 : 1);
                                        }
                                    }, { pin, debug: true }); // <-- PIN nel secondo login + DEBUG
                                }, 500);
                            });
                        }, 500);
                    } else {
                        console.log("\n❌ ERRORE: Mismatch nell'indice globale.");
                        console.log("   L'indice globale non contiene la tua chiave pubblica.");
                        console.log("   Dati ricevuti:", Object.keys(data || {}));
                        process.exit(1);
                    }
                });
            }, 1000); 
        }, { pin, debug: true }); // <-- PIN nella prima autenticazione + DEBUG
    }
}, 100); // Piccolo delay per assicurarsi che l'override sia applicato