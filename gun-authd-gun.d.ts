// Estensioni dei tipi Gun per gun-authd
// Questo file estende i tipi di gun senza interferire con la risoluzione del modulo principale
// 
// Per utilizzare queste estensioni, includi questo file nel tuo tsconfig.json:
//   "include": ["node_modules/gun-authd/gun-authd-gun.d.ts"]
// Oppure usa un riferimento triplo-slash nel tuo file:
//   /// <reference types="gun-authd/gun-authd-gun" />

// Estende IGunChain dal file specifico
import {} from 'gun/types/gun/IGunChain';
declare module 'gun/types/gun/IGunChain' {
    // Estende IGunChain con tutti i suoi parametri generici originali
    export interface IGunChain<
        TNode extends import('gun/types/gun').GunSchema,
        TChainParent extends
            | IGunChain<any, any, any, any>
            | import('gun/types/gun').IGunInstanceRoot<any, any> = any,
        TGunInstance extends import('gun/types/gun').IGunInstanceRoot<any, any> = any,
        TKey extends string = any
    > {
        /**
         * Verify if a password matches an expected public key
         */
        verifyPassword(
            expectedPub: string,
            username: string,
            password: string
        ): Promise<boolean>;
    }
}

// Estende IGun dal file specifico
import {} from 'gun/types/gun/IGun';
declare module 'gun/types/gun/IGun' {
    // Estende IGun (l'interfaccia statica del costruttore Gun)
    export interface IGun {
        /**
         * GunAuthd utilities namespace
         */
        authd: {
            generatePair: (username: string, password: string) => Promise<{
                pub: string;
                priv: string;
                epub: string;
                epriv: string;
            }>;
            validatePassword: (password: string) => boolean;
            verifyPassword: (expectedPub: string, username: string, password: string) => Promise<boolean>;
            enableDebug: (enable?: boolean) => void;
            config: {
                parallelism: number;
                iterations: number;
                memorySize: number;
                hashLength: number;
            };
            version: string;
        };
    }
}

