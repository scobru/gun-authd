// TypeScript declarations for gun-authd
declare module 'gun-authd' {
    /**
     * SEA key pair compatible with GunDB
     */
    export interface SEAPair {
        /** Public signing key (ECDSA P-256) */
        pub: string;
        /** Private signing key */
        priv: string;
        /** Public encryption key (ECDH P-256) */
        epub: string;
        /** Private encryption key */
        epriv: string;
    }

    /**
     * Argon2id configuration
     */
    export interface Argon2Config {
        /** Number of parallel threads */
        parallelism: number;
        /** Time cost (iterations) */
        iterations: number;
        /** Memory size in KB */
        memorySize: number;
        /** Output hash length in bytes */
        hashLength: number;
    }

    /**
     * Generates a deterministic SEA key pair from username and password
     * Uses Argon2id + HKDF for secure key derivation
     * 
     * @param username - The username
     * @param password - The password
     * @returns Promise resolving to SEA key pair
     * 
     * @example
     * const pair = await generateDeterministicPair("alice", "strong-password!");
     * console.log(pair.pub); // Public key
     */
    export function generateDeterministicPair(
        username: string,
        password: string
    ): Promise<SEAPair>;

    /**
     * Validates password strength
     * 
     * @param password - The password to validate
     * @returns true if valid
     * @throws Error if password is too weak
     * 
     * @example
     * try {
     *   validatePasswordStrength("weak");
     * } catch (e) {
     *   console.error(e.message); // "Password must be at least 8 characters"
     * }
     */
    export function validatePasswordStrength(password: string): boolean;

    /**
     * Verify if a password matches an expected public key
     * Useful for UI validation without full auth
     * 
     * @param expectedPub - The expected public key
     * @param username - The username
     * @param password - The password to verify
     * @returns Promise resolving to true if password matches
     * 
     * @example
     * const isValid = await verifyPassword(storedPub, "alice", inputPassword);
     */
    export function verifyPassword(
        expectedPub: string,
        username: string,
        password: string
    ): Promise<boolean>;

    /**
     * Enable or disable debug logging
     * 
     * @param enable - Whether to enable debug mode
     * 
     * @example
     * enableDebug(true);
     * // Now auth operations will log to console
     */
    export function enableDebug(enable?: boolean): void;

    /**
     * Argon2id configuration used for key derivation
     */
    export const ARGON2_CONFIG: Argon2Config;

    /**
     * GunAuthd namespace with all utilities
     */
    export interface GunAuthdNamespace {
        generatePair: typeof generateDeterministicPair;
        validatePassword: typeof validatePasswordStrength;
        verifyPassword: typeof verifyPassword;
        enableDebug: typeof enableDebug;
        config: Argon2Config;
        version: string;
    }

    const GunAuthd: GunAuthdNamespace;
    export default GunAuthd;
}

