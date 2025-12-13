// TypeScript declarations for gun-authd v3
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
     * Password validation configuration
     */
    export interface PasswordConfig {
        /** Minimum password length */
        minLength: number;
        /** Minimum entropy bits */
        minEntropy: number;
    }

    /**
     * PIN validation configuration
     */
    export interface PinConfig {
        /** Minimum PIN length */
        minLength: number;
        /** Maximum PIN length */
        maxLength: number;
        /** PIN pattern regex */
        pattern: RegExp;
    }

    /**
     * Rate limiting configuration
     */
    export interface RateLimitConfig {
        /** Maximum attempts before lockout */
        maxAttempts: number;
        /** Time window in milliseconds */
        windowMs: number;
        /** Base delay in milliseconds */
        baseDelayMs: number;
        /** Maximum delay in milliseconds */
        maxDelayMs: number;
    }

    /**
     * Combined configuration object
     */
    export interface GunAuthdConfig {
        argon2: Argon2Config;
        password: PasswordConfig;
        pin: PinConfig;
        rateLimit: RateLimitConfig;
    }

    /**
     * Generates a deterministic SEA key pair from username, password, and optional PIN
     * Uses Argon2id + HKDF for secure key derivation
     * 
     * @param username - The username
     * @param password - The password
     * @param pin - Optional PIN (4-8 digits) for additional security
     * @returns Promise resolving to SEA key pair
     * 
     * @example
     * // Without PIN
     * const pair = await generateDeterministicPair("alice", "strong-password!");
     * 
     * // With PIN
     * const pairWithPin = await generateDeterministicPair("alice", "strong-password!", "1234");
     */
    export function generateDeterministicPair(
        username: string,
        password: string,
        pin?: string | null
    ): Promise<SEAPair>;

    /**
     * Validates password strength with stricter requirements
     * - Minimum 12 characters
     * - Minimum 40 bits entropy
     * - Blocks common passwords
     * - Blocks repetitive patterns
     * 
     * @param password - The password to validate
     * @returns true if valid
     * @throws Error if password is too weak
     * 
     * @example
     * try {
     *   validatePasswordStrength("weak");
     * } catch (e) {
     *   console.error(e.message); // "Password must be at least 12 characters"
     * }
     */
    export function validatePasswordStrength(password: string): boolean;

    /**
     * Validates PIN format
     * - 4-8 digits only
     * - Blocks obvious PINs like 1234, 0000
     * 
     * @param pin - The PIN to validate
     * @returns true if valid
     * @throws Error if PIN format is invalid
     * 
     * @example
     * try {
     *   validatePin("1234");
     * } catch (e) {
     *   console.error(e.message); // "PIN is too simple"
     * }
     */
    export function validatePin(pin: string): boolean;

    /**
     * Verify if a password (and optional PIN) matches an expected public key
     * Useful for UI validation without full auth
     * 
     * @param expectedPub - The expected public key
     * @param username - The username
     * @param password - The password to verify
     * @param pin - Optional PIN
     * @returns Promise resolving to true if credentials match
     * 
     * @example
     * const isValid = await verifyPassword(storedPub, "alice", "password!", "1234");
     */
    export function verifyPassword(
        expectedPub: string,
        username: string,
        password: string,
        pin?: string | null
    ): Promise<boolean>;

    /**
     * Checks rate limit for an alias
     * Throws error if too many attempts have been made
     * 
     * @param alias - The username/alias
     * @throws Error if rate limit exceeded
     * 
     * @example
     * try {
     *   checkRateLimit("alice");
     * } catch (e) {
     *   console.error(e.message); // "Too many attempts. Please wait 30 seconds..."
     * }
     */
    export function checkRateLimit(alias: string): void;

    /**
     * Resets rate limit for an alias
     * Called automatically on successful authentication
     * 
     * @param alias - The username/alias
     */
    export function resetRateLimit(alias: string): void;

    /**
     * Check if an alias exists in the network
     * 
     * @param gunInstance - Gun instance
     * @param alias - The alias to check
     * @param timeout - Timeout in ms (default: 2000)
     * @returns Promise with exists flag and associated public key
     */
    export function checkAliasExists(
        gunInstance: any,
        alias: string,
        timeout?: number
    ): Promise<{ exists: boolean; pub: string | null }>;

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
     * Securely wipes a buffer by overwriting with random data then zeros
     * Helps prevent memory side-channel attacks
     * 
     * @param buffer - Uint8Array buffer to wipe
     */
    export function secureWipe(buffer: Uint8Array): void;

    /**
     * Argon2id configuration used for key derivation
     */
    export const ARGON2_CONFIG: Argon2Config;

    /**
     * Password validation configuration
     */
    export const PASSWORD_CONFIG: PasswordConfig;

    /**
     * PIN validation configuration
     */
    export const PIN_CONFIG: PinConfig;

    /**
     * Rate limiting configuration
     */
    export const RATE_LIMIT_CONFIG: RateLimitConfig;

    /**
     * Auth options for gun.user().auth()
     */
    export interface AuthOptions {
        /** Optional PIN (4-8 digits) */
        pin?: string;
        /** Enable debug logging */
        debug?: boolean;
        /** Skip password strength validation */
        skipValidation?: boolean;
        /** Skip PIN format validation */
        skipPinValidation?: boolean;
        /** Skip rate limiting check */
        skipRateLimit?: boolean;
        /** Remember session in sessionStorage */
        remember?: boolean;
    }

    /**
     * GunAuthd namespace with all utilities
     */
    export interface GunAuthdNamespace {
        // Core functions
        generatePair: typeof generateDeterministicPair;
        validatePassword: typeof validatePasswordStrength;
        validatePin: typeof validatePin;
        verifyPassword: typeof verifyPassword;
        checkAliasExists: typeof checkAliasExists;

        // Rate limiting
        checkRateLimit: typeof checkRateLimit;
        resetRateLimit: typeof resetRateLimit;

        // Utilities
        enableDebug: typeof enableDebug;
        secureWipe: typeof secureWipe;

        // Configuration
        config: GunAuthdConfig;
        version: string;
    }

    const GunAuthd: GunAuthdNamespace;
    export default GunAuthd;
}
