declare module "crypto" {
    class CertDate {
        readonly year: number;
        readonly mon: number;
        readonly day: number;
        readonly hour: number;
        readonly min: number;
        readonly sec: number;
    }

    class Certificate {
        constructor(pem: string | Uint8Array);

        toString(): string;
        readonly version: number;
        readonly issuer: string;
        readonly subject: string;
        readonly serial: string;
        readonly validRange: [CertDate, CertDate];
        readonly status: "ok" | "expired" | "future";
        next(): Certificate | null;

        verify(): {
            ok: false,
            info: string
        } | {
            ok: true
        };
    }

    interface Crypto {
        /**
         * Calculate SHA hash of data
         * @param data Input data
         * @param shalevel SHA level (1, 224, 256, 384, 512, 3224, 3256, 3384, 3512)
         * @returns Hash result as Uint8Array
         */
        sha(data: Uint8Array, shalevel?: number): Uint8Array;

        /**
         * Calculate MD5 hash of data
         * @param data Input data
         * @returns Hash result as Uint8Array
         */
        md5(data: Uint8Array): Uint8Array;

        /**
         * AES encryption/decryption
         * @param key Encryption key (16, 24 or 32 bytes)
         * @param iv Initialization vector
         * @param data Data to encrypt/decrypt
         * @param encrypt Whether to encrypt (true) or decrypt (false)
         * @returns Result as Uint8Array
         */
        aes(key: Uint8Array, iv: Uint8Array, data: Uint8Array, encrypt?: boolean): Uint8Array;

        /**
         * HMAC calculation
         * @param algtype Algorithm type (e.g. "sha256", "sha3-256", "md5", "ripemd160")
         * @param key Secret key
         * @param data Data to authenticate
         * @returns HMAC result as Uint8Array
         */
        hmac(algtype: string, key: Uint8Array, data: Uint8Array): Uint8Array;

        /**
         * Generate random bytes
         * @param size Number of random bytes to generate
         * @returns Random bytes as Uint8Array
         */
        random(size: number): Uint8Array;

        /**
         * Base64 encode data
         * @param data Data to encode
         * @returns Base64 encoded string
         */
        b64encode(data: Uint8Array): string;

        /**
         * Base64 decode data
         * @param data Base64 encoded string
         * @returns Decoded data as Uint8Array
         */
        b64decode(data: Uint8Array): Uint8Array;

        readonly Certificate: {
            new(pem: string | Uint8Array): Certificate;
            /**
             * Cautious: ArrayBuffer is a pointer div not a real arraybuffer
             *  donot try to modify or read it directly if you donot know what you are doing
             * @param pem PEM or DER encoded certificate
             */
            parseKey(pem: string | Uint8Array): ArrayBuffer;
        };

        readonly CertDate: {
            new(): never; // Not constructable
        };

        [Symbol.toStringTag]: "Crypto";
    }

    const crypto: Crypto;
    export = crypto;
}
