# Encryption

Includes the C source code for Argon2 copied from https://github.com/alipha/csharp-argon2

When doing Password-based-encryption (PBE), one should:
1. Derive the key from the password using a good hasher with cryptographically strong random salt values unique for each message that needs encryption. The Rfc2898 (PBKDF2) algorithm in combination with any of the SHAs, and Argon2 hasher are two good candidates for this task. Salting the password with a unique value before key-generation ensures the same password does not provide the same key each time thus rendering rainbow tables useless.
2. Generate a cryptographically strong random initial vector (IV) unique for each message that needs encryption. This ensures the same plaintext encrypted with the same key does not equate to the same output thus making crypto-analysis difficult.
3. Keep the random salt and IV public, and part of the encrypted message.

The tests here provide implementations of this approach when doing AES256 encryption with various combinations of key-generators.

Best practice, so far, is to HMAC the password with a secret key before handing it over to the key-generator. In that way, it becomes very difficult for an attacker to guess your password knowing the public salt should he have guessed the key for a given encrypted message.
