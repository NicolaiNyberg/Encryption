# Encryption

Includes the C source code for Argon2 copied from https://github.com/alipha/csharp-argon2

When doing Password-based-encryption (PBE), one should:
1. Derive the key from the password using a good hasher with cryptographically strong random salt values unique for each message that needs encryption. The Rfc2898 (PBKDF2) algorithm and Argon2 hasher are good candidates for this task.
2. Generate a cryptographically strong random initial vector (IV) unique for each message that needs encryption.
3. Keep the random salt and IV public, and part of the encrypted message.

The tests here give implementations of this approach when doing AES256 encryption with various combinations of key-generators.

Best practice, so far, is to HMAC the password with a secret key before handing it over to the key-generator. In that way, it becomes very difficult for an attacker to guess your password knowing the public salt and should he have guessed the key for a given encrypted message.
