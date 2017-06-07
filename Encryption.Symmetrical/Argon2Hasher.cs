using System;
using System.Runtime.InteropServices;

namespace Encryption.Symmetrical
{
    public enum Argon2Error
    {
        /// <summary>
        /// The operation was successful
        /// </summary>
        Ok = 0,

        /// <summary>
        /// The output hash length is less than 4 bytes
        /// </summary>
        OutputTooShort = -2,

        /// <summary>
        /// The salt is less than 8 bytes
        /// </summary>
        SaltTooShort = -6,

        /// <summary>
        /// The time cost is less than 1
        /// </summary>
        TimeTooSmall = -12,

        /// <summary>
        /// The memory cost is less than 8 (KiB)
        /// </summary>
        MemoryTooLittle = -14,
        /// <summary>
        /// The memory cost is greater than 2^21 (KiB) (2 GiB)
        /// </summary>
        MemoryTooMuch = -15,

        /// <summary>
        /// The parallelism is less than 1
        /// </summary>
        LanesTooFew = -16,
        /// <summary>
        /// The parallelism is greater than 16,777,215
        /// </summary>
        LanesTooMany = -17,

        /// <summary>
        /// Memory allocation failed
        /// </summary>
        MemoryAllocationError = -22,

        /// <summary>
        /// The parallelism is less than 1
        /// </summary>
        ThreadsTooFew = -28,
        /// <summary>
        /// The parallelism is greater than 16,777,215
        /// </summary>
        ThreadsTooMany = -29,

        /// <summary>
        /// This will not be returned from the C# PasswordHasher wrapper
        /// </summary>
        DecodingFail = -32,
        /// <summary>
        /// Unable to create the number of threads requested
        /// </summary>
        ThreadFail = -33,

        /// <summary>
        /// This will not be returned from the C# PasswordHasher wrapper
        /// </summary>
        VerifyMismatch = -35
    }

    public enum Argon2Type
    {
        /// <summary>
        /// The memory access is dependent upon the hash value (vulnerable to side-channel attacks)
        /// </summary>
        Argon2D = 0,

        /// <summary>
        /// The memory access is independent upon the hash value (safe from side-channel atacks)
        /// </summary>
        Argon2I = 1
    }

    public class Argon2Hasher
    {
        const int ArgonVersion = 0x13;

        readonly Argon2Type _argonType;
        readonly int _hashLength;
        readonly uint _iterations;
        readonly uint _costMemKb;
        readonly uint _parallelism;

        public Argon2Hasher(int hashLength = 32, Argon2Type argonType = Argon2Type.Argon2I, uint iterations = 10, uint costMemKb = 131072, uint parallelism = 1)
        {
            _iterations = iterations;
            _costMemKb = costMemKb;
            _parallelism = parallelism;
            _argonType = argonType;
            _hashLength = hashLength;
        }

        public byte[] HashRaw(byte[] password, byte[] salt)
        {
            var hash = new byte[_hashLength];
            var result = (Argon2Error)crypto_argon2_hash(_iterations, _costMemKb, _parallelism, password, password.Length, salt, salt.Length, hash, hash.Length, null, 0, (int)_argonType, ArgonVersion);
            if (result != Argon2Error.Ok)
                throw new Exception($"Argon hashing failed: {result}");
            return hash;
        }

        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int crypto_argon2_hash(uint iterations, uint costMem, uint parallelism,
            byte[] pwd, int pwdlen,
            byte[] salt, int saltlen,
            byte[] hash, int hashlen,
            byte[] encoded, int encodedlen,
            int type, int version);
    }
}
