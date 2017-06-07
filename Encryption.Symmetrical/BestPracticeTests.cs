using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace Encryption.Symmetrical
{
    [TestFixture]
    public class BestPracticeTests : SymmetricalEncryptionTestsBase
    {
        protected override byte[] GetKey(string pwd)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[SaltSizeBits / 8];
                rng.GetNonZeroBytes(salt);
                var h = new Argon2Hasher(KeySizeBits / 8);
                var pwdbytes = new UTF8Encoding(false).GetBytes(pwd);
                var hmacPwd = HmacPasswordWithSecretKeyBeforeGivingItToTheUnderlyingHasher(pwdbytes, SecretKey);
                var key = h.HashRaw(hmacPwd, salt);
                return key;
            }
        }

        byte[] HmacPasswordWithSecretKeyBeforeGivingItToTheUnderlyingHasher(byte[] password, byte[] secretKey)
        {            
            using (var hmac = new HMACSHA512(secretKey))
                return hmac.ComputeHash(password);
        }

        // Key should be derived from RNGCryptoServiceProvider
        static readonly byte[] SecretKey = 
        {
            24,
            194,
            255,
            21,
            179,
            58,
            239,
            203,
            181,
            74,
            123,
            227,
            17,
            103,
            42,
            235,
            121,
            115,
            146,
            224,
            97,
            10,
            98,
            80,
            243,
            191,
            220,
            87,
            140,
            109,
            89,
            208,
            54,
            132,
            83,
            225,
            194,
            240,
            114,
            190,
            210,
            127,
            190,
            206,
            222,
            36,
            124,
            178,
            53,
            169,
            151,
            59,
            14,
            204,
            191,
            240,
            96,
            168,
            147,
            166,
            242,
            20,
            203,
            240
        };
    }
}
