using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace Encryption.Symmetrical
{
    [TestFixture]
    public abstract class SymmetricalEncryptionTestsBase
    {
        public const string Plaintext = "This is our plaintext12345678901";
        public const int BlockSizeBits = 128;
        public const int KeySizeBits = 256;
        public const int SaltSizeBits = 512;
        public const int SaltIterations = 655331;

        [Test]
        public void CanEncryptDecrypt()
        {
            var enc = Encoding.UTF8;
            var input = enc.GetBytes(Plaintext);
            var pwd = "my password";
            using (var csp = GetCsp(pwd))
            {
                var e = Encrypt(csp.CreateEncryptor(), input);
                var d = Decrypt(csp.CreateDecryptor(), e);
                var output = enc.GetString(d);
                Assert.AreEqual(Plaintext, output);
            }
        }

        byte[] Decrypt(ICryptoTransform transform, byte[] encrypted)
        {
            using (var ms = new MemoryStream(encrypted, false))
            using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
            {
                var len = encrypted.Length;
                var ba = new byte[len];
                len = cs.Read(ba, 0, len);
                return ba.Take(len).ToArray();
            }
        }

        byte[] Encrypt(ICryptoTransform transform, byte[] input)
        {
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
            {
                cs.Write(input, 0, input.Length);
                cs.FlushFinalBlock();
                var encrypted = ms.GetBuffer().Take((int) ms.Length).ToArray();
                return encrypted;
            }
        }

        AesCryptoServiceProvider GetCsp(string pwd)
        {
            var csp = new AesCryptoServiceProvider
            {
                Mode = CipherMode.CBC,
                BlockSize = BlockSizeBits,
                Padding = PaddingMode.PKCS7,
                Key = GetKey(pwd),
                IV = GetIv()
            };
            return csp;
        }

        byte[] GetIv()
        {
            var b = new byte[BlockSizeBits/8];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetNonZeroBytes(b);
            return b;
        }

        protected abstract byte[] GetKey(string pwd);
    }
}