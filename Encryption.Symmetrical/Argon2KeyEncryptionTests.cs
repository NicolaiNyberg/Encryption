using System.Security.Cryptography;
using System.Text;

namespace Encryption.Symmetrical
{
    public class Argon2KeyEncryptionTests : SymmetricalEncryptionTestsBase
    {
        protected override byte[] GetKey(string pwd)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[SaltSizeBits / 8];
                rng.GetNonZeroBytes(salt);
                var h = new Argon2Hasher(KeySizeBits/8);
                var pwdbytes = new UTF8Encoding(false).GetBytes(pwd);
                var key = h.HashRaw(pwdbytes, salt);
                return key;
            }
        }
    }
}
