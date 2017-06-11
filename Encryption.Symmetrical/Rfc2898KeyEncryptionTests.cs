using System;
using System.Security.Cryptography;

namespace Encryption.Symmetrical
{
    public class Rfc2898KeyEncryptionTestsSha1 : Rfc2898KeyEncryptionTests
    {
        public Rfc2898KeyEncryptionTestsSha1() : base((p, s, i) => new Rfc2898DeriveBytesSha1(p, s, i))
        { }
    }

    public class Rfc2898KeyEncryptionTestsSha256 : Rfc2898KeyEncryptionTests
    {
        public Rfc2898KeyEncryptionTestsSha256() : base((p, s, i) => new Rfc2898DeriveBytesSha256(p, s, i))
        { }
    }

    public class Rfc2898KeyEncryptionTestsSha384 : Rfc2898KeyEncryptionTests
    {
        public Rfc2898KeyEncryptionTestsSha384() : base((p, s, i) => new Rfc2898DeriveBytesSha384(p, s, i))
        { }
    }

    public class Rfc2898KeyEncryptionTestsSha512 : Rfc2898KeyEncryptionTests
    {
        public Rfc2898KeyEncryptionTestsSha512() : base((p, s, i) => new Rfc2898DeriveBytesSha512(p, s, i))
        { }
    }

    public class Rfc2898KeyEncryptionTests : SymmetricalEncryptionTestsBase
    {
        readonly Func<string, byte[], uint, Rfc2898DeriveBytesBase> _tFactory;

        protected Rfc2898KeyEncryptionTests(Func<string, byte[], uint, Rfc2898DeriveBytesBase> tFactory)
        {
            _tFactory = tFactory;
        }

        protected override byte[] GetKey(string pwd)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[SaltSizeBits/8];
                rng.GetNonZeroBytes(salt);
                using (var db = _tFactory(pwd, salt, SaltIterations))
                {
                    var key = db.GetBytes(KeySizeBits/8);
                    return key;
                }
            }
        }
    }
}
