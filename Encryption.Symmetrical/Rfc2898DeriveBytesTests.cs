using System;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Encryption.Symmetrical
{
    [TestFixture]
    public class Rfc2898DeriveBytesTests : IDisposable
    {
        readonly RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();

        [Test]
        public void MsImplementationMatchesOurImplementation()
        {
            const string pwd = "mypwd";
            const int iterations = 10000;
            const int keySizeBits = 256;
            var salt = new byte[16];
            _rng.GetBytes(salt);
            using (var ms = new Rfc2898DeriveBytes(pwd, salt, iterations))
            using (var our = new Rfc2898DeriveBytesSha1(pwd, salt, iterations))
            {
                var a = ms.GetBytes(keySizeBits/8);
                var b = our.GetBytes(keySizeBits/8);
                a.AssertEquals(b);
            }
        }

        public void Dispose()
        {
            _rng.Dispose();
        }
    }
}
