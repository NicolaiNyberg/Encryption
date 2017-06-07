using System.Collections.Generic;
using NUnit.Framework;

namespace Encryption.Symmetrical
{
    public static class AssertExtensions
    {
        public static void AssertEquals<T>(this IList<T> a, IList<T> b)
        {
            if (a == null && b == null)
                return;
            Assert.True(a != null);
            Assert.True(b != null);
            Assert.AreEqual(a.Count, b.Count, "Array length");
            for (var i = 0; i < a.Count; i++)
                Assert.AreEqual(a[i], b[i], $"Array element {i}");
        }
    }
}
