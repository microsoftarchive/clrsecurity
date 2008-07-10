// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for RNGCng
    /// </summary>
    [TestClass]
    public class RNGCngTests
    {
        [TestMethod]
        public void RNGCngPositiveTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] randomBytes = new byte[128];
                rng.GetBytes(randomBytes);
                Assert.IsTrue(AreRandomBytes(randomBytes));
            }
        }

        [TestMethod]
        public void RNGCngLargeTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] randomBytes = new byte[10485760];        // 10 MB
                rng.GetBytes(randomBytes);
                Assert.IsTrue(AreRandomBytes(randomBytes));
            }
        }

        [TestMethod]
        public void RNGCngZeroTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] randomBytes = new byte[128];
                rng.GetBytes(randomBytes);
                Assert.IsTrue(true);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void RNGCngNegativeTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                rng.GetBytes(null);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(NotImplementedException))]
        public void RNGCngNonZeroNegativeTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] randomBytes = new byte[128];
                rng.GetNonZeroBytes(randomBytes);
            }
        }

        /// <summary>
        ///     Number of one bits in each possible 4 bit number
        /// </summary>
        private static uint[] s_oneCount = new uint[] { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

        /// <summary>
        ///     Utility to check that we got something that looks like random bytes.  We basically just
        ///     check to see tha we have approximately the same number of 1 and 0 bits.
        /// </summary>
        private static bool AreRandomBytes(byte[] bytes)
        {
            ulong ones = 0;

            for (int i = 0; i < bytes.Length; ++i)
            {
                ones += s_oneCount[bytes[i] & 0x0F];
                ones += s_oneCount[(bytes[i] & 0xF0) >> 4];
            }

            ulong zeros = ((uint)bytes.Length * 8) - ones;
            ulong difference = (ones > zeros) ? ones - zeros : zeros - ones;

            return ((double)difference / (double)ones) <= 0.1;
        }
    }
}
