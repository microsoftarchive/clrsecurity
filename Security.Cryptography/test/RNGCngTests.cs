// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Linq;
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
        public void RNGCngPropertiesTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                Assert.AreEqual(CngProvider2.MicrosoftPrimitiveAlgorithmProvider, rng.Provider);
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
        ///     Utility to check that we got something that looks like random bytes.  We basically just
        ///     build up a list of the count of each possible set of 4 bits that we get and ensure that
        ///     given a sufficient number of data points we have a relatively even distribution.
        /// </summary>
        private static bool AreRandomBytes(byte[] bytes)
        {
            long[] nibbles = new long[16];

            foreach (byte b in bytes)
            {
                nibbles[b & 0xF]++;
                nibbles[(b >> 4) & 0xF]++;
            }

            long total = nibbles.Sum();
            double average = nibbles.Average();
            var deltas = from nibble in nibbles
                         select Math.Ceiling(Math.Abs(nibble - average)) / total;

            return deltas.All(d => d < 0.05);
        }
    }
}
