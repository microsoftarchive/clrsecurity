// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the HMACSHA256Cng class
    /// </summary>
    [TestClass]
    public sealed class HMACSHA256CngTets
    {
        /// <summary>
        ///     Comparison test with built-in HMACSHA256
        /// </summary>
        [TestMethod]
        public void HMACSHA256CngTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] key = new byte[64];
                rng.GetBytes(key);

                using (HMACSHA256 bclHmac = new HMACSHA256(key))
                using (HMACSHA256Cng cngHmac = new HMACSHA256Cng(key))
                {
                    for (int i = 0; i < 10; ++i)
                    {
                        byte[] data = new byte[2048];
                        rng.GetBytes(data);

                        byte[] bcl = bclHmac.ComputeHash(data);
                        byte[] cng = cngHmac.ComputeHash(data);

                        Assert.IsTrue(Util.CompareBytes(bcl, cng));
                    }
                }
            }
        }

        /// <summary>
        ///     Make sure the properties of HMACSHA256 agree with the BCL properties
        /// </summary>
        [TestMethod]
        public void HMACSH256CngPropertyTest()
        {
            using (HMACSHA256 bclHmac = new HMACSHA256())
            using (HMACSHA256Cng cngHmac = new HMACSHA256Cng())
            {
                Assert.AreEqual(bclHmac.HashName, cngHmac.HashName);
                Assert.AreEqual(bclHmac.HashSize, cngHmac.HashSize);
                Assert.AreEqual(bclHmac.InputBlockSize, cngHmac.InputBlockSize);
                Assert.AreEqual(bclHmac.OutputBlockSize, cngHmac.OutputBlockSize);

                Assert.AreEqual(CngProvider2.MicrosoftPrimitiveAlgorithmProvider, cngHmac.Provider);
            }
        }
    }
}
