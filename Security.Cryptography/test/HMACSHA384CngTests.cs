// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the HMACSHA384Cng class
    /// </summary>
    [TestClass]
    public sealed class HMACSHA384CngTets
    {
        /// <summary>
        ///     Comparison test with built-in HMACSHA384
        /// </summary>
        [TestMethod]
        public void HMACSHA384CngTest()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] key = new byte[128];
                rng.GetBytes(key);

                using (HMACSHA384 bclHmac = new HMACSHA384(key))
                using (HMACSHA384Cng cngHmac = new HMACSHA384Cng(key))
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
        ///     Make sure the properties of HMACSHA384 agree with the BCL properties
        /// </summary>
        [TestMethod]
        public void HMACSH384CngPropertyTest()
        {
            using (HMACSHA384 bclHmac = new HMACSHA384())
            using (HMACSHA384Cng cngHmac = new HMACSHA384Cng())
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
