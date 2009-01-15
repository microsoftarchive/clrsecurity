// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the HMACSHA512Cng class
    /// </summary>
    [TestClass]
    public sealed class HMACSHA512CngTets
    {
        /// <summary>
        ///     Comparison test with built-in HMACSHA512
        /// </summary>
        [TestMethod]
        public void HMACSHA512Test()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] key = new byte[128];
                rng.GetBytes(key);

                using (HMACSHA512 bclHmac = new HMACSHA512(key))
                using (HMACSHA512Cng cngHmac = new HMACSHA512Cng(key))
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
        ///     Make sure the properties of HMACSHA512 agree with the BCL properties
        /// </summary>
        [TestMethod]
        public void HMACSH512PropertyTest()
        {
            using (HMACSHA512 bclHmac = new HMACSHA512())
            using (HMACSHA512Cng cngHmac = new HMACSHA512Cng())
            {
                Assert.AreEqual(bclHmac.HashName, cngHmac.HashName);
                Assert.AreEqual(bclHmac.HashSize, cngHmac.HashSize);
                Assert.AreEqual(bclHmac.InputBlockSize, cngHmac.InputBlockSize);
                Assert.AreEqual(bclHmac.OutputBlockSize, cngHmac.OutputBlockSize);
            }
        }
    }
}
