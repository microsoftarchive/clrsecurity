// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the CngAlgorithm2 class
    /// </summary>
    [TestClass]
    public class CngAlgorithm2Tests
    {
        /// <summary>
        ///     Tests to validate the built in algorithms have the correct values
        /// </summary>
        [TestMethod]
        public void CngAlgorithm2ValueTest()
        {
            Assert.AreEqual("AES", CngAlgorithm2.Aes.Algorithm);
            Assert.AreEqual("RSA", CngAlgorithm2.Rsa.Algorithm);
        }
    }
}
