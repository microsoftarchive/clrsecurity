// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the CngProvider2 class
    /// </summary>
    [TestClass]
    public class CngProvider2Tests
    {
        /// <summary>
        ///     Tests to validate the built in providers have the correct values
        /// </summary>
        [TestMethod]
        public void CngProvider2ValueTest()
        {
            Assert.AreEqual("Microsoft Primitive Provider", CngProvider2.MicrosoftPrimitiveAlgorithmProvider.Provider);
        }
    }
}
