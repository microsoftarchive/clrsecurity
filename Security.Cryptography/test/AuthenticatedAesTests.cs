// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the AuthenticatedAes class
    /// </summary>
    [TestClass]
    public class AuthenticatedAesTests
    {
        /// <summary>
        ///     Tests for creating default Authenticated AES intsances
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCreateTest()
        {
            // AuthenticatedAesCng should be the default implementation
            using (AuthenticatedAes aes = AuthenticatedAes.Create())
            {
                Assert.IsInstanceOfType(aes, typeof(AuthenticatedAesCng));
            }

            using (AuthenticatedAes aes = AuthenticatedAes.Create("AuthenticatedAesCng"))
            {
                Assert.IsInstanceOfType(aes, typeof(AuthenticatedAesCng));
            }

            Assert.IsNull(AuthenticatedAes.Create("AuthenticatedAesDoesntExist"));
            Assert.IsNull(AuthenticatedAes.Create("AesCng"));
        }
    }
}
