// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the AuthenticatedSymmetricAlgorithm class
    /// </summary>
    [TestClass]
    public class AuthenticatedSymmetricAlgorithmTests
    {
        /// <summary>
        ///     Tests for creating default Authenticated symmetric algorithm intsances
        /// </summary>
        [TestMethod]
        public void AuthenticatedSymmetricAlgorithmCreateTest()
        {
            // AuthenticatedAesCng should be the default implementation
            using (AuthenticatedSymmetricAlgorithm alg = AuthenticatedSymmetricAlgorithm.Create())
            {
                Assert.IsInstanceOfType(alg, typeof(AuthenticatedAesCng));
            }

            using (AuthenticatedSymmetricAlgorithm alg = AuthenticatedSymmetricAlgorithm.Create("AuthenticatedAesCng"))
            {
                Assert.IsInstanceOfType(alg, typeof(AuthenticatedAesCng));
            }

            Assert.IsNull(AuthenticatedAes.Create("AuthenticatedAesDoesntExist"));
            Assert.IsNull(AuthenticatedAes.Create("AesCng"));
        }

        /// <summary>
        ///     Test for the IsValidTagSize method
        /// </summary>
        [TestMethod]
        public void AuthenticatedSymmetricAlgorithmValidTagSizeTest()
        {
            using (AuthenticatedSymmetricAlgorithm alg = AuthenticatedSymmetricAlgorithm.Create())
            {
                foreach (KeySizes tagSizeRange in alg.LegalTagSizes)
                {
                    Assert.IsTrue(alg.ValidTagSize(tagSizeRange.MinSize));
                    Assert.IsTrue(alg.ValidTagSize(tagSizeRange.MaxSize));

                    if (tagSizeRange.MinSize != tagSizeRange.MaxSize)
                    {
                        for (int tagSize = tagSizeRange.MinSize; tagSize < tagSizeRange.MaxSize; tagSize += tagSizeRange.SkipSize)
                        {
                            Assert.IsTrue(alg.ValidTagSize(tagSize));
                        }
                    }
                }

                Assert.IsFalse(alg.ValidTagSize(0));
                Assert.IsFalse(alg.ValidTagSize(Int32.MaxValue));
            }
        }
    }
}
