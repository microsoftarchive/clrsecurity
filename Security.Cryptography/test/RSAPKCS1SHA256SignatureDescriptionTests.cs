// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Test cases for the RSAPKCS1SHA256SignatureDescription class
    /// </summary>
    [TestClass]
    public sealed class RSAPKCS1SHA256SignatureDescriptionTests
    {
        /// <summary>
        ///     Test to ensure that the properties of the signature description contain the expected values
        /// </summary>
        [TestMethod]
        public void RSAPKCS1SHA256SignatureDescriptionPropertiesTest()
        {
            RSAPKCS1SHA256SignatureDescription sd = new RSAPKCS1SHA256SignatureDescription();

            // We should be using RSAPKCS1 for formatting
            Assert.AreEqual(typeof(RSAPKCS1SignatureDeformatter).FullName, sd.DeformatterAlgorithm);
            Assert.AreEqual(typeof(RSAPKCS1SignatureFormatter).FullName, sd.FormatterAlgorithm);

            // We should be using SHA256 as the digest algorithm
            Assert.AreEqual(typeof(SHA256Managed).FullName, sd.DigestAlgorithm);
            using (HashAlgorithm digestAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(sd.DigestAlgorithm))
            {
                Assert.IsInstanceOfType(digestAlgorithm, typeof(SHA256Managed));
            }

            // We should be using RSACryptoServiceProvider as the signature algorithm
            Assert.AreEqual(typeof(RSACryptoServiceProvider).FullName, sd.KeyAlgorithm);
            using (AsymmetricAlgorithm keyAlgorithm = (AsymmetricAlgorithm)CryptoConfig.CreateFromName(sd.KeyAlgorithm))
            {
                Assert.IsInstanceOfType(keyAlgorithm, typeof(RSACryptoServiceProvider));
            }
        }

        /// <summary>
        ///     Test to ensure that the creation methods of the signature description create the expected types
        /// </summary>
        [TestMethod]
        public void RSAPKCS1SHA256SignatureCreateTest()
        {
            RSAPKCS1SHA256SignatureDescription sd = new RSAPKCS1SHA256SignatureDescription();

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // We should be using the PKCS1 signature deformatter
                AsymmetricSignatureDeformatter deformatter = sd.CreateDeformatter(rsa);
                Assert.IsInstanceOfType(deformatter, typeof(RSAPKCS1SignatureDeformatter));

                // We should be using the PKCS1 signature formatter
                AsymmetricSignatureFormatter formatter = sd.CreateFormatter(rsa);
                Assert.IsInstanceOfType(formatter, typeof(RSAPKCS1SignatureFormatter));
            }

            // We should be using SHA256Managed for hashing
            using (HashAlgorithm digestAlgorithm = sd.CreateDigest())
            {
                Assert.IsInstanceOfType(digestAlgorithm, typeof(SHA256Managed));
            }
        }

        /// <summary>
        ///     Test to ensure that we can sign and verify a message through the signature description
        /// </summary>
        [TestMethod]
        public void RSAPKCS1SHA256RoundTripTest()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                RSAPKCS1SHA256SignatureDescription sd = new RSAPKCS1SHA256SignatureDescription();

                using (HashAlgorithm digestAlgorithm = sd.CreateDigest())
                {
                    // Create some data to sign
                    RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                    byte[] data = new byte[1025];
                    rng.GetBytes(data);
                    byte[] hash = digestAlgorithm.ComputeHash(data);

                    // Sign the data
                    AsymmetricSignatureFormatter formatter = sd.CreateFormatter(rsa);
                    byte[] signature = formatter.CreateSignature(hash);
                    Assert.IsNotNull(signature, "Failed to create a signature");

                    // Verify the signature
                    AsymmetricSignatureDeformatter deformatter = sd.CreateDeformatter(rsa);
                    Assert.IsTrue(deformatter.VerifySignature(hash, signature), "Failed to verify signature");
                }
            }
        }
    }
}
