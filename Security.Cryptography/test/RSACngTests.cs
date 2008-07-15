// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Test cases for the RSACng class
    /// </summary>
    [TestClass]
    public sealed class RSACngTests
    {
        /// <summary>
        ///     Test that we can round trip a signature using PKCS #1 padding
        /// </summary>
        [TestMethod]
        public void RSACngSignaturePkcsRoundTripTest()
        {
            using (RSACng rsa = new RSACng())
            using (RNGCng rng = new RNGCng())
            {
                rsa.SignaturePaddingMode = AsymmetricPaddingMode.Pkcs1;

                byte[] data = new byte[2000];
                rng.GetBytes(data);

                byte[] signature = rsa.SignData(data);
                Assert.IsTrue(rsa.VerifyData(data, signature));
            }
        }

        /// <summary>
        ///     Test that we can round trip a signature using PSS padding
        /// </summary>
        [TestMethod]
        public void RSACngSignaturePssRoundTripTest()
        {
            using (RSACng rsa = new RSACng())
            using (RNGCng rng = new RNGCng())
            {
                rsa.SignaturePaddingMode = AsymmetricPaddingMode.Pss;

                byte[] data = new byte[2000];
                rng.GetBytes(data);

                byte[] signature = rsa.SignData(data);
                Assert.IsTrue(rsa.VerifyData(data, signature));
            }
        }

        /// <summary>
        ///     Test that we can round trip ciphertext using no padding
        /// </summary>
        [TestMethod]
        public void RSACngEncryptionPkcsRoundTripTest()
        {
            using (RSACng rsa = new RSACng())
            {
                rsa.EncryptionPaddingMode = AsymmetricPaddingMode.Pkcs1;

                string secret = "Secret message";
                byte[] plaintext = Encoding.UTF8.GetBytes(secret);

                byte[] encrypted = rsa.EncryptValue(plaintext);
                byte[] decrypted = rsa.DecryptValue(encrypted);

                string rtSecret = Encoding.UTF8.GetString(decrypted);
                Assert.IsTrue(String.Equals(secret, rtSecret, StringComparison.Ordinal));
            }
        }

        /// <summary>
        ///     Test that we can round trip ciphertext using no padding
        /// </summary>
        [TestMethod]
        public void RSACngEncryptionOaepRoundTripTest()
        {
            using (RSACng rsa = new RSACng())
            {
                rsa.EncryptionPaddingMode = AsymmetricPaddingMode.Oaep;

                string secret = "Secret message";
                byte[] plaintext = Encoding.UTF8.GetBytes(secret);

                byte[] encrypted = rsa.EncryptValue(plaintext);
                byte[] decrypted = rsa.DecryptValue(encrypted);

                string rtSecret = Encoding.UTF8.GetString(decrypted);
                Assert.IsTrue(String.Equals(secret, rtSecret, StringComparison.Ordinal));
            }
        }

        /// <summary>
        ///     Make sure that we can import / export an RSA key through XML
        /// </summary>
        [TestMethod]
        public void RSACngXmlRoundTripTest()
        {
            using (RSACng rsa = new RSACng())
            using (RSACng rsaRT = new RSACng())
            using (RNGCng rng = new RNGCng())
            {
                string keyXml = rsa.ToXmlString(false); // The default KSP does not support importing full RSA key blobs
                rsaRT.FromXmlString(keyXml);

                rsa.SignaturePaddingMode = AsymmetricPaddingMode.Pkcs1;
                rsaRT.SignaturePaddingMode = AsymmetricPaddingMode.Pkcs1;

                byte[] data = new byte[2000];
                rng.GetBytes(data);

                byte[] signature = rsa.SignData(data);
                Assert.IsTrue(rsaRT.VerifyData(data, signature));
            }
        }
    }
}
