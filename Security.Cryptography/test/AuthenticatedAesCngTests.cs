// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///    This is a test class for Cng crypto classes.
    ///</summary>
    [TestClass]
    public class AuthenticatedAesCngTests
    {
        /// <summary>
        ///     Test to validate the default property values in an AuthenticatedAesCng instance
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngPropertiesTest()
        {
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                Assert.AreEqual(128, aes.BlockSize);
                Assert.AreEqual(CngChainingMode.Gcm, aes.CngMode);
                Assert.AreEqual(256, aes.KeySize);
                Assert.AreEqual(128, aes.TagSize);
                Assert.AreEqual(CngProvider2.MicrosoftPrimitiveAlgorithmProvider, aes.Provider);
            }
        }

        /// <summary>
        ///     Test to ensure that we can chain multiple blocks of data through the AES transform and get
        ///     correct results.
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngChainingTest()
        {
            byte[] plaintext = new byte[20 * 1024];
            byte[] iv = new byte[12];
            byte[] authenticatedData = new byte[1024];

            using (RNGCng rng = new RNGCng())
            {
                rng.GetBytes(plaintext);
                rng.GetBytes(iv);
                rng.GetBytes(authenticatedData);
            }

            foreach (CngChainingMode chainingMode in new CngChainingMode[] { CngChainingMode.Ccm, CngChainingMode.Gcm })
            {
                using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
                {
                    aes.AuthenticatedData = authenticatedData;
                    aes.CngMode = chainingMode;
                    aes.IV = iv;

                    // Encrypt the whole block of data at once
                    byte[] wholeCiphertext = null;
                    byte[] wholeTag = null;
                    using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                    {
                        wholeCiphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                        wholeTag = encryptor.GetTag();
                    }

                    // Encrypt it in chunks
                    byte[] blockCiphertext = null;
                    byte[] blockTag = null;
                    using (MemoryStream ms = new MemoryStream())
                    using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        int chunkSize = 128;
                        for (int offset = 0; offset < plaintext.Length; offset += chunkSize)
                        {
                            cs.Write(plaintext, offset, chunkSize);
                        }
                        cs.FlushFinalBlock();

                        blockCiphertext = ms.ToArray();
                        blockTag = encryptor.GetTag();
                    }

                    // Make sure we got the same results in both cases
                    Assert.IsTrue(Util.CompareBytes(wholeCiphertext, blockCiphertext));
                    Assert.IsTrue(Util.CompareBytes(wholeTag, blockTag));

                    aes.Tag = wholeTag;

                    // Decrypt the whole block of data at once
                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        byte[] wholePlaintext = decryptor.TransformFinalBlock(wholeCiphertext, 0, wholeCiphertext.Length);
                        Assert.IsTrue(Util.CompareBytes(plaintext, wholePlaintext));
                    }

                    // Decrypt the data in chunks
                    using (MemoryStream ms = new MemoryStream())
                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        int chunkSize = 128;
                        for (int offset = 0; offset < blockCiphertext.Length; offset += chunkSize)
                        {
                            cs.Write(blockCiphertext, offset, chunkSize);
                        }
                        cs.FlushFinalBlock();

                        byte[] blockPlaintext = ms.ToArray();
                        Assert.IsTrue(Util.CompareBytes(plaintext, blockPlaintext));
                    }
                }
            }
        }

        private class RoundTripTestData
        {
            public CngChainingMode ChainingMode;
            public byte[] Plaintext;
            public byte[] Key;
            public byte[] IV;
            public byte[] AuthenticationData;
            public byte[] ExpectedCiphertext;
            public byte[] ExpectedTag;
        }

        /// <summary>
        ///    AES GCM single round trip test
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngGcmRoundTripTest()
        {
            var testData = new RoundTripTestData
            {
                ChainingMode = CngChainingMode.Gcm,
                Plaintext =  new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
                ExpectedCiphertext = new byte[] { 0x54, 0x2d, 0x26, 0x15, 0x9c, 0xb3, 0x6e, 0x21, 0xd2, 0x58, 0xcf, 0x9c, 0x6e, 0xce, 0xfb, 0x5f },
                ExpectedTag = new byte[] { 0xd8, 0x80, 0xc3, 0x7a, 0x5a, 0x93, 0xc4, 0x7c, 0xd2, 0x44, 0x2d, 0x7d, 0x6b, 0xfa, 0x5c, 0x02 }
            };

            AuthenticatedAesCngRoundTripTest(testData);
        }

        /// <summary>
        ///    AES GCM two block round trip test
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngGcmTwoBlocksRoundTripTest()
        {
            var testData = new RoundTripTestData
            {
                ChainingMode = CngChainingMode.Gcm,
                Plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
                ExpectedCiphertext = new byte[] { 0x54, 0x2d, 0x26, 0x15, 0x9c, 0xb3, 0x6e, 0x21, 0xd2, 0x58, 0xcf, 0x9c, 0x6e, 0xce, 0xfb, 0x5f, 0x8c, 0x2a, 0xb8, 0x22, 0x4d, 0x6d, 0xd0, 0x02, 0x76, 0xd2, 0xab, 0x22, 0xa2, 0xd6, 0xee, 0x5b },
                ExpectedTag = new byte[] { 0xc1, 0x34, 0x38, 0x0b, 0xc3, 0x87, 0x7c, 0xf5, 0x2f, 0x3b, 0xa9, 0xfe, 0x3c, 0x69, 0x4b, 0x9f }
            };

            AuthenticatedAesCngRoundTripTest(testData);
        }

        /// <summary>
        ///     AES GCM auth data round trip test
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngGcmAuthDataRoundTripTest()
        {
            var testData = new RoundTripTestData
            {
                ChainingMode = CngChainingMode.Gcm,
                Plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
                AuthenticationData = new byte[] { 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 },
                ExpectedCiphertext = new byte[] { 0x54, 0x2d, 0x26, 0x15, 0x9c, 0xb3, 0x6e, 0x21, 0xd2, 0x58, 0xcf, 0x9c, 0x6e, 0xce, 0xfb, 0x5f },
                ExpectedTag = new byte[] { 0xb4, 0xb9, 0x6b, 0xea, 0x33, 0x41, 0xeb, 0x4f, 0x19, 0xc8, 0x25, 0x92, 0xfa, 0x1b, 0x2b, 0xf1 }
            };

            AuthenticatedAesCngRoundTripTest(testData);
        }

        /// <summary>
        ///     AES GCM encrypt multiple arrays round trip
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngGcmMultiRoundTripTest()
        {
            byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
            byte[] plaintext2 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
            byte[] expectedCiphertext = new byte[]
            {
                0x54, 0x2d, 0x26, 0x15, 0x9c, 0xb3, 0x6e, 0x21, 0xd2, 0x58, 0xcf, 0x9c, 0x6e, 0xce, 0xfb, 0x5f,
                0x8c, 0x2a, 0xb8, 0x22, 0x4d, 0x6d, 0xd0, 0x02, 0x76, 0xd2, 0xab, 0x22, 0xa2, 0xd6, 0xee, 0x5b
            };
            byte[] expectedTag = new byte[] { 0xc1, 0x34, 0x38, 0x0b, 0xc3, 0x87, 0x7c, 0xf5, 0x2f, 0x3b, 0xa9, 0xfe, 0x3c, 0x69, 0x4b, 0x9f };
            byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
            byte[] iv = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

            using (AuthenticatedAesCng gcm = new AuthenticatedAesCng())
            {
                gcm.CngMode = CngChainingMode.Gcm;
                gcm.Key = key;
                gcm.IV = iv;
                gcm.Tag = expectedTag;

                // Encrypt
                byte[] ciphertext = null;
                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = gcm.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    // Push through two blocks and call final to get the tag.
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.Write(plaintext2, 0, plaintext2.Length);
                    cs.FlushFinalBlock();

                    ciphertext = ms.ToArray();

                    // Check if the ciphertext and tag are what are expected.
                    Assert.IsTrue(Util.CompareBytes(expectedCiphertext, ciphertext));
                    Assert.IsTrue(Util.CompareBytes(expectedTag, encryptor.GetTag()));
                }

                // Decrypt
                using (MemoryStream ms = new MemoryStream())
                using (ICryptoTransform decryptor = gcm.CreateDecryptor())
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    cs.Write(ciphertext, 0, ciphertext.Length / 2);
                    cs.Write(ciphertext, ciphertext.Length / 2, ciphertext.Length / 2);

                    cs.FlushFinalBlock();

                    byte[] decrypted = ms.ToArray();

                    // Compare the decrypted text to the initial ciphertext.
                    byte[] fullPlaintext = new byte[plaintext.Length + plaintext2.Length];
                    Array.Copy(plaintext, 0, fullPlaintext, 0, plaintext.Length);
                    Array.Copy(plaintext2, 0, fullPlaintext, plaintext.Length, plaintext2.Length);
                    Assert.IsTrue(Util.CompareBytes(fullPlaintext, decrypted));
                }
            }
        }

        /// <summary>
        ///    AES CCM round trip test
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngCcmRoundTripTest()
        {
            var testData = new RoundTripTestData
            {
                ChainingMode = CngChainingMode.Ccm,
                Plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
                ExpectedCiphertext = new byte[] { 0x83, 0x57, 0x54, 0x84, 0x0e, 0x3d, 0x4a, 0x81, 0x42, 0x33, 0x6a, 0xd3, 0x99, 0x9a, 0x3e, 0x03 },
                ExpectedTag = new byte[] { 0xfa, 0xf7, 0xab, 0x3c, 0x9b, 0xbf, 0x1e, 0x10, 0xc8, 0xa3, 0xc9, 0xd8, 0x66, 0x39, 0xa6, 0x77 }
            };

            AuthenticatedAesCngRoundTripTest(testData);
        }

        /// <summary>
        ///    AES CCM round trip with auth data test
        /// </summary>
        [TestMethod]
        public void AuthenticatedAesCngCcmAuthDataRoundTripTest()
        {
            var testData = new RoundTripTestData
            {
                ChainingMode = CngChainingMode.Ccm,
                Plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 },
                IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
                AuthenticationData = new byte[] { 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 },
                ExpectedCiphertext = new byte[] { 0x83, 0x57, 0x54, 0x84, 0x0e, 0x3d, 0x4a, 0x81, 0x42, 0x33, 0x6a, 0xd3, 0x99, 0x9a, 0x3e, 0x03 },
                ExpectedTag = new byte[] { 0x1b, 0x74, 0x18, 0xfd, 0xca, 0x76, 0x3c, 0x61, 0x03, 0x5c, 0x46, 0xa8, 0xe1, 0x77, 0xac, 0x96 }
            };

            AuthenticatedAesCngRoundTripTest(testData);
        }

        /// <summary>
        ///     Perform a round trip test given input and the expected output
        /// </summary>
        private void AuthenticatedAesCngRoundTripTest(RoundTripTestData testData)
        {
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = testData.ChainingMode;
                aes.Key = testData.Key;
                aes.IV = testData.IV;
                aes.AuthenticatedData = testData.AuthenticationData;
                aes.Tag = testData.ExpectedTag;

                // Encrypt
                byte[] ciphertext = null;
                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(testData.Plaintext, 0, testData.Plaintext.Length);
                    cs.FlushFinalBlock();

                    ciphertext = ms.ToArray();

                    // Check if the ciphertext and tag are what are expected.
                    Assert.IsTrue(Util.CompareBytes(testData.ExpectedCiphertext, ciphertext));
                    Assert.IsTrue(Util.CompareBytes(testData.ExpectedTag, encryptor.GetTag()));
                }

                // Decrypt
                using (MemoryStream ms = new MemoryStream())
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    cs.Write(ciphertext, 0, ciphertext.Length);
                    cs.FlushFinalBlock();

                    // Compare the decrypted text to the initial ciphertext.
                    byte[] decrypted = ms.ToArray();
                    Assert.IsTrue(Util.CompareBytes(testData.Plaintext, decrypted));
                }
            }
        }
    }
}
