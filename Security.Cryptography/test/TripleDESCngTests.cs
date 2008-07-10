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
    ///     Unit tests for the TripleDESCng class
    /// </summary>
    [TestClass]
    public class TripleDESCngTests
    {
        /// <summary>
        ///     Basic round trip test
        /// </summary>
        [TestMethod]
        public void TripleDESCngRoundTripTest()
        {
            Assert.IsTrue(RoundTripHelper(Encoding.UTF8.GetBytes("Secret message...")));
        }

        /// <summary>
        ///     Test to make sure we can round trip various numbers of blocks
        /// </summary>
        [TestMethod]
        public void TripleDESCngBlockRoundTripTests()
        {
            int blockSize = 0;
            using (TripleDESCng tdes = new TripleDESCng())
            {
                blockSize = tdes.BlockSize / 8;
            }

            Assert.IsTrue(RoundTripHelper(0), "Zero byte round trip failed");
            Assert.IsTrue(RoundTripHelper(1), "One byte round trip failed");
            Assert.IsTrue(RoundTripHelper(blockSize - 1), "Block size - 1 round trip failed");
            Assert.IsTrue(RoundTripHelper(blockSize), "Block size round trip failed");
            Assert.IsTrue(RoundTripHelper(blockSize + 1), "Block size + 1 round trip failed");
            Assert.IsTrue(RoundTripHelper(blockSize * 2), "Block size * 2 round trip failed");
            Assert.IsTrue(RoundTripHelper(blockSize * 10), "Block size * 10 round trip failed");
            Assert.IsTrue(RoundTripHelper(blockSize * 1024), "Block size * 1024 round trip failed");
        }

        /// <summary>
        ///     Tests to make sure each padding mode works with various block sizes
        /// </summary>
        [TestMethod]
        public void TripleDESCngPaddingRoundTripTests()
        {
            int blockSize = 0;
            using (TripleDESCng tdes = new TripleDESCng())
            {
                blockSize = tdes.BlockSize / 8;
            }

            using (RNGCng rng = new RNGCng())
            {
                byte[] zeroByte = new byte[0];

                byte[] oneByte = new byte[1];
                rng.GetBytes(oneByte);

                byte[] blockMinusOne = new byte[blockSize - 1];
                rng.GetBytes(blockMinusOne);

                byte[] block = new byte[blockSize];
                rng.GetBytes(block);

                byte[] blockPlusOne = new byte[blockSize + 1];
                rng.GetBytes(blockPlusOne);

                foreach (var paddingMode in new PaddingMode[] { PaddingMode.ANSIX923, PaddingMode.ISO10126, PaddingMode.PKCS7 })
                {
                    Assert.IsTrue(RoundTripHelper(zeroByte, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { tdes.Padding = paddingMode; }), paddingMode.ToString() + " - zeroByte");
                    Assert.IsTrue(RoundTripHelper(oneByte, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { tdes.Padding = paddingMode; }), paddingMode.ToString() + " - oneByte");
                    Assert.IsTrue(RoundTripHelper(blockMinusOne, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { tdes.Padding = paddingMode; }), paddingMode.ToString() + " - blockMinusOne");
                    Assert.IsTrue(RoundTripHelper(block, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { tdes.Padding = paddingMode; }), paddingMode.ToString() + " - block");
                    Assert.IsTrue(RoundTripHelper(blockPlusOne, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { tdes.Padding = paddingMode; }), paddingMode.ToString() + " - blockPlusOne");
                }
            }
        }

        /// <summary>
        ///     Tests to make sure each cipher mode works with various block sizes
        /// </summary>
        [TestMethod]
        public void TripleDESCngModeRoundTripTests()
        {
            int blockSize = 0;
            using (TripleDESCng tdes = new TripleDESCng())
            {
                blockSize = tdes.BlockSize / 8;
            }

            using (RNGCng rng = new RNGCng())
            {
                for (int i = 1; i <= 10; ++i)
                {
                    byte[] data = new byte[i * blockSize];
                    rng.GetBytes(data);

                    foreach (var cipherMode in new CipherMode[] { CipherMode.CBC, CipherMode.ECB, CipherMode.CFB })
                    {
                        Assert.IsTrue(RoundTripHelper(data, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { tdes.Mode = cipherMode; }), i.ToString() + " blocks - " + cipherMode.ToString());
                    }
                }
            }
        }

        /// <summary>
        ///     Tests to make sure TripleDESCng interops with the other 3DES implementations
        /// </summary>
        [TestMethod]
        public void TripleDESCngInteropTests()
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] data = new byte[1001];
                rng.GetBytes(data);

                Assert.IsTrue(RoundTripHelper(data, typeof(TripleDESCng), typeof(TripleDESCryptoServiceProvider), (tdes) => { }), "CNG/CSP interop failed");
                Assert.IsTrue(RoundTripHelper(data, typeof(TripleDESCryptoServiceProvider), typeof(TripleDESCng), (tdes) => { }), "CSP/CNG interop failed");
            }
        }

        /// <summary>
        ///     Utility method to help write AesCng round-trip tests
        /// </summary>
        private static bool RoundTripHelper(int bytes)
        {
            using (RNGCng rng = new RNGCng())
            {
                byte[] data = new byte[bytes];
                rng.GetBytes(data);
                return RoundTripHelper(data);
            }
        }

        /// <summary>
        ///     Utility method to help write AesCng round-trip tests
        /// </summary>
        private static bool RoundTripHelper(byte[] input)
        {
            return RoundTripHelper(input, typeof(TripleDESCng), typeof(TripleDESCng), (tdes) => { });
        }

        /// <summary>
        ///     Utility method to help write AES round-trip tests
        /// </summary>
        private static bool RoundTripHelper(byte[] input,
                                            Type encryptionAlgorithm,
                                            Type decryptionAlgorithm,
                                            Action<SymmetricAlgorithm> encryptionSetup)
        {
            // Encryption parameters
            byte[] key = null;
            byte[] iv = null;
            CipherMode cipherMode = CipherMode.CBC;
            PaddingMode paddingMode = PaddingMode.PKCS7;

            // Round tripping data
            byte[] cipherText = null;

            SymmetricAlgorithm encryptionObject = null;
            try
            {
                // Setup the encryption algorithm
                encryptionObject = (SymmetricAlgorithm)Activator.CreateInstance(encryptionAlgorithm);
                encryptionSetup(encryptionObject);

                // Encrypt the data
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptionObject.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(input, 0, input.Length);
                    cs.FlushFinalBlock();

                    cipherText = ms.ToArray();
                }

                // Save the encryption parameters
                key = encryptionObject.Key;
                iv = encryptionObject.IV;
                cipherMode = encryptionObject.Mode;
                paddingMode = encryptionObject.Padding;
            }
            finally
            {
                if (encryptionObject != null)
                {
                    (encryptionObject as IDisposable).Dispose();
                }
            }

            byte[] roundTrip = null;

            // Now verify the data
            SymmetricAlgorithm decryptionObject = null;
            try
            {
                decryptionObject = (SymmetricAlgorithm)Activator.CreateInstance(decryptionAlgorithm);

                decryptionObject.Key = key;
                decryptionObject.IV = iv;
                decryptionObject.Mode = cipherMode;
                decryptionObject.Padding = paddingMode;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, decryptionObject.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipherText, 0, cipherText.Length);
                    cs.FlushFinalBlock();

                    roundTrip = ms.ToArray();
                }
            }
            finally
            {
                if (decryptionObject != null)
                {
                    (decryptionObject as IDisposable).Dispose();
                }
            }

            return CompareBytes(input, roundTrip);
        }

        /// <summary>
        ///     Utility method to compare two byte arrays for equality
        /// </summary>
        private static bool CompareBytes(byte[] lhs, byte[] rhs)
        {
            if (lhs.Length != rhs.Length)
            {
                return false;
            }

            for (int i = 0; i < lhs.Length; ++i)
            {
                if (lhs[i] != rhs[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
