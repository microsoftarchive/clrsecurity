// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Tests for symmetric algorithm verification functionality.
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics
    /// </summary>
    [TestClass]
    public class SymmetricAlgorithmVerifierTests
    {
        /// <summary>
        ///     Test to ensure that the verifier does not interfere with a successful round trip
        /// </summary>
        [TestMethod]
        public void SymmetricAlgorithmVerifierPositiveAesTest()
        {
            Assert.IsTrue(RoundTripHelper(typeof(AesManaged),
                                          (enc) => { },
                                          typeof(AesManaged),
                                          (dec) => { }));
        }

        /// <summary>
        ///     Test to ensure that the verifier does not interfere with a successful round trip between two
        ///     different implementations of the same algorithm
        /// </summary>
        [TestMethod]
        public void SymmetricAlgorithmVerifierPositiveAlternateAesAlgorithmsTest()
        {
            if (Environment.OSVersion.Version.Major >= 6 ||
                (Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Major >= 1))
            {
                Assert.IsTrue(RoundTripHelper(typeof(AesManaged),
                                              (enc) => { },
                                              typeof(AesCryptoServiceProvider),
                                              (dec) => { }));
            }
            else
            {
                // Only run the test on XP+
                Assert.IsTrue(true);
            }
        }

        /// <summary>
        ///     Test to ensure that changing the key of a symmetric algorithm results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void SymmetricAlgorithmVerifierNegativeKeyTest()
        {
            RoundTripHelper(typeof(AesManaged),
                            (enc) => { },
                            typeof(AesManaged),
                            (dec) => { dec.GenerateKey(); });
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that changing the IV of a symmetric algorithm results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void SymmetricAlgorithmVerifierNegativeIVTest()
        {
            RoundTripHelper(typeof(AesManaged),
                            (enc) => { },
                            typeof(AesManaged),
                            (dec) => { dec.GenerateIV(); });
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that changing the CipherMode of a symmetric algorithm results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException), "Cipher mode mismatch.\n    Encryption: System.Security.Cryptography.CipherMode.CBC\n    Decryption: System.Security.Cryptography.CipherMode.ECB")]
        public void SymmetricAlgorithmVerifierNegativeCipherModeTest()
        {
            RoundTripHelper(typeof(AesManaged),
                (enc) => { enc.Mode = CipherMode.CBC; },
                typeof(AesManaged),
                (dec) => { dec.Mode = CipherMode.ECB; });
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that changing the PaddingMode of a symmetric algorithm results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException), "Padding mode mismatch.\n    Encryption: System.Security.Cryptography.PaddingMode.PKCS7\n    Decryption: System.Security.Cryptography.PaddingMode.Zeros")]
        public void SymmetricAlgorithmVerifierNegativePaddingModeTest()
        {
            RoundTripHelper(typeof(AesManaged),
                            (enc) => { enc.Padding = PaddingMode.PKCS7; },
                            typeof(AesManaged),
                            (dec) => { dec.Padding = PaddingMode.Zeros; });
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that encrypting and decrypting with different algorithms results in the
        ///     correct diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException), "Algorithm mismatch.\n    Encryption: System.Security.Cryptography.AesManaged\n    Decryption: System.Security.Cryptography.RijndaelManaged")]
        public void SymmetricAlgorithmVerifierNegativeAlgorithmTest()
        {
            RoundTripHelper(typeof(AesManaged),
                            (enc) => { },
                            typeof(RijndaelManaged),
                            (dec) => { });
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that changing the BlockSize of a symmetric algorithm results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException), "Block size mismatch.\n    Encryption: 128\n    Decryption: 256")]
        public void SymmetricAlgorithmVerifierNegativeBlockSizeTest()
        {
            RoundTripHelper(typeof(RijndaelManaged),
                            (enc) => { enc.BlockSize = 128; },
                            typeof(RijndaelManaged),
                            (dec) => { dec.BlockSize = 256; });
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that changing the FeedbackSize of a symmetric algorithm results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException), "Feedback size mismatch.\n    Encryption: 8\n    Decryption:  16")]
        public void SymmetricAlgorithmVerifierNegativeFeedbackSizeTest()
        {
            RoundTripHelper(typeof(TripleDESCryptoServiceProvider),
                            (enc) => { enc.Mode = CipherMode.CFB; enc.FeedbackSize = 8; },
                            typeof(TripleDESCryptoServiceProvider),
                            (dec) => { dec.Mode = CipherMode.CFB; dec.FeedbackSize = 16; });
            Assert.Fail("Decryption should have failed.");
        }

        [TestMethod]
        public void SymmetricAlgorithmVerifierNegativeThreadingTest()
        {
            // Synchronization state
            object lockCheckParameter = new object();
            SymmetricAlgorithm encryptorInstance = null;
            bool lockChecked = false;

            SymmetricAlgorithmDiagnosticOptions diagnosticOptions = new SymmetricAlgorithmDiagnosticOptions
            {
                CheckThreadSafety = true,
                LockCheckParameter = lockCheckParameter,
                LockCheckCallback = delegate(CryptographyLockContext<SymmetricAlgorithm> lockCheck)
                {
                    Assert.AreSame(lockCheck.Parameter, lockCheckParameter, "Unexpected lock check parameter");
                    Assert.AreSame(lockCheck.Algorithm, encryptorInstance, "Unexpected algorithm check parameter");
                    lockChecked = true;
                    return false;
                }
            };

            // Encryption state
            bool encryptionSucceeded = true;
            Exception encryptionException = null;

            try
            {
                encryptorInstance = new AesManaged();
                SymmetricAlgorithm encryptor = encryptorInstance.EnableLogging(diagnosticOptions);

                // Thread to do the encryption
                Thread encryptionThread = new Thread(delegate()
                {
                    try
                    {
                        using (MemoryStream ms = new MemoryStream())
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            byte[] plainText = Encoding.UTF8.GetBytes("Secret round trip message");
                            cs.Write(plainText, 0, plainText.Length);
                            cs.FlushFinalBlock();
                        }

                        encryptionSucceeded = true;
                    }
                    catch (Exception e)
                    {
                        encryptionException = e;
                        encryptionSucceeded = false;
                    }
                });

                encryptionThread.Start();
                encryptionThread.Join();
            }
            finally
            {
                if (encryptorInstance != null)
                    (encryptorInstance as IDisposable).Dispose();
            }

            // Verify that our lock check was called, that we failed encryption, and that we got the correct exception
            Assert.IsTrue(lockChecked, "Lock check callback was not performed");
            Assert.IsFalse(encryptionSucceeded, "Encryption should not have succeeded");
            Assert.IsInstanceOfType(encryptionException, typeof(CryptographicDiagnosticException), "Did not get expected exception");
        }

        /// <summary>
        ///     Utility to encapsulate round-tripping ciphertext
        /// </summary>
        private static bool RoundTripHelper(Type encryptionAlgorithm,
                                            Action<SymmetricAlgorithm> encryptionSetup,
                                            Type decryptionAlgorithm,
                                            Action<SymmetricAlgorithm> decryptionSetup)
        {
            // Encryption parameters
            byte[] key = null;
            byte[] iv = null;
            CipherMode cipherMode = CipherMode.CBC;
            PaddingMode paddingMode = PaddingMode.None;

            // Round tripping data
            byte[] plainText = Encoding.UTF8.GetBytes("Secret round trip message");
            byte[] cipherText = null;
            SymmetricEncryptionState encryptionState = null;

            SymmetricAlgorithm encryptionObject = null;
            try
            {
                // Setup the encryption algorithm
                encryptionObject = (SymmetricAlgorithm)Activator.CreateInstance(encryptionAlgorithm);
                encryptionSetup(encryptionObject);
                encryptionObject = encryptionObject.EnableLogging();

                // Encrypt the data
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptionObject.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainText, 0, plainText.Length);
                    cs.FlushFinalBlock();

                    cipherText = ms.ToArray();
                }

                // Save the encryption parameters
                key = encryptionObject.Key;
                iv = encryptionObject.IV;
                cipherMode = encryptionObject.Mode;
                paddingMode = encryptionObject.Padding;
                encryptionState = encryptionObject.GetLastEncryptionState();
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

                decryptionSetup(decryptionObject);
                decryptionObject = decryptionObject.EnableDecryptionVerification(encryptionState);

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

            if (roundTrip.Length != plainText.Length)
            {
                return false;
            }

            for (int i = 0; i < roundTrip.Length; ++i)
            {
                if (roundTrip[i] != plainText[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
