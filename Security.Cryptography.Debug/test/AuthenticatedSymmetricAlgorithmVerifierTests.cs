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
#if !FXONLY_BUILD
    /// <summary>
    ///     Tests for authenticated symmetric algorithm verification functionality.
    /// </summary>
    [TestClass]
    public class AuthenticatedSymmetricAlgorithmVerifierTests
    {
        /// <summary>
        ///     Test to ensure that the verifier does not interfere with a successful round trip
        /// </summary>
        [TestMethod]
        public void AuthenticatedSymmetricAlgorithmVerifierPositiveAesGcmTestPositiveAesGcmTest()
        {
            // GCM mode
            Assert.IsTrue(RoundTripHelper<AuthenticatedAesCng, AuthenticatedAesCng>(
                    (enc) => { enc.CngMode = CngChainingMode.Gcm; },
                    (dec) => { byte[] tag = dec.Tag; dec.CngMode = CngChainingMode.Gcm; dec.Tag = tag; }));

            // CCM mode
            Assert.IsTrue(RoundTripHelper<AuthenticatedAesCng, AuthenticatedAesCng>(
                    (enc) => { enc.CngMode = CngChainingMode.Ccm; },
                    (dec) => { byte[] tag = dec.Tag; dec.CngMode = CngChainingMode.Ccm; dec.Tag = tag; }));
        }
        /// <summary>
        ///     Test to ensure that changing the authenticated of an authenticated symmetric algorithm results
        ///     in the correct diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void AuthenticatedSymmetricAlgorithmVerifierTestNegativeAuthenticatedDataTest()
        {
            Assert.IsTrue(RoundTripHelper<AuthenticatedAesCng, AuthenticatedAesCng>(
                    (enc) => { },
                    (dec) => { dec.AuthenticatedData = new byte[] { 0, 1, 2, 3 }; }));
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that adding authenticated data during encryption results in the correct
        ///     diagnostic message
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void AuthenticatedSymmetricAlgorithmVerifierTestNegativeNoEncAuthenticatedDataTest()
        {
            Assert.IsTrue(RoundTripHelper<AuthenticatedAesCng, AuthenticatedAesCng>(
                    (enc) => { enc.AuthenticatedData = null; },
                    (dec) => { dec.AuthenticatedData = new byte[] { 0, 1, 2, 3 }; }));
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that removing authenticated data from decryption results in the correct
        ///     diagnostic message.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void AuthenticatedSymmetricAlgorithmVerifierTestNegativeNoDecAuthenticatedDataTest()
        {
            Assert.IsTrue(RoundTripHelper<AuthenticatedAesCng, AuthenticatedAesCng>(
                    (enc) => { enc.AuthenticatedData = new byte[] { 1, 2, 3, 4 }; },
                    (dec) => { dec.AuthenticatedData = null; }));
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that switching the authenticated decryption mode results in the correct
        ///     diagnostic message.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void AuthenticatedSymmetricAlgorithmVerifierTestNegativeModeMismatchTest()
        {
            Assert.IsTrue(RoundTripHelper<AuthenticatedAesCng, AuthenticatedAesCng>(
                    (enc) => { enc.CngMode = CngChainingMode.Gcm; },
                    (dec) => { byte[] tag = dec.Tag; dec.CngMode = CngChainingMode.Ccm; dec.Tag = tag; }));
            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that using an authenticated algorithm to encrypt and an unauthenticated
        ///     algorithm to decrypt works.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(CryptographicDiagnosticException))]
        public void AuthenticatedSymmetricAlgorithmVerifierTestNegativeAuthenticationEncryptStandardDecryptTest()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Plaintext");
            byte[] ciphertext = null;

            byte[] key = null;
            SymmetricEncryptionState encryptionState = null;

            using (AuthenticatedSymmetricAlgorithm encryptAes = new AuthenticatedAesCng().EnableLogging())
            {
                key = encryptAes.Key;
                encryptAes.IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

                using (IAuthenticatedCryptoTransform encryptor = encryptAes.CreateAuthenticatedEncryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();

                    ciphertext = ms.ToArray();
                    encryptionState = encryptAes.GetLastEncryptionState();
                }
            }

            using (SymmetricAlgorithm decryptAes = new AesCng().EnableDecryptionVerification(encryptionState))
            {
                decryptAes.Key = key;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, decryptAes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(ciphertext, 0, ciphertext.Length);
                    cs.FlushFinalBlock();
                }
            }

            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Test to ensure that using an unauthenticated algorithm to encrypt and an authenticated
        ///     algorithm to decrypt works.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void AuthenticatedSymmetricAlgorithmVerifierTestNegativeStandardEncryptAuthenticatedDecryptTest()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Plaintext");
            byte[] ciphertext = null;

            byte[] key = null;
            SymmetricEncryptionState encryptionState = null;

            using (SymmetricAlgorithm encryptAes = new AesCng().EnableLogging())
            {
                key = encryptAes.Key;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptAes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();

                    ciphertext = ms.ToArray();
                    encryptionState = encryptAes.GetLastEncryptionState();
                }
            }

            using (SymmetricAlgorithm decryptAes = (new AuthenticatedAesCng() as SymmetricAlgorithm).EnableDecryptionVerification(encryptionState))
            {
                decryptAes.Key = key;
                decryptAes.IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, decryptAes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(ciphertext, 0, ciphertext.Length);
                    cs.FlushFinalBlock();
                }
            }

            Assert.Fail("Decryption should have failed.");
        }

        /// <summary>
        ///     Simple multi-threading verification test
        /// </summary>
        [TestMethod]
        public void AuthenticatedSymmetricAlgorithmVerifierNegativeThreadingTest()
        {
            // Synchronization state
            object lockCheckParameter = new object();
            AuthenticatedSymmetricAlgorithm encryptorInstance = null;
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
                encryptorInstance = new AuthenticatedAesCng();
                AuthenticatedSymmetricAlgorithm encryptor = encryptorInstance.EnableLogging(diagnosticOptions);

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
        private static bool RoundTripHelper<TEncryptionAlgorithm, TDecryptionAlgorithm>(Action<TEncryptionAlgorithm> encryptionSetup,
                                                                                        Action<TDecryptionAlgorithm> decryptionSetup)
            where TEncryptionAlgorithm : AuthenticatedSymmetricAlgorithm, new()
            where TDecryptionAlgorithm : AuthenticatedSymmetricAlgorithm, new()
        {
            // Encryption parameters
            byte[] key = null;
            byte[] iv = null;
            byte[] authenticatedData = Encoding.UTF8.GetBytes("Additional authenticated data");

            // Round tripping data
            byte[] plainText = Encoding.UTF8.GetBytes("Authenticated round trip message");
            byte[] cipherText = null;
            byte[] tag = null;
            AuthenticatedSymmetricEncryptionState encryptionState = null;

            AuthenticatedSymmetricAlgorithm encryptionObject = null;
            try
            {
                // Setup the encryption algorithm
                encryptionObject = new TEncryptionAlgorithm();
                encryptionObject.AuthenticatedData = authenticatedData;
                encryptionObject.IV = new byte[] { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
                encryptionSetup(encryptionObject as TEncryptionAlgorithm);
                encryptionObject = encryptionObject.EnableLogging();

                // Encrypt the data
                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = encryptionObject.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(plainText, 0, plainText.Length);
                    cs.FlushFinalBlock();

                    cipherText = ms.ToArray();
                    tag = encryptor.GetTag();
                }

                // Save the encryption parameters
                key = encryptionObject.Key;
                iv = encryptionObject.IV;
                authenticatedData = encryptionObject.AuthenticatedData;
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
            AuthenticatedSymmetricAlgorithm decryptionObject = null;
            try
            {
                decryptionObject = new TDecryptionAlgorithm();

                decryptionObject.Key = key;
                decryptionObject.IV = iv;
                decryptionObject.AuthenticatedData = authenticatedData;
                decryptionObject.Tag = tag;

                decryptionSetup(decryptionObject as TDecryptionAlgorithm);
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
#endif // !FXONLY_BUILD
}
