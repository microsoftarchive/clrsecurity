// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    //
    // #SymmetricAlgorithmDiagnostics
    //
    // Nearly all errors that occur when using symmetric cryptography result in a single
    // CryptographicException upon decrypting the final block.  This is because any mismatch between input
    // crypto parameters and output parameters results in incorrect decryption - however that is only
    // detectable by the crypto code when it is unable to remove the padding on the last block of the
    // ciphertext.
    //
    // Since any mismatch between input parameters (such as key, IV, ciper mode, and padding mode) and output
    // parameters results in the same exception, it's often difficult to figure out exactly what parameters
    // were incorrect, and therefore it becomes difficult to debug why the parameter was incorrect in the
    // first place.  Further, it becomes very difficult to diferentiate between exceptions thrown due to
    // incorrect data being supplied to the cryptographic operation from exceptions resulting from a bug in
    // the operation itself.
    //
    // In order to help diagnose these issues, SymmetricAlgorithmLogger forms the core of a symmetric
    // algorithm diagnostic facility. At its most basic, this facility does nothing more than make a note of
    // all the relevant input parameters during the encryption operaiton, and then compares them to the inputs
    // to the decryption operation.  Any mismatch is flagged as an error, which can then be tracked down to
    // its root cause.
    //
    // Setting this up involves several parts.  First a SymmetricAlgorithmLogger is attached to the
    // encryption algorithm object.  This logger acts as a shim for the encryption algorithm, passing all
    // requests through to it, while keeping track of its parameters.
    //
    // When the encryption is complete, an opaque SymmetricEncryptionState object that wraps the relevant
    // encryption parameters is produced.  This object may be supplied to a SymmetricAlgorithmVerifier object
    // that wraps the decryption operation. The verifier object then compares the decryption parameters to
    // the ones used for encryption and throws a CyrpotgraphicDiagnosticException if there is a difference
    // between the two.
    //
    // Note that no attempt is made to verify the correctness of the encryption algoritm itself, instead we
    // only look for issues with the code consuming the algorithm.  If a SymmetricAlgorithm implementation is
    // buggy, verification may suceed and the cryptographic operation may still fail.
    // 
    // For example to setup diagnostics on crypto code that originally looked like this:
    //   using (AesManaged aes = CreateEncryptionObject())
    //   {
    //       ...
    //   }
    //   
    // We would simply transform the AES creation call to enable logging.
    //   using (SymmetricAlgorithm aes = CreateEncryptionObject().EnableLogging())
    //   {
    //         ...
    //   }
    //
    //   SymmetricEncryptionState encryptionState = aes.GetLastEncryptionState();
    //   
    // On the decryption side, code which originally looked like this:
    //   using (AesManaged aes = CreateDecryptionObject())
    //   {
    //       ...
    //   }
    //   
    // Now gets wired up for diagnostics in a very similar way:
    //   using (SymmetricAlgorithm aes = CreateDecryptionObject().EnableDecryptionVerification(encryptionState))
    //   {
    //      ...
    //   }
    //
    // With this wired up, any incorrect inputs to the decryption algorithm will result in a
    // CryptographicDiagnosticException with information about which input was not matched up properly.
    // 

    /// <summary>
    ///     Logging object for symmetric encryption
    /// </summary>
    internal sealed class SymmetricAlgorithmLogger : SymmetricAlgorithmShim
    {
        private SymmetricEncryptionState m_lastCapturedEncryptionState;

        internal SymmetricAlgorithmLogger(SymmetricAlgorithm wrappedAlgorithm,
                                          Predicate<CryptographyLockContext<SymmetricAlgorithm>> lockCheckCallback,
                                          object lockCheckParameter) 
            : base(wrappedAlgorithm, lockCheckCallback, lockCheckParameter)
        {
        }

        /// <summary>
        ///     Get the last captured encryption state
        /// </summary>
        internal SymmetricEncryptionState LastEncryptionState
        {
            get
            {
                if (m_lastCapturedEncryptionState == null)
                    throw new InvalidOperationException(Properties.Resources.NoEncryptionStateCaptured);

                return m_lastCapturedEncryptionState.Clone();
            }
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (m_lastCapturedEncryptionState != null)
                    {
                        m_lastCapturedEncryptionState.Dispose();
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        protected override void OnEncryptorCreated(byte[] key, byte[] iv)
        {
            base.OnEncryptorCreated(key, iv);

            // An encryptor is being created, which means that all of the encryption parameters must be set at
            // this point.  Capture them so that they can be extracted for later verification.

            if (m_lastCapturedEncryptionState != null)
            {
                m_lastCapturedEncryptionState.Dispose();
            }

            m_lastCapturedEncryptionState = new SymmetricEncryptionState(key,
                                                                         iv,
                                                                         WrappedAlgorithm);
        }
    }
}
