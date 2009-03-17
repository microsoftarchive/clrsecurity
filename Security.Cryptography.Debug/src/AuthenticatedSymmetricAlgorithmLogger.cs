// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
#if !FXONLY_BUILD
    //
    // #AuthenticatedSymmetricAlgorithmDiagnostics
    //
    // AuthenticatedSymmetricAlgorithmLogger forms the core of authenticated symmetric algorithm diagnostics
    // in the same way that SymmetricAlgorithmLogger forms the core of the diagnostics for unauthenticated
    // symmetric algorithms.  AuthenticatedSymmetricAlgorithmLogger follows the same design principals as
    // SymmetricAlgorithmLogger, for more information on how that type works,
    // see: code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics.
    // 
    // Setting up an authenticated symmetric algorithm logger is very similar to setting up an
    // unauthenticated logger, except that we now work with AuthenticatedSymmetricAlgorithm and
    // IAuthenticatedCryptoTransform objects instead.
    // 
    // For example to setup diagnostics on crypto code that originally looked like this:
    //   using (AuthenticatedAesCng aes = CreateEncryptionObject())
    //   {
    //       ...
    //   }
    //   
    // We would simply transform the AES creation call to enable logging.
    //   using (AuthenticatedSymmetricAlgorithm aes = CreateEncryptionObject().EnableLogging())
    //   {
    //         ...
    //   }
    //
    //   AuthenticatedSymmetricEncryptionState encryptionState = aes.GetLastEncryptionState();
    //   
    // On the decryption side, code which originally looked like this:
    //   using (AuthenticatedAesCng aes = CreateDecryptionObject())
    //   {
    //       ...
    //   }
    //   
    // Now gets wired up for diagnostics in a very similar way:
    //   using (AuthenticatedSymmetricAlgorithm aes = CreateDecryptionObject().EnableDecryptionVerification(encryptionState))
    //   {
    //      ...
    //   }
    //
    // With this wired up, any incorrect inputs to the decryption algorithm will result in a
    // CryptographicDiagnosticException with information about which input was not matched up properly.
    // 

    /// <summary>
    ///     Logging object for authenticated symmetric encryption
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics
    /// </summary>
    internal sealed class AuthenticatedSymmetricAlgorithmLogger : AuthenticatedSymmetricAlgorithmShim
    {
        private AuthenticatedSymmetricEncryptionState m_lastCapturedEncryptionState;

        internal AuthenticatedSymmetricAlgorithmLogger(AuthenticatedSymmetricAlgorithm wrappedAlgorithm,
                                                       Predicate<CryptographyLockContext<SymmetricAlgorithm>> lockCheckCallback,
                                                       object lockCheckParameter) 
            : base(wrappedAlgorithm, lockCheckCallback, lockCheckParameter)
        {
        }

        /// <summary>
        ///     Get the last captured encryption state
        /// </summary>
        internal AuthenticatedSymmetricEncryptionState LastEncryptionState
        {
            get
            {
                if (m_lastCapturedEncryptionState == null)
                    throw new InvalidOperationException(Resources.NoEncryptionStateCaptured);

                return m_lastCapturedEncryptionState.Clone() as AuthenticatedSymmetricEncryptionState;
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

        protected override void  OnEncryptorCreated(byte[] key, byte[] iv, byte[] authenticatedData)
        {
            base.OnEncryptorCreated(key, iv, authenticatedData);

            // An encryptor is being created, which means that all of the encryption parameters must be set at
            // this point.  Capture them so that they can be extracted for later verification.

            if (m_lastCapturedEncryptionState != null)
            {
                m_lastCapturedEncryptionState.Dispose();
            }

            m_lastCapturedEncryptionState = new AuthenticatedSymmetricEncryptionState(key,
                                                                                      iv,
                                                                                      authenticatedData,
                                                                                      WrappedAlgorithm);
        }
    }
#endif // FXONLY_BUILD
}
