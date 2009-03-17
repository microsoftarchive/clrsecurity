// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Security.Cryptography
{
#if !FXONLY_BUILD
    /// <summary>
    ///     Verification object for authenticated symmetric decryption.
    ///     
    ///     See code:System.Security.Cryptography.AuthenticatedSymmetricAlgorithmLogger#AuthenticatedSymmetricAlgorithmDiagnostics
    /// </summary>
    internal sealed class AuthenticatedSymmetricAlgorithmVerifier : AuthenticatedSymmetricAlgorithmShim
    {
        private AuthenticatedSymmetricEncryptionState m_encryptionState;


        internal AuthenticatedSymmetricAlgorithmVerifier(AuthenticatedSymmetricAlgorithm verificationAlgorithm,
                                                         AuthenticatedSymmetricEncryptionState encryptionState,
                                                         Predicate<CryptographyLockContext<SymmetricAlgorithm>> lockCheckCallback,
                                                         object lockCheckParameter)
            : base(verificationAlgorithm, lockCheckCallback, lockCheckParameter)
        {
            Debug.Assert(encryptionState != null, "encryptionState != null");
            m_encryptionState = encryptionState;
        }

        protected override void  OnDecryptorCreated(byte[] key, byte[] iv, byte[] authenticatedData, byte[] tag)
        {
            base.OnDecryptorCreated(key, iv, authenticatedData, tag);

            using (AuthenticatedSymmetricEncryptionState decryptionState =
                new AuthenticatedSymmetricEncryptionState(key, iv, authenticatedData, WrappedAlgorithm))
            {
                m_encryptionState.VerifyDecryptionState(decryptionState);
            }
        }
    }
#endif // !FXONLY_BUILD
}
