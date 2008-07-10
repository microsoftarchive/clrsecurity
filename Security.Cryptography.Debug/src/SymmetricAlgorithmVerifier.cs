// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Verification object for symmetric decryption.
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics
    /// </summary>
    internal sealed class SymmetricAlgorithmVerifier : SymmetricAlgorithmShim
    {
        private SymmetricEncryptionState m_encryptionState;


        internal SymmetricAlgorithmVerifier(SymmetricAlgorithm verificationAlgorithm,
                                            SymmetricEncryptionState encryptionState,
                                            Predicate<CryptographyLockContext<SymmetricAlgorithm>> lockCheckCallback,
                                            object lockCheckParameter)
            : base(verificationAlgorithm, lockCheckCallback, lockCheckParameter)
        {
            Debug.Assert(encryptionState != null, "encryptionState != null");
            m_encryptionState = encryptionState;
        }

        protected override void OnDecryptorCreated(byte[] key, byte[] iv)
        {
            base.OnDecryptorCreated(key, iv);

            using (SymmetricEncryptionState decryptionState = new SymmetricEncryptionState(key, iv, WrappedAlgorithm))
            {
                m_encryptionState.VerifyDecryptionState(decryptionState);
            }
        }
    }
}
