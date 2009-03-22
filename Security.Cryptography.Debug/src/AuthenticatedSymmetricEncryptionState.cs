// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
#if !FXONLY_BUILD
    /// <summary>
    ///     Opaque blob of parameters that were used to encrypt authenticated data
    ///     
    ///     See code:System.Security.Cryptography.AuthenticatedSymmetricAlgorithmLogger#AuthenticatedSymmetricAlgorithmDiagnostics
    /// </summary>
    [Serializable]
    public sealed class AuthenticatedSymmetricEncryptionState : SymmetricEncryptionState
    {
        private byte[] m_authenticatedData;
        private CngChainingMode m_cngChainingMode;

        /// <summary>
        ///     Capture the parameters used for encryption, and verify that they make sense together
        /// </summary>
        internal AuthenticatedSymmetricEncryptionState(byte[] key,
                                                       byte[] iv,
                                                       byte[] authenticatedData,
                                                       AuthenticatedSymmetricAlgorithm algorithm)
            : base(key, iv, algorithm, typeof(AuthenticatedSymmetricAlgorithm), false)
        {
            if (authenticatedData != null)
            {
                m_authenticatedData = new byte[authenticatedData.Length];
                Array.Copy(authenticatedData, m_authenticatedData, m_authenticatedData.Length);
            }

            // Since CipherMode doesn't contain authenticated encryption modes, it's not very useful for
            // debugging mode mismatches in authenticated symmetric algorithms.  Our only current
            // authenticated symmetric algorithm implementations ues CNG chaining modes, so we'll grab that
            // if it's available to aid in debugging.
            ICngSymmetricAlgorithm cngAlgorithm = algorithm as ICngSymmetricAlgorithm;
            if (cngAlgorithm != null)
            {
                m_cngChainingMode = cngAlgorithm.CngMode;
            }
        }

        /// <summary>
        ///     Make a deep copy of the authenticated encryption state
        /// </summary>
        private AuthenticatedSymmetricEncryptionState(AuthenticatedSymmetricEncryptionState other)
            : base(other)
        {
            Debug.Assert(other != null, "other != null");

            m_cngChainingMode = other.m_cngChainingMode;

            if (other.m_authenticatedData != null)
            {
                m_authenticatedData = new byte[other.m_authenticatedData.Length];
                Array.Copy(other.m_authenticatedData, m_authenticatedData, m_authenticatedData.Length);
            }
        }

        /// <summary>
        ///     Make a deep copy of the authenticated encryption state
        /// </summary>
        public override SymmetricEncryptionState Clone()
        {
            return new AuthenticatedSymmetricEncryptionState(this);
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (m_authenticatedData != null)
                    {
                        Array.Clear(m_authenticatedData, 0, m_authenticatedData.Length);
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        public override string ToString()
        {
            return String.Format(CultureInfo.CurrentCulture,
                                 Resources.AuthenticatedSymmetricAlgorithmStateString,
                                 base.ToString(),
                                 m_authenticatedData != null ? m_authenticatedData.Length * 8 : 0,
                                 HexString(m_authenticatedData),
                                 m_cngChainingMode != null ? m_cngChainingMode.ChainingMode : Resources.Unknown);
        }

        /// <summary>
        ///     Verify that the input decryption state matches our encryption state, throwing an error if 
        ///     they do not.
        /// </summary>
        internal override void VerifyDecryptionState(SymmetricEncryptionState decryptionState)
        {
            Debug.Assert(decryptionState != null, "decryptionState != null");

            // All of the symmetric algorithm comparisons need to match
            base.VerifyDecryptionState(decryptionState);

            AuthenticatedSymmetricEncryptionState authenticatedDecryptionState =
                decryptionState as AuthenticatedSymmetricEncryptionState;

            // The base verify decryption state should have caught an algorithm mismatch, which would be the
            // only way that we could be encrypting with an authenticated symmetric algortihm but decrypting
            // with an unauthenticated algorithm.
            Debug.Assert(authenticatedDecryptionState != null, "authenticatedDecryptionState != null");

            // If we have authenticated data, make sure it matches
            if (m_authenticatedData != null)
            {
                // If we have authenticated data, then the decryption state also needs to have authenticated
                // data, and that data needs to match.
                if (authenticatedDecryptionState.m_authenticatedData == null ||
                    !CompareBytes(m_authenticatedData, authenticatedDecryptionState.m_authenticatedData))
                {
                    ThrowDiagnosticException(Resources.AuthenticatedDataMismatch,
                                             m_authenticatedData.Length * 8,
                                             HexString(m_authenticatedData),
                                             authenticatedDecryptionState.m_authenticatedData != null ? authenticatedDecryptionState.m_authenticatedData.Length * 8 : 0,
                                             HexString(authenticatedDecryptionState.m_authenticatedData));
                }
            }
            else if (authenticatedDecryptionState.m_authenticatedData != null)
            {
                // We had no authenticated data during encryption, but we have some during decryption, so we
                // have a mismatch.
                ThrowDiagnosticException(Resources.AuthenticatedDataMismatch,
                                         0,
                                         HexString(null),
                                         authenticatedDecryptionState.m_authenticatedData.Length * 8,
                                         HexString(authenticatedDecryptionState.m_authenticatedData));
            }

            // Make sure the CNG chaining modes match
            if (m_cngChainingMode != authenticatedDecryptionState.m_cngChainingMode)
            {
                ThrowDiagnosticException(Resources.CngChainingModeMismatch,
                                         m_cngChainingMode,
                                         authenticatedDecryptionState.m_cngChainingMode);
            }
        }
    }
#endif // !FXONLY_BUILD
}
