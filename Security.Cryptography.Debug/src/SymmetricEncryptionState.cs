// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Security.Cryptography
{
    /// <summary>
    ///     Opaque blob of parameters that were used to encrypt data
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics
    /// </summary>
    [Serializable]
    public class SymmetricEncryptionState : IDisposable
    {
        private Type m_baseAlgorithmType;
        private bool m_compareCipherModes;

        private int m_blockSize;
        private CipherMode m_cipherMode;
        private int m_feedbackSize;
        private byte[] m_iv;
        private byte[] m_key;
        private PaddingMode m_paddingMode;
        private Type m_algorithm;

        /// <summary>
        ///     Capture the parameters used for encryption, and verify that they make sense together
        /// </summary>
        internal SymmetricEncryptionState(byte[] key,
                                          byte[] iv,
                                          SymmetricAlgorithm algorithm)
            : this(key, iv, algorithm, typeof(SymmetricAlgorithm), true)
        {
        }

        internal SymmetricEncryptionState(byte[] key,
                                          byte[] iv,
                                          SymmetricAlgorithm algorithm,
                                          Type baseAlgorithmType,
                                          bool compareCipherModes)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (iv == null)
                throw new ArgumentNullException("iv");
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(baseAlgorithmType != null, "baseAlgorithmType != null");
            Debug.Assert(typeof(SymmetricAlgorithm).IsAssignableFrom(baseAlgorithmType), "typeof(SymmetricAlgorithm).IsAssignableFrom(baseAlgorithmType)");

            m_baseAlgorithmType = baseAlgorithmType;
            m_compareCipherModes = compareCipherModes;

            m_algorithm = GetAlgorithmType(algorithm.GetType());
            m_blockSize = algorithm.BlockSize;
            m_cipherMode = algorithm.Mode;
            m_paddingMode = algorithm.Padding;

            if (m_compareCipherModes && CipherModeUsesFeedback(algorithm.Mode))
            {
                m_feedbackSize = algorithm.FeedbackSize;
            }

            m_iv = new byte[iv.Length];
            Array.Copy(iv, m_iv, m_iv.Length);

            m_key = new byte[key.Length];
            Array.Copy(key, m_key, m_key.Length);
        }

        /// <summary>
        ///     Perform a deep copy of another symmetric encryption state
        /// </summary>
        protected SymmetricEncryptionState(SymmetricEncryptionState other)
        {
            if (other == null)
                throw new ArgumentNullException("other");

            m_baseAlgorithmType = other.m_baseAlgorithmType;
            m_compareCipherModes = other.m_compareCipherModes;

            m_blockSize = other.m_blockSize;
            m_cipherMode = other.m_cipherMode;
            m_feedbackSize = other.m_feedbackSize;
            m_paddingMode = other.m_paddingMode;
            m_algorithm = other.m_algorithm;

            m_iv = new byte[other.m_iv.Length];
            Array.Copy(other.m_iv, m_iv, m_iv.Length);

            m_key = new byte[other.m_key.Length];
            Array.Copy(other.m_key, m_key, m_key.Length);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        ///     Make a deep copy of the current encryption state
        /// </summary>
        public virtual SymmetricEncryptionState Clone()
        {
            return new SymmetricEncryptionState(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (m_key != null)
                {
                    Array.Clear(m_key, 0, m_key.Length);
                }
            }
        }

        public override string ToString()
        {
            return String.Format(CultureInfo.CurrentCulture,
                                 Properties.Resources.SymmetricAlgorithmStateString,
                                 m_algorithm.GetType(),
                                 m_cipherMode,
                                 m_paddingMode,
                                 m_blockSize,
                                 m_feedbackSize,
                                 m_key.Length * 8,
                                 HexString(m_key),
                                 m_iv.Length * 8,
                                 HexString(m_iv));
        }

        /// <summary>
        ///     Verify that the input decryption state matches our encryption state, throwing an error if 
        ///     they do not.
        /// </summary>
        internal virtual void VerifyDecryptionState(SymmetricEncryptionState decryptionState)
        {
            Debug.Assert(decryptionState != null, "decryptionState != null");

            // Make sure the algorithms match
            if (m_algorithm != decryptionState.m_algorithm)
            {
                ThrowDiagnosticException(Properties.Resources.AlgorithmMismatch,
                                         m_algorithm,
                                         decryptionState.m_algorithm);
            }

            // Check the block sizes
            if (m_blockSize != decryptionState.m_blockSize)
            {
                ThrowDiagnosticException(Properties.Resources.BlockSizeMismatch,
                                         m_blockSize,
                                         decryptionState.m_blockSize);
            }

            // Check the ciper modes
            if (m_compareCipherModes && m_cipherMode != decryptionState.m_cipherMode)
            {
                ThrowDiagnosticException(Properties.Resources.CipherModeMismatch,
                                         m_cipherMode,
                                         decryptionState.m_cipherMode);
            }

            // Check the feedback
            if (CipherModeUsesFeedback(m_cipherMode) && m_feedbackSize != decryptionState.m_feedbackSize)
            {
                ThrowDiagnosticException(Properties.Resources.FeedbackSizeMismatch,
                                         m_feedbackSize,
                                         decryptionState.m_feedbackSize);
            }

            // Check the IVs
            if (!CompareBytes(m_iv, decryptionState.m_iv))
            {
                ThrowDiagnosticException(Properties.Resources.IVMismatch,
                                         m_iv.Length * 8,
                                         HexString(m_iv),
                                         decryptionState.m_iv.Length * 8,
                                         HexString(decryptionState.m_iv));
            }

            // Check the keys
            if (!CompareBytes(m_key, decryptionState.m_key))
            {
                ThrowDiagnosticException(Properties.Resources.KeyMismatch,
                                         m_key.Length * 8,
                                         HexString(m_key),
                                         decryptionState.m_key.Length * 8,
                                         HexString(decryptionState.m_key));
            }

            // Check the padding modes
            if (m_paddingMode != decryptionState.m_paddingMode)
            {
                ThrowDiagnosticException(Properties.Resources.PaddingModeMismatch,
                                         m_paddingMode,
                                         decryptionState.m_paddingMode);
            }
        }

        /// <summary>
        ///     Determine if a cipher mode uses feedback in its operation
        /// </summary>
        private static bool CipherModeUsesFeedback(CipherMode mode)
        {
            return mode == CipherMode.CFB || mode == CipherMode.OFB;
        }

        /// <summary>
        ///     Compare two byte arrays for equality
        /// </summary>
        protected static bool CompareBytes(byte[] left, byte[] right)
        {
            Debug.Assert(left != null, "lhs != null");
            Debug.Assert(right != null, "rhs != null");

            if (left.Length != right.Length)
            {
                return false;
            }

            for (uint i = 0; i < left.Length; ++i)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Given a symmetric algortihm implementation, find the abstract algorithm type it implements
        /// </summary>
        private Type GetAlgorithmType(Type implementationType)
        {
            Debug.Assert(implementationType != null, "implementationType != null");

            Type currentType = implementationType;
            while (currentType.BaseType != m_baseAlgorithmType)
            {
                Debug.Assert(currentType != typeof(object), "Walked too far up the object hierarchy");
                currentType = currentType.BaseType;
            }

            return currentType;
        }

        /// <summary>
        ///     Convert a byte array into a hex string
        /// </summary>
        protected static string HexString(byte[] value)
        {
            if (value == null)
            {
                return "(null)";
            }

            StringBuilder hexBuilder = new StringBuilder(value.Length * 2);
            foreach (byte b in value)
            {
                hexBuilder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }

            return hexBuilder.ToString();
        }

        /// <summary>
        ///     Throw a diagnostic error for the algorithm
        /// </summary>
        protected static void ThrowDiagnosticException(string message, params object[] data)
        {
            Debug.Assert(message != null, "message != null");

            throw new CryptographicDiagnosticException(
                String.Format(CultureInfo.CurrentCulture, message, data));
        }
    }
}
