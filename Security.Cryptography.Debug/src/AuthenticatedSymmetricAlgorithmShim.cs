// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;

namespace Security.Cryptography
{
#if !FXONLY_BUILD
    /// <summary>
    ///     Shim class for authenticated symmetric algorithms.  This class simply wraps an existing
    ///     authenticated symmetric algorithm and forwards all crypto operations on to that class.  It
    ///     provides hooks for capturing the creation of an encryptor or decryptor, which is used by the
    ///     authenticated symmetric algorithm logging and verification facility.
    /// </summary>
    internal abstract class AuthenticatedSymmetricAlgorithmShim : AuthenticatedSymmetricAlgorithm
    {
        private AuthenticatedSymmetricAlgorithm m_wrappedAlgorithm;

        //
        // Fields used only when we're checking for thread-safe access to the cryptography object
        //

        private Predicate<CryptographyLockContext<SymmetricAlgorithm>> m_lockCheckCallback;
        private CryptographyLockContext<SymmetricAlgorithm> m_lockCheckContext;

        internal AuthenticatedSymmetricAlgorithmShim(AuthenticatedSymmetricAlgorithm wrappedAlgorithm,
                                                     Predicate<CryptographyLockContext<SymmetricAlgorithm>> lockCheckCallback,
                                                     object lockCheckParameter)
        {
            Debug.Assert(wrappedAlgorithm != null, "wrappedAlgorithm != null");
            m_wrappedAlgorithm = wrappedAlgorithm;

            if (lockCheckCallback != null)
            {
                m_lockCheckCallback = lockCheckCallback;
                m_lockCheckContext = new CryptographyLockContext<SymmetricAlgorithm>(m_wrappedAlgorithm, lockCheckParameter);
            }
        }

        /// <summary>
        ///     Authenticated symmetric algorithm that we're acting as a shim for
        /// </summary>
        protected AuthenticatedSymmetricAlgorithm WrappedAlgorithm
        {
            get { return m_wrappedAlgorithm; }
        }

        /// <summary>
        ///     Check that the object is being accessed in a thread-safe manner
        /// </summary>
        protected void CheckThreadAccess()
        {
            // If we're not doing thread checks, then we'll just assume this is safe
            if (m_lockCheckCallback == null)
            {
                return;
            }

            // If the lock checking predicate fails, then we're doing something unsafely so we should log that
            // with a CryptographicDiagnosticException.
            if (!m_lockCheckCallback(m_lockCheckContext))
            {
                throw new CryptographicDiagnosticException(Properties.Resources.ThreadSafetyViolation);
            }
        }

        /// <summary>
        ///     Clean up any resources that we hold onto
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    IDisposable wrappedAlgorithm = m_wrappedAlgorithm as IDisposable;
                    if (wrappedAlgorithm != null)
                    {
                        wrappedAlgorithm.Dispose();
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
            return String.Format(CultureInfo.InvariantCulture,
                                 Properties.Resources.SymmetricAlgorithmShimString,
                                 GetType(),
                                 m_wrappedAlgorithm.GetType());
        }

        //
        // Encryptor / Decryptor creation
        //
        // This is the point where encryption/decryption parameters should be finalized, so we can capture
        // and verify them as appropriate.
        //

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor()
        {
            CheckThreadAccess();
            OnEncryptorCreated(Key, IV, AuthenticatedData);

            return new AuthenticatedCryptoTransformShim(m_wrappedAlgorithm.CreateAuthenticatedEncryptor(),
                                                        CheckThreadAccess);
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            CheckThreadAccess();
            OnEncryptorCreated(rgbKey, rgbIV, AuthenticatedData);

            return new AuthenticatedCryptoTransformShim(m_wrappedAlgorithm.CreateAuthenticatedEncryptor(rgbKey, rgbIV),
                                                        CheckThreadAccess);
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey,
                                                                                   byte[] rgbIV,
                                                                                   byte[] rgbAuthenticatedData)
        {
            CheckThreadAccess();
            OnEncryptorCreated(rgbKey, rgbIV, rgbAuthenticatedData);

            return new AuthenticatedCryptoTransformShim(m_wrappedAlgorithm.CreateAuthenticatedEncryptor(rgbKey, rgbIV, rgbAuthenticatedData),
                                                        CheckThreadAccess);
        }

        public override ICryptoTransform CreateDecryptor()
        {
            CheckThreadAccess();
            OnDecryptorCreated(Key, IV, AuthenticatedData, Tag);

            return new CryptoTransformShim(m_wrappedAlgorithm.CreateDecryptor(),
                                           CheckThreadAccess);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            CheckThreadAccess();
            OnDecryptorCreated(rgbKey, rgbIV, AuthenticatedData, Tag);

            return new CryptoTransformShim(m_wrappedAlgorithm.CreateDecryptor(rgbKey, rgbIV),
                                           CheckThreadAccess);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey,
                                                         byte[] rgbIV,
                                                         byte[] rgbAuthenticatedData,
                                                         byte[] rgbTag)
        {
            CheckThreadAccess();
            OnDecryptorCreated(rgbKey, rgbIV, rgbAuthenticatedData, rgbTag);

            return new CryptoTransformShim(m_wrappedAlgorithm.CreateDecryptor(rgbKey, rgbIV, rgbAuthenticatedData, rgbTag),
                                           CheckThreadAccess);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            CheckThreadAccess();
            OnEncryptorCreated(Key, IV, AuthenticatedData);

            return new CryptoTransformShim(m_wrappedAlgorithm.CreateEncryptor(),
                                           CheckThreadAccess);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            CheckThreadAccess();
            OnEncryptorCreated(rgbKey, rgbIV, AuthenticatedData);

            return new CryptoTransformShim(m_wrappedAlgorithm.CreateEncryptor(rgbKey, rgbIV),
                                           CheckThreadAccess);
        }

        //
        // virtual hooks for the encryption logging and decryption verification types to listen to
        //

        protected virtual void OnDecryptorCreated(byte[] key, byte[] iv, byte[] authenticatedData, byte[] tag)
        {
        }

        protected virtual void OnEncryptorCreated(byte[] key, byte[] iv, byte[] authenticatedData)
        {
        }

        //
        // Shim methods and properties - these just ensure that our logging algorithm object looks exactly
        // like the algorithm it's wrapping.
        //

        public override byte[] AuthenticatedData
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.AuthenticatedData; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.AuthenticatedData = value; }
        }

        public override int BlockSize
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.BlockSize; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.BlockSize = value; }
        }

        public override int FeedbackSize
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.FeedbackSize; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.FeedbackSize = value; }
        }

        public override byte[] IV
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.IV; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.IV = value; }
        }

        public override byte[] Key
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.Key; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.Key = value; }
        }

        public override int KeySize
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.KeySize; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.KeySize = value; }
        }

        public override KeySizes[] LegalBlockSizes
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalKeySizes
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalTagSizes
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.LegalTagSizes; }
        }

        public override CipherMode Mode
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.Mode; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.Mode = value; }
        }

        public override PaddingMode Padding
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.Padding; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.Padding = value; }
        }

        public override byte[] Tag
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.Tag; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.Tag = value; }
        }

        public override int TagSize
        {
            get { CheckThreadAccess(); return m_wrappedAlgorithm.TagSize; }
            set { CheckThreadAccess(); m_wrappedAlgorithm.TagSize = value; }
        }

        public override void GenerateIV()
        {
            CheckThreadAccess();
            m_wrappedAlgorithm.GenerateIV();
        }

        public override void GenerateKey()
        {
            CheckThreadAccess();
            m_wrappedAlgorithm.GenerateKey();
        }
    }
#endif // !FXONLY_BUILD
}
