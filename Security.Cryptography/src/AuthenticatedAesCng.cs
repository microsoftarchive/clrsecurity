// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Implementation class for authenticated AES over CNG's BCrypt APIs.
    /// </summary>
    public sealed class AuthenticatedAesCng : AuthenticatedAes, ICngSymmetricAlgorithm
    {
        private BCryptAuthenticatedSymmetricAlgorithm m_authenticatedSymmetricAlgorithm;

        public AuthenticatedAesCng()
            : this(CngProvider2.MicrosoftPrimitiveAlgorithmProvider)
        {
        }

        public AuthenticatedAesCng(CngProvider provider)
        {
            if (provider == null)
                throw new ArgumentNullException("provider");

            m_authenticatedSymmetricAlgorithm =
                new BCryptAuthenticatedSymmetricAlgorithm(CngAlgorithm2.Aes,
                                                          provider,
                                                          LegalBlockSizesValue,
                                                          LegalKeySizesValue);

            // Propigate the default properties from the Aes class to the implementation algorithm.
            m_authenticatedSymmetricAlgorithm.BlockSize = BlockSizeValue;
            m_authenticatedSymmetricAlgorithm.KeySize = KeySizeValue;
            m_authenticatedSymmetricAlgorithm.Padding = PaddingValue;
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing && m_authenticatedSymmetricAlgorithm != null)
                {
                    (m_authenticatedSymmetricAlgorithm as IDisposable).Dispose();
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        //
        // Forwarded APIs
        //

        public override byte[] AuthenticatedData
        {
            get { return m_authenticatedSymmetricAlgorithm.AuthenticatedData; }
            set { m_authenticatedSymmetricAlgorithm.AuthenticatedData = value; }
        }

        public override int BlockSize
        {
            get { return m_authenticatedSymmetricAlgorithm.BlockSize; }
            set { m_authenticatedSymmetricAlgorithm.BlockSize = value; }
        }

        public bool ChainingSupported
        {
            get { return m_authenticatedSymmetricAlgorithm.ChainingSupported; }
        }

        public CngChainingMode CngMode
        {
            get { return m_authenticatedSymmetricAlgorithm.CngMode; }
            set { m_authenticatedSymmetricAlgorithm.CngMode = value; }
        }

        public override int FeedbackSize
        {
            get { return m_authenticatedSymmetricAlgorithm.FeedbackSize; }
            set { m_authenticatedSymmetricAlgorithm.FeedbackSize = value; }
        }

        public override byte[] IV
        {
            get { return m_authenticatedSymmetricAlgorithm.IV; }
            set { m_authenticatedSymmetricAlgorithm.IV = value; }
        }

        public override byte[] Key
        {
            get { return m_authenticatedSymmetricAlgorithm.Key; }
            set { m_authenticatedSymmetricAlgorithm.Key = value; }
        }

        public override int KeySize
        {
            get { return m_authenticatedSymmetricAlgorithm.KeySize; }
            set { m_authenticatedSymmetricAlgorithm.KeySize = value; }
        }

        public override KeySizes[] LegalBlockSizes
        {
            get { return m_authenticatedSymmetricAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalKeySizes
        {
            get { return m_authenticatedSymmetricAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalTagSizes
        {
            get { return m_authenticatedSymmetricAlgorithm.LegalTagSizes; }
        }

        public override CipherMode Mode
        {
            get { return m_authenticatedSymmetricAlgorithm.Mode; }
            set { m_authenticatedSymmetricAlgorithm.Mode = value; }
        }

        public override PaddingMode Padding
        {
            get { return m_authenticatedSymmetricAlgorithm.Padding; }
            set { m_authenticatedSymmetricAlgorithm.Padding = value; }
        }

        public CngProvider Provider
        {
            get { return m_authenticatedSymmetricAlgorithm.Provider; }
        }

        public override byte[] Tag
        {
            get { return m_authenticatedSymmetricAlgorithm.Tag; }
            set { m_authenticatedSymmetricAlgorithm.Tag = value; }
        }

        public override int TagSize
        {
            get { return m_authenticatedSymmetricAlgorithm.TagSize; }
            set { m_authenticatedSymmetricAlgorithm.TagSize = value;  }
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor()
        {
            return m_authenticatedSymmetricAlgorithm.CreateAuthenticatedEncryptor();
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_authenticatedSymmetricAlgorithm.CreateAuthenticatedEncryptor(rgbKey, rgbIV);
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey,
                                                                                   byte[] rgbIV,
                                                                                   byte[] rgbAuthenticatedData)
        {
            return m_authenticatedSymmetricAlgorithm.CreateAuthenticatedEncryptor(rgbKey, rgbIV, rgbAuthenticatedData);
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return m_authenticatedSymmetricAlgorithm.CreateDecryptor();
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_authenticatedSymmetricAlgorithm.CreateDecryptor(rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey,
                                                         byte[] rgbIV,
                                                         byte[] rgbAuthenticatedData,
                                                         byte[] rgbTag)
        {
            return m_authenticatedSymmetricAlgorithm.CreateDecryptor(rgbKey, rgbIV, rgbAuthenticatedData, rgbTag);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return m_authenticatedSymmetricAlgorithm.CreateEncryptor();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_authenticatedSymmetricAlgorithm.CreateEncryptor(rgbKey, rgbIV);
        }

        public override void GenerateIV()
        {
            m_authenticatedSymmetricAlgorithm.GenerateIV();
        }

        public override void GenerateKey()
        {
            KeyValue = RNGCng.GenerateKey(KeySizeValue / 8);
        }
    }
}
