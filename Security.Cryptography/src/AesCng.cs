// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     CNG implementation of the AES encryption algorithm.
    ///     
    ///     See code:Microsoft.Security.Cryptography.BCryptSymmetricAlgorithm
    /// </summary>
    public sealed class AesCng : Aes, ICngSymmetricAlgorithm
    {
        private BCryptSymmetricAlgorithm m_symmetricAlgorithm;

        public AesCng() : this(CngProvider2.MicrosoftPrimitiveAlgorithmProvider)
        {
        }

        public AesCng(CngProvider algorithmProvider)
        {
            if (algorithmProvider == null)
                throw new ArgumentNullException("algorithmProvider");

            m_symmetricAlgorithm = new BCryptSymmetricAlgorithm(new CngAlgorithm(BCryptNative.AlgorithmName.Aes),
                                                                algorithmProvider,
                                                                LegalBlockSizesValue,
                                                                LegalKeySizesValue);
            
            // Propigate the default properties from the Aes class to the implementation algorithm.
            m_symmetricAlgorithm.BlockSize = BlockSizeValue;
            m_symmetricAlgorithm.KeySize = KeySizeValue;
            m_symmetricAlgorithm.Mode = ModeValue;
            m_symmetricAlgorithm.Padding = PaddingValue;
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing && m_symmetricAlgorithm != null)
                {
                    (m_symmetricAlgorithm as IDisposable).Dispose();
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

        public override int BlockSize
        {
            get { return m_symmetricAlgorithm.BlockSize; }
            set { m_symmetricAlgorithm.BlockSize = value; }
        }

        public CngChainingMode CngMode
        {
            get { return m_symmetricAlgorithm.CngMode; }
            set { m_symmetricAlgorithm.CngMode = value; }
        }

        public override int FeedbackSize
        {
            get { return m_symmetricAlgorithm.FeedbackSize; }
            set { m_symmetricAlgorithm.FeedbackSize = value; }
        }

        public override byte[] IV
        {
            get { return m_symmetricAlgorithm.IV; }
            set { m_symmetricAlgorithm.IV = value; }
        }

        public override byte[] Key
        {
            get { return m_symmetricAlgorithm.Key; }
            set { m_symmetricAlgorithm.Key = value; }
        }

        public override int KeySize
        {
            get { return m_symmetricAlgorithm.KeySize; }
            set { m_symmetricAlgorithm.KeySize = value; }
        }

        public override KeySizes[] LegalBlockSizes
        {
            get { return m_symmetricAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalKeySizes
        {
            get { return m_symmetricAlgorithm.LegalBlockSizes; }
        }

        public override CipherMode Mode
        {
            get { return m_symmetricAlgorithm.Mode; }
            set { m_symmetricAlgorithm.Mode = value; }
        }

        public override PaddingMode Padding
        {
            get { return m_symmetricAlgorithm.Padding; }
            set { m_symmetricAlgorithm.Padding = value; }
        }

        public CngProvider Provider
        {
            get { return m_symmetricAlgorithm.Provider; }
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return m_symmetricAlgorithm.CreateDecryptor();
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_symmetricAlgorithm.CreateDecryptor(rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return m_symmetricAlgorithm.CreateEncryptor();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_symmetricAlgorithm.CreateEncryptor(rgbKey, rgbIV);
        }

        public override void GenerateIV()
        {
            m_symmetricAlgorithm.GenerateIV();
        }

        public override void GenerateKey()
        {
            m_symmetricAlgorithm.GenerateKey();
        }
    }
}
