// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     Abstract base class for authenticated symmetric algorithms
    /// </summary>
    public abstract class AuthenticatedSymmetricAlgorithm : SymmetricAlgorithm
    {
        private byte[] m_authenticatedData;
        private byte[] m_tag;

        //
        // Tag size values - these are protected fields without array copy semantics to behave similar to
        // the KeySize / IVSize mechanisms
        //

        /// <summary>
        ///     Valid tag sizes that this instance supports (in bits)
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields", Justification = "Consistency with other SymmetricAlgorithm APIs (LegalKeySizesValue, LegalBlockSizesValue")]
        protected KeySizes[] LegalTagSizesValue;

        /// <summary>
        ///     Current tag size (in bits)
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields", Justification = "Consistency with other SymmetricAlgorithm APIs (KeyValue, BlockValue, etc)")]
        protected int TagSizeValue;

        /// <summary>
        ///     Gets or sets the authenticated data buffer.
        ///     
        ///     This data is included in calculations of the authentication tag, but is not included in the
        ///     ciphertext.  A value of null means that there is no additional authenticated data.
        /// </summary>
        [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Consistency with the other SymmetricAlgorithm API (Key, IV, etc)")]
        public virtual byte[] AuthenticatedData
        {
            get
            {
                return m_authenticatedData != null ? m_authenticatedData.Clone() as byte[] : null;
            }

            set
            {
                if (value != null)
                {
                    m_authenticatedData = value.Clone() as byte[];
                }
                else
                {
                    m_authenticatedData = null;
                }
            }
        }

        /// <summary>
        ///     Get or set the IV (nonce) to use with transorms created with this object.  Note that we
        ///     override the base implementation because it requires that the nonce equal the block size,
        ///     while in general authenticated transforms do not.
        /// </summary>
        public override byte[] IV
        {
            get
            {
                if (IVValue == null)
                {
                    GenerateIV();
                }

                return IVValue.Clone() as byte[];
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                IVValue = value.Clone() as byte[];
            }
        }

        /// <summary>
        ///     Get the range of allowed sizes (in bits) for authentication tags
        /// </summary>
        [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Consistency with other SymmetricAlgorithm APIs (LegalKeySizes, LegalBlockSizes)")]
        public virtual KeySizes[] LegalTagSizes
        {
            get { return LegalTagSizesValue.Clone() as KeySizes[]; }
        }

        /// <summary>
        ///     Gets or sets the authentication tag to use when verifying a decryption operation.  This
        ///     value is only read for decryption operaions, and is not used for encryption operations.  To
        ///     find the value of the tag generated on encryption, check the Tag property of the
        ///     IAuthenticatedCryptoTransform encryptor object.
        /// </summary>
        [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Consistency with other SymmetricAlgorithm APIs (Key, IV)")]
        public virtual byte[] Tag
        {
            get
            {
                if (m_tag == null)
                {
                    m_tag = new byte[TagSizeValue / 8];
                }

                return m_tag.Clone() as byte[];
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                if (!ValidTagSize(value.Length * 8))
                    throw new ArgumentException(Resources.InvalidTagSize, "value");

                m_tag = value.Clone() as byte[];
                TagSizeValue = m_tag.Length * 8;
            }
        }

        /// <summary>
        ///     Get or set the size (in bits) of the authentication tag
        /// </summary>
        public virtual int TagSize
        {
            get { return TagSizeValue; }

            set
            {
                if (!ValidTagSize(value))
                    throw new ArgumentOutOfRangeException(Resources.InvalidTagSize);

                TagSizeValue = value;
                m_tag = null;
            }
        }

        /// <summary>
        ///     Create an instance of the default AuthenticatedSymmetricAlgorithm on this machine
        /// </summary>
        public static new AuthenticatedSymmetricAlgorithm Create()
        {
            return Create(typeof(AuthenticatedSymmetricAlgorithm).Name);
        }

        /// <summary>
        ///     Create an instance of a specific AuthenticatedSymmetricAlgorithm
        /// </summary>
        public static new AuthenticatedSymmetricAlgorithm Create(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            return CryptoConfig2.CreateFromName(algorithm) as AuthenticatedSymmetricAlgorithm;
        }

        /// <summary>
        ///     Create an encryptor using the key, nonce, and authenticated data from the properties of this
        ///     algorithm.
        /// </summary>
        public virtual IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor()
        {
            return CreateAuthenticatedEncryptor(Key, IV, AuthenticatedData);
        }

        /// <summary>
        ///     Create an encryptor using the given key and nonce, and the authenticated data from this
        ///     algorithm.
        /// </summary>
        public virtual IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateAuthenticatedEncryptor(rgbKey, rgbIV, AuthenticatedData);
        }

        /// <summary>
        ///     Create an authenticated crypto transform using the given key, nonce, and authenticated data
        /// </summary>
        public abstract IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey,
                                                                                   byte[] rgbIV,
                                                                                   byte[] rgbAuthenticatedData);

        /// <summary>
        ///     Create a decryptor using the key, nonce, authenticated data, and authentication tag from the
        ///     properties of this algorithm.
        /// </summary>
        public override ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(Key, IV, AuthenticatedData, Tag);
        }

        /// <summary>
        ///     Create a decryptor with the given key and nonce, using the authenticated data and
        ///     authentication tag from the properties of the algorithm.
        /// </summary>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateDecryptor(rgbKey, rgbIV, AuthenticatedData, Tag);
        }

        /// <summary>
        ///     Create a decryption transform with the given key, nonce, authenticated data, and
        ///     authentication tag
        /// </summary>
        public abstract ICryptoTransform CreateDecryptor(byte[] rgbKey,
                                                         byte[] rgbIV,
                                                         byte[] rgbAuthenticatedData,
                                                         byte[] rgbTag);

        /// <summary>
        ///     Create an encryptor using the given key and nonce, and the authenticated data from this
        ///     algorithm.
        /// </summary>
        public override ICryptoTransform CreateEncryptor()
        {
            return CreateAuthenticatedEncryptor();
        }

        /// <summary>
        ///     Create an encryptor using the given key and nonce, and the authenticated data from this
        ///     algorithm.
        /// </summary>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateAuthenticatedEncryptor(rgbKey, rgbIV);
        }

        /// <summary>
        ///     Is the tag size (in bits) valid for this implementation of the algorithm
        /// </summary>
        public bool ValidTagSize(int tagSize)
        {
            // If we don't have any valid tag sizes, then no tag is of the correct size
            if (LegalTagSizes == null)
            {
                return false;
            }

            // Loop over all of the legal size ranges, and see if we match any of them
            foreach (KeySizes legalTagSizeRange in LegalTagSizes)
            {
                for (int legalTagSize = legalTagSizeRange.MinSize;
                     legalTagSize <= legalTagSizeRange.MaxSize;
                     legalTagSize += legalTagSizeRange.SkipSize)
                {
                    if (legalTagSize == tagSize)
                    {
                        return true;
                    }
                }
            }

            // No matches - this isn't a valid tag size
            return false;
        }
    }
}
