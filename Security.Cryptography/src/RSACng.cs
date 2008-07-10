// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     Implementation of the RSA algorithm using the NCrypt layer of CNG.
    ///     
    ///     Note that this type is not a drop in replacement for RSACryptoServiceProvider, and follows an
    ///     API pattern more similar to ECDsaCng than RSACryptoServiceProvider.
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSA", Justification = "This is for consistency with the existing RSACryptoServiceProvider type")]
    public sealed class RSACng : RSA
    {
        private static KeySizes[] s_legalKeySizes = new KeySizes[] { new KeySizes(384, 16384, 8) };
        
        private static CngAlgorithm s_algorithmName = new CngAlgorithm(BCryptNative.AlgorithmName.Rsa);

        // CngKeyBlob formats for RSA key blobs
        private static CngKeyBlobFormat s_rsaFullPrivateBlob = new CngKeyBlobFormat(BCryptNative.KeyBlobType.RsaFullPrivateBlob);
        private static CngKeyBlobFormat s_rsaPrivateBlob = new CngKeyBlobFormat(BCryptNative.KeyBlobType.RsaPrivateBlob);
        private static CngKeyBlobFormat s_rsaPublicBlob = new CngKeyBlobFormat(BCryptNative.KeyBlobType.RsaPublicBlob);

        // Key handle
        private CngKey m_key;

        // Properties used when encrypting or decrypting
        private AsymmetricPaddingMode m_encryptionPaddingMode = AsymmetricPaddingMode.Oaep;
        private CngAlgorithm m_encryptionHashAlgorithm = CngAlgorithm.Sha256;

        // Properties used when signing or verifying data
        private AsymmetricPaddingMode m_signaturePaddingMode = AsymmetricPaddingMode.Pkcs1;
        private CngAlgorithm m_signatureHashAlgorithm = CngAlgorithm.Sha256;
        private int m_signatureSaltBytes = 20;

        /// <summary>
        ///     Create an RSACng algorithm with a random 2048 bit key
        /// </summary>
        public RSACng() : this(2048)
        {
            return;
        }

        /// <summary>
        ///     Create an RSACng algorithm with a random key of the specified size
        /// </summary>
        public RSACng(int keySize)
        {
            LegalKeySizesValue = s_legalKeySizes;
            KeySize = keySize;
        }

        /// <summary>
        ///     Construct an RSACng algorithm with the specified key
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public RSACng(CngKey key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            LegalKeySizesValue = s_legalKeySizes;

            new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            Key = CngKey.Open(key.Handle, key.IsEphemeral ? CngKeyHandleOpenOptions.EphemeralKey : CngKeyHandleOpenOptions.None);
            CodeAccessPermission.RevertAssert();
        }

        /// <summary>
        ///     Hash algorithm to use for padding when encrypting or decrypting. This is only used with
        ///     AsymmetricPaddingMode.Oaep.
        /// </summary>
        public CngAlgorithm EncryptionHashAlgorithm
        {
            get { return m_encryptionHashAlgorithm; }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_encryptionHashAlgorithm = value;
            }
        }

        /// <summary>
        ///     Padding to use when encrypting or decrypting
        /// </summary>
        public AsymmetricPaddingMode EncryptionPaddingMode
        {
            get { return m_encryptionPaddingMode; }

            set
            {
                if (value != AsymmetricPaddingMode.Oaep &&
                    value != AsymmetricPaddingMode.Pkcs1)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                m_encryptionPaddingMode = value;
            }
        }

        /// <summary>
        ///     Key that we're using for RSA operations
        /// </summary>
        public CngKey Key
        {
            [SecurityCritical]
            [SecurityTreatAsSafe]
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            [SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
            get
            {
                // If our key size was changed from the key we're using, we need to generate a new key
                if (m_key != null && m_key.KeySize != KeySize)
                {
                    m_key.Dispose();
                    m_key = null;
                }

                // If we don't have a key yet, we need to generate a random one now
                if (m_key == null)
                {
                    CngKeyCreationParameters creationParameters = new CngKeyCreationParameters();
                    CngProperty keySizeProperty = new CngProperty(NCryptNative.KeyPropertyName.Length,
                                                                  BitConverter.GetBytes(KeySize),
                                                                  CngPropertyOptions.None);
                    creationParameters.Parameters.Add(keySizeProperty);
                    m_key = CngKey.Create(s_algorithmName, null, creationParameters);
                }

                return m_key;
            }

            private set
            {
                Debug.Assert(value != null, "value != null");
                if (value.AlgorithmGroup != CngAlgorithmGroup.Rsa)
                    throw new ArgumentException(Properties.Resources.KeyMustBeRsa, "value");

                // If we already have a key, clear it out
                if (m_key != null)
                {
                    m_key.Dispose();
                }

                m_key = value;
                KeySize = m_key.KeySize;
            }
        }

        /// <summary>
        ///     Helper property to get the NCrypt key handle
        /// </summary>
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Internal security critical code")]
        private SafeNCryptKeyHandle KeyHandle
        {
            [SecurityCritical]
            [SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
            get { return Key.Handle; }
        }

        public override string KeyExchangeAlgorithm
        {
            get { return "RSA-PKCS1-KeyEx";  }
        }

        public override string SignatureAlgorithm
        {
            get { return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; }
        }

        /// <summary>
        ///     Hash algorithm that will be used when signing and verifying data
        /// </summary>
        public CngAlgorithm SignatureHashAlgorithm
        {
            get { return m_signatureHashAlgorithm; }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_signatureHashAlgorithm = value;
            }
        }

        /// <summary>
        ///     Padding mode to use for signature generation and verification
        /// </summary>
        public AsymmetricPaddingMode SignaturePaddingMode
        {
            get { return m_signaturePaddingMode; }

            set
            {
                if (value != AsymmetricPaddingMode.Pkcs1 &&
                    value != AsymmetricPaddingMode.Pss)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                m_signaturePaddingMode = value;
            }
        }

        /// <summary>
        ///     Number of bytes of salt to use in signature padding.
        ///     This is only used for SignaturePaddingMode.Pss
        /// </summary>
        public int SignatureSaltBytes
        {
            get { return m_signatureSaltBytes; }

            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException("value");

                m_signatureSaltBytes = value;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && m_key != null)
            {
                m_key.Dispose();
            }
        }

        /// <summary>
        ///     Build a key container permission that should be demanded before using the private key
        /// </summary>
        private static KeyContainerPermission BuildKeyContainerPermission(CngKey key, KeyContainerPermissionFlags flags)
        {
            // If this isn't a named key, then we can use it without any demand
            if (key.IsEphemeral || String.IsNullOrEmpty(key.KeyName))
            {
                return null;
            }

            KeyContainerPermissionAccessEntry entry = new KeyContainerPermissionAccessEntry(key.KeyName, flags);
            entry.ProviderName = key.Provider.Provider;

            KeyContainerPermission permission = new KeyContainerPermission(PermissionState.None);
            permission.AccessEntries.Add(entry);
            return permission;
        }

        /// <summary>
        ///     Create an object to hash signature data with
        /// </summary>
        private HashAlgorithm CreateSignatureHashObject()
        {
            if (m_signatureHashAlgorithm == CngAlgorithm.MD5)
            {
                return new MD5Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha1)
            {
                return new SHA1Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha256)
            {
                return new SHA256Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha384)
            {
                return new SHA384Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha512)
            {
                return new SHA512Cng();
            }
            else
            {
                throw new InvalidOperationException(Properties.Resources.InvalidSignatureHashAlgorithm);
            }
        }

        //
        // Key import and export
        //

        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of SizeOf")]
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            byte[] rsaBlob = Key.Export(includePrivateParameters ? s_rsaFullPrivateBlob : s_rsaPublicBlob);
            RSAParameters rsaParams = new RSAParameters();

            //
            // We now have a buffer laid out as follows:
            //     BCRYPT_RSAKEY_BLOB   header
            //     byte[cbPublicExp]    publicExponent      - Exponent
            //     byte[cbModulus]      modulus             - Modulus
            //     -- Private only --
            //     byte[cbPrime1]       prime1              - P
            //     byte[cbPrime2]       prime2              - Q
            //     byte[cbPrime1]       exponent1           - DP
            //     byte[cbPrime2]       exponent2           - DQ
            //     byte[cbPrime1]       coefficient         - InverseQ
            //     byte[cbModulus]      privateExponent     - D
            //

            unsafe
            {
                fixed (byte* pRsaBlob = rsaBlob)
                {
                    BCryptNative.BCRYPT_RSAKEY_BLOB* pBcryptBlob = (BCryptNative.BCRYPT_RSAKEY_BLOB*)pRsaBlob;
                    
                    int offset = Marshal.SizeOf(typeof(BCryptNative.BCRYPT_RSAKEY_BLOB));

                    // Read out the exponent
                    rsaParams.Exponent = new byte[pBcryptBlob->cbPublicExp];
                    Buffer.BlockCopy(rsaBlob, offset, rsaParams.Exponent, 0, rsaParams.Exponent.Length);
                    offset += pBcryptBlob->cbPublicExp;

                    // Read out the modulus
                    rsaParams.Modulus = new byte[pBcryptBlob->cbModulus];
                    Buffer.BlockCopy(rsaBlob, offset, rsaParams.Modulus, 0, rsaParams.Modulus.Length);
                    offset += pBcryptBlob->cbModulus;

                    if (includePrivateParameters)
                    {
                        // Read out P
                        rsaParams.P = new byte[pBcryptBlob->cbPrime1];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.P, 0, rsaParams.P.Length);
                        offset += pBcryptBlob->cbPrime1;

                        // Read out Q
                        rsaParams.Q = new byte[pBcryptBlob->cbPrime2];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.Q, 0, rsaParams.Q.Length);
                        offset += pBcryptBlob->cbPrime2;

                        // Read out DP
                        rsaParams.DP = new byte[pBcryptBlob->cbPrime1];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.DP, 0, rsaParams.DP.Length);
                        offset += pBcryptBlob->cbPrime1;

                        // Read out DQ
                        rsaParams.DQ = new byte[pBcryptBlob->cbPrime2];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.DQ, 0, rsaParams.DQ.Length);
                        offset += pBcryptBlob->cbPrime2;

                        // Read out InverseQ
                        rsaParams.InverseQ = new byte[pBcryptBlob->cbPrime1];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.InverseQ, 0, rsaParams.InverseQ.Length);
                        offset += pBcryptBlob->cbPrime1;

                        //  Read out D
                        rsaParams.D = new byte[pBcryptBlob->cbModulus];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.D, 0, rsaParams.D.Length);
                        offset += pBcryptBlob->cbModulus;
                    }
                }
            }

            return rsaParams;
        }

        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of SizeOf")]
        public override void ImportParameters(RSAParameters parameters)
        {
            if (parameters.Exponent == null || parameters.Modulus == null)
                throw new ArgumentException(Properties.Resources.InvalidRsaParameters);

            bool publicOnly = parameters.P == null || parameters.Q == null;

            //
            // We need to build a key blob structured as follows:
            //     BCRYPT_RSAKEY_BLOB   header
            //     byte[cbPublicExp]    publicExponent      - Exponent
            //     byte[cbModulus]      modulus             - Modulus
            //     -- Private only --
            //     byte[cbPrime1]       prime1              - P
            //     byte[cbPrime2]       prime2              - Q
            //

            int blobSize = Marshal.SizeOf(typeof(BCryptNative.BCRYPT_RSAKEY_BLOB)) +
                           parameters.Exponent.Length +
                           parameters.Modulus.Length;
            if (!publicOnly)
            {
                blobSize += parameters.P.Length +
                            parameters.Q.Length;
            }

            byte[] rsaBlob = new byte[blobSize];
            unsafe
            {
                fixed (byte* pRsaBlob = rsaBlob)
                {
                    // Build the header
                    BCryptNative.BCRYPT_RSAKEY_BLOB* pBcryptBlob = (BCryptNative.BCRYPT_RSAKEY_BLOB*)pRsaBlob;
                    pBcryptBlob->Magic = publicOnly ? BCryptNative.KeyBlobMagicNumber.RsaPublic :
                                                      BCryptNative.KeyBlobMagicNumber.RsaPrivate;

                    pBcryptBlob->cbPublicExp = parameters.Exponent.Length;
                    pBcryptBlob->cbModulus = parameters.Modulus.Length;

                    if (!publicOnly)
                    {
                        pBcryptBlob->cbPrime1 = parameters.P.Length;
                        pBcryptBlob->cbPrime2 = parameters.Q.Length;
                    }

                    int offset = Marshal.SizeOf(typeof(BCryptNative.BCRYPT_RSAKEY_BLOB));

                    // Copy the exponent
                    Buffer.BlockCopy(parameters.Exponent, 0, rsaBlob, offset, parameters.Exponent.Length);
                    offset += parameters.Exponent.Length;

                    // Copy the modulus
                    Buffer.BlockCopy(parameters.Modulus, 0, rsaBlob, offset, parameters.Modulus.Length);
                    offset += parameters.Modulus.Length;

                    if (!publicOnly)
                    {
                        // Copy P
                        Buffer.BlockCopy(parameters.P, 0, rsaBlob, offset, parameters.P.Length);
                        offset += parameters.P.Length;

                        // Copy Q
                        Buffer.BlockCopy(parameters.Q, 0, rsaBlob, offset, parameters.Q.Length);
                        offset += parameters.Q.Length;
                    }
                }
            }

            Key = CngKey.Import(rsaBlob, publicOnly ? s_rsaPublicBlob : s_rsaPrivateBlob);
        }

        //
        // Encryption and decryption
        //

        [SecurityCritical]
        [SecurityTreatAsSafe]
        public override byte[] DecryptValue(byte[] rgb)
        {
            if (rgb == null)
                throw new ArgumentNullException("rgb");

            // Keep a local copy of the key to prevent races with the key container that the key references
            // and the key container permission we're going to demand.
            CngKey key = Key;

            // Make sure we have permission to use the private key to decrypt data
            KeyContainerPermission kcp = BuildKeyContainerPermission(key, KeyContainerPermissionFlags.Decrypt);
            if (kcp != null)
            {
                kcp.Demand();
            }

            new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            SafeNCryptKeyHandle keyHandle = key.Handle;
            CodeAccessPermission.RevertAssert();

            switch (EncryptionPaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.DecryptDataPkcs1(keyHandle, rgb);
                case AsymmetricPaddingMode.Oaep:
                    return NCryptNative.DecryptDataOaep(keyHandle, rgb, EncryptionHashAlgorithm.Algorithm);

                default:
                    throw new InvalidOperationException(Properties.Resources.UnsupportedPaddingMode);
            };
        }

        [SecurityCritical]
        [SecurityTreatAsSafe]
        public override byte[] EncryptValue(byte[] rgb)
        {
            if (rgb == null)
                throw new ArgumentNullException("rgb");

            switch (EncryptionPaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.EncryptDataPkcs1(KeyHandle, rgb);
                case AsymmetricPaddingMode.Oaep:
                    return NCryptNative.EncryptDataOaep(KeyHandle, rgb, EncryptionHashAlgorithm.Algorithm);

                default:
                    throw new InvalidOperationException(Properties.Resources.UnsupportedPaddingMode);
            };
        }

        //
        // Signature APIs
        //

        /// <summary>
        ///     Sign data after hashing it with the SignatureHashAlgorithm
        /// </summary>
        public byte[] SignData(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return SignData(data, 0, data.Length);
        }

        /// <summary>
        ///     Sign data after hashing it with the SignatureHashAlgorithm
        /// </summary>
        public byte[] SignData(byte[] data, int offset, int count)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");
            if (count < 0)
                throw new ArgumentOutOfRangeException("count");
            if (count > data.Length - offset)
                throw new ArgumentOutOfRangeException("count");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data, offset, count);
                return SignHash(hashedData);
            }
        }

        /// <summary>
        ///     Sign data after hashing it with the SignatureHashAlgorithm
        /// </summary>
        public byte[] SignData(Stream data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data);
                return SignHash(hashedData);
            }
        }

        /// <summary>
        ///     Sign data which was hashed using the SignatureHashAlgorithm; if the algorithm used to hash
        ///     the data was different, use the SignHash(byte[], CngAlgorithm) overload instead.
        /// </summary>
        public byte[] SignHash(byte[] hash)
        {
            return SignHash(hash, SignatureHashAlgorithm);
        }

        /// <summary>
        ///     Sign already hashed data, specifying the algorithm it was hashed with
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public byte[] SignHash(byte[] hash, CngAlgorithm hashAlgorithm)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            // Keep a local copy of the key to prevent races with the key container that the key references
            // and the key container permission we're going to demand.
            CngKey key = Key;

            KeyContainerPermission kcp = BuildKeyContainerPermission(key, KeyContainerPermissionFlags.Sign);
            if (kcp != null)
            {
                kcp.Demand();
            }

            new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            SafeNCryptKeyHandle keyHandle = key.Handle;
            CodeAccessPermission.RevertAssert();

            switch (SignaturePaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.SignHashPkcs1(keyHandle, hash, hashAlgorithm.Algorithm);
                case AsymmetricPaddingMode.Pss:
                    return NCryptNative.SignHashPss(keyHandle, hash, hashAlgorithm.Algorithm, SignatureSaltBytes);

                default:
                    throw new InvalidOperationException(Properties.Resources.UnsupportedPaddingMode);
            }
        }

        //
        // Signature verification APIs
        //

        /// <summary>
        ///     Verify data which was signed with the SignatureHashAlgorithm
        /// </summary>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return VerifyData(data, 0, data.Length, signature);
        }

        /// <summary>
        ///     Verify data which was signed with the SignatureHashAlgorithm
        /// </summary>
        public bool VerifyData(byte[] data, int offset, int count, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");
            if (count < 0)
                throw new ArgumentOutOfRangeException("count");
            if (count > data.Length - offset)
                throw new ArgumentOutOfRangeException("count");
            if (signature == null)
                throw new ArgumentNullException("signature");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data, offset, count);
                return VerifyHash(hashedData, signature);
            }
        }

        /// <summary>
        ///     Verify data which was signed with the SignatureHashAlgorithm
        /// </summary>
        public bool VerifyData(Stream data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (signature == null)
                throw new ArgumentNullException("signature");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data);
                return VerifyHash(hashedData, signature);
            }
        }

        /// <summary>
        ///     Verify data which was signed and already hashed with the SignatureHashAlgorithm; if a
        ///     different hash algorithm was used to hash the data use the VerifyHash(byte[], byte[],
        ///     CngAlgorithm) overload instead.
        /// </summary>
        public bool VerifyHash(byte[] hash, byte[] signature)
        {
            return VerifyHash(hash, signature, SignatureHashAlgorithm);
        }

        /// <summary>
        ///     Verify data which was signed and hashed with the given hash algorithm
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public bool VerifyHash(byte[] hash, byte[] signature, CngAlgorithm hashAlgorithm)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (signature == null)
                throw new ArgumentNullException("signature");
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            switch (SignaturePaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.VerifySignaturePkcs1(KeyHandle, hash, hashAlgorithm.Algorithm, signature);
                case AsymmetricPaddingMode.Pss:
                    return NCryptNative.VerifySignaturePss(KeyHandle, hash, hashAlgorithm.Algorithm, SignatureSaltBytes, signature);

                default:
                    throw new InvalidOperationException(Properties.Resources.UnsupportedPaddingMode);
            }
        }
    }
}
