// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     Abstract base class for authenticated AES
    /// </summary>
    public abstract class AuthenticatedAes : AuthenticatedSymmetricAlgorithm
    {
        private static KeySizes[] s_legalBlockSizes = { new KeySizes(128, 128, 0) };
        private static KeySizes[] s_legalKeySizes = { new KeySizes(128, 256, 64) };

        protected AuthenticatedAes()
        {
            LegalBlockSizesValue = s_legalBlockSizes;
            LegalKeySizesValue = s_legalKeySizes;

            BlockSizeValue = 128;
            KeySizeValue = 256;
        }

        /// <summary>
        ///     Create an instance of the default Authenticated AES implementation on this machine.
        /// </summary>
        public static new AuthenticatedAes Create()
        {
            return Create(typeof(AuthenticatedAes).Name);
        }

        /// <summary>
        ///     Create an instance of a specific Authenticated AES implementation
        /// </summary>
        public static new AuthenticatedAes Create(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            return CryptoConfig2.CreateFromName(algorithm) as AuthenticatedAes;
        }
    }
}
