// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     Random number generator using the BCrypt RNG
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RNG", Justification = "This is for consistency with the existing RNGCryptoServiceProvider type")]
    public sealed class RNGCng : RandomNumberGenerator, IDisposable
    {
        private SafeBCryptAlgorithmHandle m_algorithm;

        private static RNGCng s_rngCng = new RNGCng();

        [SecurityCritical]
        [SecurityTreatAsSafe]
        public RNGCng()
        {
            m_algorithm = BCryptNative.OpenAlgorithm(BCryptNative.AlgorithmName.Rng,
                                                     BCryptNative.ProviderName.MicrosoftPrimitiveProvider);
        }

        /// <summary>
        ///     Static random number generator that can be shared within the AppDomain
        /// </summary>
        internal static RNGCng StaticRng
        {
            get { return s_rngCng; }
        }

        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of Dispose")]
        public void Dispose()
        {
            if (m_algorithm != null)
            {
                m_algorithm.Dispose();
            }
        }

        /// <summary>
        ///     Helper function to generate a random key value using the static RNG
        /// </summary>
        internal static byte[] GenerateKey(int size)
        {
            Debug.Assert(size > 0, "size > 0");

            byte[] key = new byte[size];
            StaticRng.GetBytes(key);
            return key;
        }

        [SecurityCritical]
        [SecurityTreatAsSafe]
        public override void GetBytes(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            BCryptNative.GenerateRandomBytes(m_algorithm, data);
        }

        public override void GetNonZeroBytes(byte[] data)
        {
            throw new NotImplementedException();
        }
    }
}