// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Extra CNG algorithm objects for algorithms not in the standard CngAlgorithm type
    /// </summary>
    public static class CngAlgorithm2
    {
        private static CngAlgorithm s_rsa = new CngAlgorithm(BCryptNative.AlgorithmName.Rsa);

        /// <summary>
        ///     CngAlgorithm for the RSA asymmetric algorithm
        /// </summary>
        public static CngAlgorithm Rsa
        {
            get { return s_rsa; }
        }
    }
}
