// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Extra CngProvider objects for providers not included in the standard CngProvider type
    /// </summary>
    public static class CngProvider2
    {
        private static CngProvider s_primitiveAlgorithmProvider;

        /// <summary>
        ///     Get a CngProvider for the Microsoft Primitive algorithm provider
        /// </summary>
        public static CngProvider MicrosoftPrimitiveAlgorithmProvider
        {
            get
            {
                if (s_primitiveAlgorithmProvider == null)
                {
                    s_primitiveAlgorithmProvider = new CngProvider(BCryptNative.ProviderName.MicrosoftPrimitiveProvider);
                }

                return s_primitiveAlgorithmProvider;
            }
        }
    }
}
