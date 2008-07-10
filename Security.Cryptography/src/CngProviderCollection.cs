// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     This type provides access to all of the CNG providers installed on the current machine
    /// </summary>
    public sealed class CngProviderCollection : IEnumerable<CngProvider>
    {
        public IEnumerator<CngProvider> GetEnumerator()
        {
            foreach (NCryptNative.NCryptProviderName providerName in NCryptNative.EnumerateStorageProviders())
            {
                yield return new CngProvider(providerName.pszName);
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
