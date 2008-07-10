// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Permissions;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Security.Cryptography
{
    /// <summary>
    ///     Extension methods for the CngProvider type
    /// </summary>
    public static class CngProviderExtensionMethods
    {
        /// <summary>
        ///     Get all of the keys that a CNG provider contains
        /// </summary>
        public static IEnumerable<CngKey> GetKeys(this CngProvider provider)
        {
            foreach (CngKey machineKey in GetKeys(provider, CngKeyOpenOptions.MachineKey))
            {
                yield return machineKey;
            }

            foreach (CngKey userKey in GetKeys(provider, CngKeyOpenOptions.UserKey))
            {
                yield return userKey;
            }
        }

        /// <summary>
        ///     Get the keys stored in the provider for either the current user or the machine
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public static IEnumerable<CngKey> GetKeys(this CngProvider provider, CngKeyOpenOptions openOptions)
        {
            using (SafeNCryptProviderHandle providerHandle = provider.OpenProvider())
            {
                foreach (var key in NCryptNative.EnumerateKeys(providerHandle, openOptions))
                {
                    yield return CngKey.Open(key.pszName, provider);
                }
            }
        }

        /// <summary>
        ///     Get all of the keys for a specific algorithm supported by the provider
        /// </summary>
        public static IEnumerable<CngKey> GetKeys(this CngProvider provider,
                                                  CngKeyOpenOptions openOptions,
                                                  CngAlgorithm algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            return from key in provider.GetKeys(openOptions)
                   where key.Algorithm == algorithm
                   select key;
        }

        /// <summary>
        ///     Get all of the algorithms that a CNG provider supports
        /// </summary>
        public static IEnumerable<CngAlgorithm> GetSupportedAlgorithms(this CngProvider provider)
        {
            return GetSupportedAlgorithms(provider, NCryptAlgorithmOperations.AsymmetricEncryption |
                                                    NCryptAlgorithmOperations.Cipher |
                                                    NCryptAlgorithmOperations.Hash |
                                                    NCryptAlgorithmOperations.RandomNumberGeneration |
                                                    NCryptAlgorithmOperations.SecretAgreement |
                                                    NCryptAlgorithmOperations.Signature);
        }

        /// <summary>
        ///     Get all of the algorithms that a CNG provider supports for a specific operation
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public static IEnumerable<CngAlgorithm> GetSupportedAlgorithms(this CngProvider provider,
                                                                       NCryptAlgorithmOperations operations)
        {
            using (SafeNCryptProviderHandle providerHandle = provider.OpenProvider())
            {
                foreach (NCryptNative.NCryptAlgorithmName algorithm in NCryptNative.EnumerateAlgorithms(providerHandle, operations))
                {
                    yield return new CngAlgorithm(algorithm.pszName);
                }
            }
        }

        /// <summary>
        ///     Open a safe handle to the provider which can be used with other P/Invoke methods
        /// </summary>
        [SecurityCritical]
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        public static SafeNCryptProviderHandle OpenProvider(this CngProvider provider)
        {
            return NCryptNative.OpenKeyStorageProvider(provider.Provider);
        }
    }
}