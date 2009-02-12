// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Threading;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     .NET v3.5 added some new crypto algorithms in System.Core.dll, however due to layering
    ///     restrictions CryptoConfig does not have registration entries for these algorithms.  Similarly,
    ///     CryptoConfig does not know about any of the algorithms added in this assembly.
    ///     
    ///     CryptoConfig2 wraps the CryptoConfig.Create method, allowing it to also create System.Core and
    ///     Microsoft.Security.Cryptography algorithm objects.
    /// </summary>
    public static class CryptoConfig2
    {
        private static Dictionary<string, Type> s_algorithmMap = DefaultAlgorithmMap;
        private static ReaderWriterLockSlim s_algorithmMapLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        /// <summary>
        ///     Default mapping of algorithm names to algorithm types
        /// </summary>
        private static Dictionary<string, Type> DefaultAlgorithmMap
        {
            get
            {
                Dictionary<string, Type> map = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);

                //
                // System.Core algorithms
                //

                AddAlgorithmToMap(map, typeof(AesCryptoServiceProvider), "AES");
                AddAlgorithmToMap(map, typeof(AesManaged));

                AddAlgorithmToMap(map, typeof(ECDsaCng), "ECDsa");

                AddAlgorithmToMap(map, typeof(ECDiffieHellmanCng), "ECDH", "ECDiffieHellman");

                AddAlgorithmToMap(map, typeof(MD5Cng));
                AddAlgorithmToMap(map, typeof(SHA1Cng));
                AddAlgorithmToMap(map, typeof(SHA256Cng));
                AddAlgorithmToMap(map, typeof(SHA256CryptoServiceProvider));
                AddAlgorithmToMap(map, typeof(SHA384Cng));
                AddAlgorithmToMap(map, typeof(SHA384CryptoServiceProvider));
                AddAlgorithmToMap(map, typeof(SHA512Cng));
                AddAlgorithmToMap(map, typeof(SHA512CryptoServiceProvider));

                //
                // Security.Cryptography algorithms
                //

                AddAlgorithmToMap(map, typeof(AesCng));
                AddAlgorithmToMap(map, typeof(HMACSHA256Cng));
                AddAlgorithmToMap(map, typeof(HMACSHA384Cng));
                AddAlgorithmToMap(map, typeof(HMACSHA512Cng));
                AddAlgorithmToMap(map, typeof(RNGCng));
                AddAlgorithmToMap(map, typeof(RSACng));
                AddAlgorithmToMap(map, typeof(TripleDESCng));

                return map;
            }
        }

        /// <summary>
        ///     Add an algorithm to the default map used in this AppDomain
        /// </summary>
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        [SecurityCritical]
        public static void AddAlgorithm(Type algorithm, params string[] aliases)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (aliases == null)
                throw new ArgumentNullException("aliases");

            s_algorithmMapLock.EnterWriteLock();
            try
            {
                // Make sure that we don't already have mappings for the input aliases - we want to eagerly
                // check for this rather than just letting the hash table insert fail so that the map doesn't
                // end up with some of the aliases added and others not added.
                // 
                // Note that we're explicitly not trying to protect against having the same alias added
                // multiple times via the same call to AddAlgorithm, since that problem is detectable by the
                // user of the API whereas detecting a conflict with another alias which had been previously
                // added cannot be reliably detected in the presense of multiple threads.
                foreach (string alias in aliases)
                {
                    if (String.IsNullOrEmpty(alias))
                    {
                        throw new InvalidOperationException(Resources.EmptyCryptoConfigAlias);
                    }

                    if (s_algorithmMap.ContainsKey(alias))
                    {
                        throw new InvalidOperationException(String.Format(Resources.Culture, Resources.DuplicateCryptoConfigAlias, alias));
                    }
                }

                AddAlgorithmToMap(s_algorithmMap, algorithm, aliases);
            }
            finally
            {
                s_algorithmMapLock.ExitWriteLock();
            }
        }

        /// <summary>
        ///     Add an algorithm to a given type map
        /// </summary>
        private static void AddAlgorithmToMap(Dictionary<string, Type> map, Type algorithm, params string[] aliases)
        {
            Debug.Assert(map != null, "map != null");
            Debug.Assert(algorithm != null, "algorithm != null");

            foreach (string alias in aliases)
            {
                Debug.Assert(!String.IsNullOrEmpty(alias), "!String.IsNullOrEmpty(alias)");
                map.Add(alias, algorithm);
            }

            if (!map.ContainsKey(algorithm.Name))
            {
                map.Add(algorithm.Name, algorithm);
            }

            if (!map.ContainsKey(algorithm.FullName))
            {
                map.Add(algorithm.FullName, algorithm);
            }
        }

        /// <summary>
        ///     Create an object from crypto config
        /// </summary>
        public static object CreateFromName(string name)
        {
            if (name == null)
                throw new ArgumentNullException("name");

            // First try to use standard CryptoConfig to create the algorithm
            object cryptoConfigAlgorithm = CryptoConfig.CreateFromName(name);
            if (cryptoConfigAlgorithm != null)
            {
                return cryptoConfigAlgorithm;
            }

            // If we couldn't find the algorithm in crypto config, see if we have an internal mapping for
            // the name
            s_algorithmMapLock.EnterReadLock();
            try
            {
                Type cryptoConfig2Type = null;
                if (s_algorithmMap.TryGetValue(name, out cryptoConfig2Type))
                {
                    return Activator.CreateInstance(cryptoConfig2Type);
                }
            }
            finally
            {
                s_algorithmMapLock.ExitReadLock();
            }

            // Otherwise we don't know how to create this type, so just return null
            return null;
        }
    }
}
