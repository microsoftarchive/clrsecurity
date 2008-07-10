// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;

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
        private static Dictionary<string, Type> s_algorithmMap;

        /// <summary>
        ///     Mapping of algorithm names to algorithm types
        /// </summary>
        private static Dictionary<string, Type> AlgorithmMap
        {
            get
            {
                if (s_algorithmMap == null)
                {
                    Dictionary<string, Type> map = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);

                    //
                    // System.Core algorithms
                    //

                    map.Add("AES", typeof(AesCryptoServiceProvider));
                    AddAlgorithm(map, typeof(AesCryptoServiceProvider));
                    AddAlgorithm(map, typeof(AesManaged));

                    map.Add("ECDsa", typeof(ECDsaCng));
                    AddAlgorithm(map, typeof(ECDsaCng));

                    map.Add("ECDH", typeof(ECDiffieHellmanCng));
                    map.Add("ECDiffieHellman", typeof(ECDiffieHellmanCng));
                    AddAlgorithm(map, typeof(ECDiffieHellmanCng));

                    AddAlgorithm(map, typeof(MD5Cng));
                    AddAlgorithm(map, typeof(SHA1Cng));
                    AddAlgorithm(map, typeof(SHA256Cng));
                    AddAlgorithm(map, typeof(SHA256CryptoServiceProvider));
                    AddAlgorithm(map, typeof(SHA384Cng));
                    AddAlgorithm(map, typeof(SHA384CryptoServiceProvider));
                    AddAlgorithm(map, typeof(SHA512Cng));
                    AddAlgorithm(map, typeof(SHA512CryptoServiceProvider));

                    //
                    // Security.Cryptography algorithms
                    //

                    AddAlgorithm(map, typeof(AesCng));
                    AddAlgorithm(map, typeof(RNGCng));
                    AddAlgorithm(map, typeof(RSACng));
                    AddAlgorithm(map, typeof(TripleDESCng));

                    s_algorithmMap = map;
                }

                return s_algorithmMap;
            }
        }

        /// <summary>
        ///     Add an algorithm to the type map
        /// </summary>
        private static void AddAlgorithm(Dictionary<string, Type> map, Type algorithm)
        {
            Debug.Assert(map != null, "map != null");
            Debug.Assert(algorithm != null, "algorithm != null");

            map.Add(algorithm.Name, algorithm);
            map.Add(algorithm.FullName, algorithm);
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
            Type cryptoConfig2Type = null;
            if (AlgorithmMap.TryGetValue(name, out cryptoConfig2Type))
            {
                return Activator.CreateInstance(cryptoConfig2Type);
            }

            // Otherwise we don't know how to create this type, so just return null
            return null;
        }
    }
}
