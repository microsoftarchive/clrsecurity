// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the CryptoConfig2 class
    /// </summary>
    [TestClass]
    public class CryptoConfig2Tests
    {
        private struct Mapping
        {
            public string Name;
            public Type ExpectedType;
        }

        /// <summary>
        ///     Make sure that CryptoConfig2 can map CrytptoConfig names
        /// </summary>
        [TestMethod]
        public void CryptoConfig2OldNameMapTest()
        {
            Mapping[] cryptoConfigMappings = new Mapping[]
            {
                // Just provide a few selections from mscorlib's crypto config mappings to ensure that they
                // are all working as we expect
                new Mapping { Name = "RSA", ExpectedType = typeof(RSACryptoServiceProvider) },
                new Mapping { Name = "System.Security.Cryptography.RSACryptoServiceProvider", ExpectedType = typeof(RSACryptoServiceProvider) },
                new Mapping { Name = "System.Security.Cryptography.SHA1Managed", ExpectedType = typeof(SHA1Managed) }
            };

            foreach (Mapping mapping in cryptoConfigMappings)
            {
                object algorithm = CryptoConfig2.CreateFromName(mapping.Name);
                Assert.IsNotNull(algorithm, "Failed to create algorithm in CryptoConfig for " + mapping.Name);
                Assert.AreEqual(mapping.ExpectedType, algorithm.GetType(), "Failed to map CryptoConfig for " + mapping.Name);
            }
        }

        /// <summary>
        ///     Make sure that CryptoConfig2 can map the new algorithms
        /// </summary>
        [TestMethod]
        public void CryptoConfig2MapTest()
        {
            Mapping[] cryptoConfig2Mappings = new Mapping[]
            {
                    new Mapping { Name = "AES", ExpectedType = typeof(AesCryptoServiceProvider) },
                    new Mapping { Name = "aes", ExpectedType = typeof(AesCryptoServiceProvider) },
                    new Mapping { Name = "AesCryptoServiceProvider", ExpectedType = typeof(AesCryptoServiceProvider) },
                    new Mapping { Name = "System.Security.Cryptography.AesCryptoServiceProvider", ExpectedType = typeof(AesCryptoServiceProvider) },
                    new Mapping { Name = "AesManaged", ExpectedType = typeof(AesManaged) },
                    new Mapping { Name = "System.Security.Cryptography.AesManaged", ExpectedType = typeof(AesManaged) },
                    new Mapping { Name = "ECDsa", ExpectedType = typeof(ECDsaCng) },
                    new Mapping { Name = "ECDsaCng", ExpectedType = typeof(ECDsaCng) },
                    new Mapping { Name = "System.Security.Cryptography.ECDsaCng", ExpectedType = typeof(ECDsaCng) },
                    new Mapping { Name = "ECDH", ExpectedType = typeof(ECDiffieHellmanCng) },
                    new Mapping { Name = "ECDiffieHellman", ExpectedType = typeof(ECDiffieHellmanCng) },
                    new Mapping { Name = "ECDiffieHellmanCng", ExpectedType = typeof(ECDiffieHellmanCng) },
                    new Mapping { Name = "System.Security.Cryptography.ECDiffieHellmanCng", ExpectedType = typeof(ECDiffieHellmanCng) },
                    new Mapping { Name = "MD5Cng", ExpectedType = typeof(MD5Cng) },
                    new Mapping { Name = "System.Security.Cryptography.MD5Cng", ExpectedType = typeof(MD5Cng) },
                    new Mapping { Name = "SHA1Cng", ExpectedType = typeof(SHA1Cng) },
                    new Mapping { Name = "System.Security.Cryptography.SHA1Cng", ExpectedType = typeof(SHA1Cng) },
                    new Mapping { Name = "SHA256Cng", ExpectedType = typeof(SHA256Cng) },
                    new Mapping { Name = "System.Security.Cryptography.SHA256Cng", ExpectedType = typeof(SHA256Cng) },
                    new Mapping { Name = "SHA256CryptoServiceProvider", ExpectedType = typeof(SHA256CryptoServiceProvider) },
                    new Mapping { Name = "System.Security.Cryptography.SHA256CryptoServiceProvider", ExpectedType = typeof(SHA256CryptoServiceProvider) },
                    new Mapping { Name = "SHA384CNG", ExpectedType = typeof(SHA384Cng) },
                    new Mapping { Name = "System.Security.Cryptography.SHA384CNG", ExpectedType = typeof(SHA384Cng) },
                    new Mapping { Name = "SHA384CryptoServiceProvider", ExpectedType = typeof(SHA384CryptoServiceProvider) },
                    new Mapping { Name = "System.Security.Cryptography.SHA384CryptoServiceProvider", ExpectedType = typeof(SHA384CryptoServiceProvider) },
                    new Mapping { Name = "SHA512Cng", ExpectedType = typeof(SHA512Cng) },
                    new Mapping { Name = "System.Security.Cryptography.SHA512Cng", ExpectedType = typeof(SHA512Cng) },
                    new Mapping { Name = "SHA512CryptoServiceProvider", ExpectedType = typeof(SHA512CryptoServiceProvider) },
                    new Mapping { Name = "System.Security.Cryptography.SHA512CryptoServiceProvider", ExpectedType = typeof(SHA512CryptoServiceProvider) },
                    new Mapping { Name = "AesCng", ExpectedType = typeof(AesCng) },
                    new Mapping { Name = "Security.Cryptography.AesCng", ExpectedType = typeof(AesCng) },
                    new Mapping { Name = "RNGCng", ExpectedType = typeof(RNGCng) },
                    new Mapping { Name = "Security.Cryptography.RNGCng", ExpectedType = typeof(RNGCng) },
                    new Mapping { Name = "RSACng", ExpectedType = typeof(RSACng) },
                    new Mapping { Name = "Security.Cryptography.RSACng", ExpectedType = typeof(RSACng) },
                    new Mapping { Name = "TripleDESCng", ExpectedType = typeof(TripleDESCng) },
                    new Mapping { Name = "Security.Cryptography.TripleDESCng", ExpectedType = typeof(TripleDESCng) }
            };

            foreach (Mapping mapping in cryptoConfig2Mappings)
            {
                object algorithm = CryptoConfig2.CreateFromName(mapping.Name);
                Assert.IsNotNull(algorithm, "Failed to create algorithm in CryptoConfig2 for " + mapping.Name);
                Assert.AreEqual(mapping.ExpectedType, algorithm.GetType(), "Failed to map CryptoConfig2 for " + mapping.Name);

            }
        }
    }
}
