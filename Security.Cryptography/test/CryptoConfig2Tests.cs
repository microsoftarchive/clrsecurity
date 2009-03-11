// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
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
                // System.Core.dll mappings
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

                // Security.Crytpography.dll mappings
                new Mapping { Name = "AuthenticatedAes", ExpectedType = typeof(AuthenticatedAesCng) },
                new Mapping { Name = "AuthenticatedSymmetricAlgorithm", ExpectedType = typeof(AuthenticatedAesCng) },
                new Mapping { Name = "AuthenticatedAesCng", ExpectedType = typeof(AuthenticatedAesCng) },
                new Mapping { Name = "Security.Cryptography.AuthenticatedAesCng", ExpectedType = typeof(AuthenticatedAesCng) },
                new Mapping { Name = "HMACSHA256Cng", ExpectedType = typeof(HMACSHA256Cng) },
                new Mapping { Name = "Security.Cryptography.HMACSHA256Cng", ExpectedType = typeof(HMACSHA256Cng) },
                new Mapping { Name = "HMACSHA384Cng", ExpectedType = typeof(HMACSHA384Cng) },
                new Mapping { Name = "Security.Cryptography.HMACSHA384Cng", ExpectedType = typeof(HMACSHA384Cng) },
                new Mapping { Name = "HMACSHA512Cng", ExpectedType = typeof(HMACSHA512Cng) },
                new Mapping { Name = "Security.Cryptography.HMACSHA512Cng", ExpectedType = typeof(HMACSHA512Cng) },
                new Mapping { Name = "RNGCng", ExpectedType = typeof(RNGCng) },
                new Mapping { Name = "Security.Cryptography.RNGCng", ExpectedType = typeof(RNGCng) },
                new Mapping { Name = "RSACng", ExpectedType = typeof(RSACng) },
                new Mapping { Name = "Security.Cryptography.RSACng", ExpectedType = typeof(RSACng) },
                new Mapping { Name = "TripleDESCng", ExpectedType = typeof(TripleDESCng) },
                new Mapping { Name = "Security.Cryptography.TripleDESCng", ExpectedType = typeof(TripleDESCng) }
            };

            CheckMappings(cryptoConfig2Mappings);
        }

        [TestMethod]
        public void CryptoConfig2AddMappingTest()
        {
            List<Mapping> addedMappings = new List<Mapping>();

            // Make sure that registering a class a class without any alises works
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm1));
            addedMappings.Add(new Mapping { Name = "NewAlgorithm1", ExpectedType = typeof(NewAlgorithm1) });
            addedMappings.Add(new Mapping { Name = "Security.Cryptography.Test.NewAlgorithm1", ExpectedType = typeof(NewAlgorithm1) });
            CheckMappings(addedMappings);

            // Re-registering the same class with some new aliases should also work
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm1), "NA1", "NewAlg1");
            addedMappings.Add(new Mapping { Name = "NA1", ExpectedType = typeof(NewAlgorithm1) });
            addedMappings.Add(new Mapping { Name = "NewAlg1", ExpectedType = typeof(NewAlgorithm1) });
            CheckMappings(addedMappings);

            // Adding alaises even once we've already added alaises should continue to work
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm1), "New-Alg-1");
            addedMappings.Add(new Mapping { Name = "New-Alg-1", ExpectedType = typeof(NewAlgorithm1) });
            CheckMappings(addedMappings);

            // Add an algorithm and some alaises at the same time, should work the same as doing the above all at once
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm2), "NA2", "NewAlg2", "New-Alg-2");
            addedMappings.Add(new Mapping { Name = "NewAlgorithm2", ExpectedType = typeof(NewAlgorithm2) });
            addedMappings.Add(new Mapping { Name = "Security.Cryptography.Test.NewAlgorithm2", ExpectedType = typeof(NewAlgorithm2) });
            addedMappings.Add(new Mapping { Name = "NA2", ExpectedType = typeof(NewAlgorithm2) });
            addedMappings.Add(new Mapping { Name = "NewAlg2", ExpectedType = typeof(NewAlgorithm2) });
            addedMappings.Add(new Mapping { Name = "New-Alg-2", ExpectedType = typeof(NewAlgorithm2) });
            CheckMappings(addedMappings);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CryptoConfig2AddEmptyMappingTest()
        {
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm3), "NA3", "", "New-Alg-3");
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CryptoConfig2AddNullMappingTest()
        {
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm4), "NA4", "NewAlg4", null);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CryptoConfig2AddDuplicateMappingTest()
        {
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm5), "NA5", "NewAlg5", "New-Alg5");
            CryptoConfig2.AddAlgorithm(typeof(NewAlgorithm6), "NA5");
        }

        /// <summary>
        ///     Utility method to assist in making sure a set of mappings are correctly registered in CryptoConfig2
        /// </summary>
        private static void CheckMappings(IEnumerable<Mapping> mappings)
        {
            foreach (Mapping mapping in mappings)
            {
                object algorithm = CryptoConfig2.CreateFromName(mapping.Name);
                Assert.IsNotNull(algorithm, "Failed to create algorithm in CryptoConfig2 for " + mapping.Name);
                Assert.AreEqual(mapping.ExpectedType, algorithm.GetType(), "Failed to map CryptoConfig2 for " + mapping.Name);
            }
        }
    }

    //
    // Classes to test registering in CryptoConfig
    //

    public class NewAlgorithm1 { }
    public class NewAlgorithm2 { }
    public class NewAlgorithm3 { }
    public class NewAlgorithm4 { }
    public class NewAlgorithm5 { }
    public class NewAlgorithm6 { }
}
