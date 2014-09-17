// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;
using System.Text;  

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the PBKDF2 class
    /// </summary>
    [TestClass]
    public sealed class PBKDF2Tests
    {

        private string[] hashes = new string[] { PBKDF2HashAlgorithm.SHA1, PBKDF2HashAlgorithm.SHA256, PBKDF2HashAlgorithm.SHA384, PBKDF2HashAlgorithm.SHA512 };
        private const Int64 ITERATION_COUNT = 1000;

        [TestMethod]
        public void PBKDF2SHA1TestVector()
        {
            byte[] password = Encoding.ASCII.GetBytes("mypassword");
            byte[] salt = Encoding.ASCII.GetBytes("1234567890");
            byte[] derivedKeyExpected = { 0x19, 0x36, 0x45, 0xd3, 0x70, 0x87, 0x2f, 0x63, 0xd0, 0x95, 0x5d, 0xac, 0x3d, 0x2d, 0xc8, 0x53, 0x59, 0xb1, 0x82, 0x10 };

            byte[] derviedKey = BCryptPBKDF2.ComputeHash(PBKDF2HashAlgorithm.SHA1, password, salt, ITERATION_COUNT);

            Assert.IsTrue(Util.CompareBytes(derviedKey, derivedKeyExpected));
        }

        [TestMethod]
        public void PBKDF2SHA256TestVector()
        {
            byte[] password = Encoding.ASCII.GetBytes("mypassword");
            byte[] salt = Encoding.ASCII.GetBytes("1234567890");
            byte[] derivedKeyExpected = {0x6c, 0xca, 0x73, 0xcd, 0xa2, 0x1a, 0x01, 0xf0, 0x99, 0xaf, 0x2c, 0x7d, 0x68, 0x54, 0x8c, 0x31, 0x09, 0x44, 0x8b, 0x65, 0xcf, 0x12, 0x1d, 0x40, 0x01, 0x98, 0x3d, 0x95, 0x98, 0xdc, 0x01, 0xda};

            byte[] derviedKey = BCryptPBKDF2.ComputeHash(PBKDF2HashAlgorithm.SHA256, password, salt, ITERATION_COUNT);

            Assert.IsTrue(Util.CompareBytes(derviedKey, derivedKeyExpected));
        }

        [TestMethod]
        public void PBKDF2SHA384TestVector()
        {
            byte[] password = Encoding.ASCII.GetBytes("mypassword");
            byte[] salt = Encoding.ASCII.GetBytes("1234567890");
            byte[] derivedKeyExpected = {0x1c, 0xbe, 0x2f, 0x1d, 0x30, 0x8f, 0x38, 0x2c, 0x72, 0x77, 0x42, 0x5b, 0x8f, 0xe8, 0x85, 0x38, 0x75, 0xb0, 0x5c, 0xbd, 0xd9, 0x53, 0xbb, 0xf5, 0x6c, 0x77, 0xeb, 0x11, 0x91, 0x2e, 0x08, 0xc1, 0x78, 0x89, 0xa5, 0x46, 0x72, 0xcd, 0xfd, 0xa3, 0x4e, 0xc0, 0x56, 0xfc, 0x6a, 0xd4, 0x88, 0x12};

            byte[] derviedKey = BCryptPBKDF2.ComputeHash(PBKDF2HashAlgorithm.SHA384, password, salt, ITERATION_COUNT);

            Assert.IsTrue(Util.CompareBytes(derviedKey, derivedKeyExpected));
        }

        [TestMethod]
        public void PBKDF2SHA512TestVector()
        {
            byte[] password = Encoding.ASCII.GetBytes("mypassword");
            byte[] salt = Encoding.ASCII.GetBytes("1234567890");
            byte[] derivedKeyExpected = { 0xb9, 0x1d, 0x6a, 0xac, 0xf4, 0xac, 0x55, 0x4c, 0x1c, 0xc2, 0x1b, 0xfb, 0xc4, 0x71, 0xea, 0xde, 0x24, 0x9a, 0x5e, 0x04, 0x00, 0x3c, 0x5f, 0x22, 0xbe, 0x5d, 0x2a, 0xff, 0xe6, 0x0c, 0x9c, 0xc7, 0xa2, 0x4f, 0x0b, 0x27, 0x42, 0x64, 0x68, 0x4b, 0x4f, 0xad, 0xb2, 0xa7, 0x5d, 0x37, 0xb6, 0x05, 0xc6, 0xbf, 0xc5, 0x33, 0xa1, 0x12, 0x3f, 0x41, 0x5f, 0x93, 0x46, 0x8f, 0xff, 0xde, 0x71, 0x97 };

            byte[] derviedKey = BCryptPBKDF2.ComputeHash(PBKDF2HashAlgorithm.SHA512, password, salt, ITERATION_COUNT);

            Assert.IsTrue(Util.CompareBytes(derviedKey, derivedKeyExpected));
        }

        private static bool IsAllZeroes(byte[] a)
        {
            for (int i = 0; i < a.Length; i++)
                if (a[i] != 0)
                    return false;
            return true;
        }
        private static void ValidateDerivedKey(byte[] derivedKey, string hash)
        {
            int expectedLength;

            if (hash.Equals(PBKDF2HashAlgorithm.SHA1))
                expectedLength = 20;
            else if (hash.Equals(PBKDF2HashAlgorithm.SHA256))
                expectedLength = 32;
            else if (hash.Equals(PBKDF2HashAlgorithm.SHA384))
                expectedLength = 48;
            else if (hash.Equals(PBKDF2HashAlgorithm.SHA512))
                expectedLength = 64;
            else
                throw new ArgumentException("hash must be one from the PBKDF2HashAlgorithm class", "hash");

            Assert.IsTrue(derivedKey != null);
            Assert.IsTrue(derivedKey.Length == expectedLength);
            Assert.IsTrue(!IsAllZeroes(derivedKey));
        }


        [TestMethod]
        public void PBKDF2LongInputTest()
        {
            // Test with a large password and large salt
            RNGCng rng = new RNGCng();
            byte[] password = new byte[1029];
            byte[] salt = new byte[9544];
            rng.GetBytes(salt);
            rng.GetBytes(password);
            
            foreach(string hash in hashes)
            {
                byte[] derivedKey = BCryptPBKDF2.ComputeHash(hash, password, salt, ITERATION_COUNT);
                ValidateDerivedKey(derivedKey, hash);
            }
        }

        [TestMethod]
        public void PBKDF2SmallInputTest()
        {
            // Test with a large password and large salt
            RNGCng rng = new RNGCng();
            byte[] password = new byte[1];
            byte[] salt = new byte[1];
            rng.GetBytes(salt);
            rng.GetBytes(password);

            foreach (string hash in hashes)
            {
                byte[] derivedKey = BCryptPBKDF2.ComputeHash(hash, password, salt, ITERATION_COUNT);
                ValidateDerivedKey(derivedKey, hash);
            }
        }

        [TestMethod]
        public void PBKDF2ZeroLengthTest()
        {
            // Test with zero-length salt/password         
            RNGCng rng = new RNGCng();
            byte[] password; 
            byte[] salt;

            // Test with zero-length salt
            password = new byte[10];
            rng.GetBytes(password);
            salt = new byte[0];
            foreach (string hash in hashes)
            {
                byte[] derivedKey = BCryptPBKDF2.ComputeHash(hash, password, salt, ITERATION_COUNT);
                ValidateDerivedKey(derivedKey, hash);
            }

            // Test with zero-length password
            salt = new byte[16];
            rng.GetBytes(salt);
            password = new byte[0];
            foreach (string hash in hashes)
            {
                byte[] derivedKey = BCryptPBKDF2.ComputeHash(hash, password, salt, ITERATION_COUNT);
                ValidateDerivedKey(derivedKey, hash);
            }
        }

        [TestMethod]
        public void PBKDF2OneIterationTest()
        {
            // Test with one iteration 
            RNGCng rng = new RNGCng();
            byte[] password = new byte[12];
            byte[] salt = new byte[16];
            rng.GetBytes(salt);
            rng.GetBytes(password);

            foreach (string hash in hashes)
            {
                byte[] derivedKey = BCryptPBKDF2.ComputeHash(hash, password, salt, 1);
                ValidateDerivedKey(derivedKey, hash);
            }
        }

    }
}
