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
    ///    Test vectors for AES GCM mode from
    ///    http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
    ///</summary>
    [TestClass]
    public class AuthenticatedAesCngGcmTestVectorTests
    {
        private class GcmTestVector
        {
            // Test vector input data
            public string K { get; set; }
            public string P { get; set; }
            public string A { get; set; }
            public string IV { get; set; }
            public string C { get; set; }
            public string T {get; set; }

            // Byte array versions of the input data
            
            public byte[] Key
            {
                get { return Util.HexStringToBytes(K); }
            }

            public byte[] Plaintext
            {
                get { return Util.HexStringToBytes(P); }
            }

            public byte[] AuthenticationData
            {
                get { return Util.HexStringToBytes(A); }
            }

            public byte[] IVBytes
            {
                get { return Util.HexStringToBytes(IV); }
            }

            public byte[] Ciphertext
            {
                get { return Util.HexStringToBytes(C); }
            }

            public byte[] Tag
            {
                get { return Util.HexStringToBytes(T); }
            }
        }

        private static GcmTestVector[] s_testVectors = new GcmTestVector[]
        {
            // Test Case 1
            new GcmTestVector
            {
                K = "00000000000000000000000000000000",
                P = null,
                IV = "000000000000000000000000",
                C = null,
                T = "58e2fccefa7e3061367f1d57a4e7455a"
            },

            // Test Case 2
            new GcmTestVector
            {
                K = "00000000000000000000000000000000",
                P = "00000000000000000000000000000000",
                IV = "000000000000000000000000",
                C = "0388dace60b6a392f328c2b971b2fe78",
                T = "ab6e47d42cec13bdf53a67b21257bddf"
            },

            // Test Case 3
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                IV = "cafebabefacedbaddecaf888",
                C = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                T = "4d5c2af327cd64a62cf35abd2ba6fab4"
            },

            // Test Case 4
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "cafebabefacedbaddecaf888",
                C = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                T = "5bc94fbc3221a5db94fae95ae7121a47"
            },

            // Test Case 5
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "cafebabefacedbad",
                C = "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
                T = "3612d2e79e3b0785561be14aaca2fccb"
            },

            // Test Case 6
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A ="feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
                C = "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
                T = "619cc5aefffe0bfa462af43c1699d050"
            },

            // Test Case 7
            new GcmTestVector
            {
                K = "000000000000000000000000000000000000000000000000",
                P = null,
                IV = "000000000000000000000000",
                C = null,
                T = "cd33b28ac773f74ba00ed1f312572435"
            },

            // Test Case 8
            new GcmTestVector
            {
                K = "000000000000000000000000000000000000000000000000",
                P = "00000000000000000000000000000000",
                IV = "000000000000000000000000",
                C = "98e7247c07f0fe411c267e4384b0f600",
                T = "2ff58d80033927ab8ef4d4587514f0fb"
            },

            // Test Case 9
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                IV = "cafebabefacedbaddecaf888",
                C = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
                T = "9924a7c8587336bfb118024db8674a14"
            },

            // Test Case 10
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "cafebabefacedbaddecaf888",
                C = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
                T = "2519498e80f1478f37ba55bd6d27618c"
            },

            // Test Case 11
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "cafebabefacedbad",
                C = "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
                T = "65dcc57fcf623a24094fcca40d3533f8"
            },

            // Test Case 12
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
                C = "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
                T = "dcf566ff291c25bbb8568fc3d376a6d9"
            },

            // Test Case 13
            new GcmTestVector
            {
                K = "0000000000000000000000000000000000000000000000000000000000000000",
                P = null,
                IV = "000000000000000000000000",
                C = null,
                T = "530f8afbc74536b9a963b4f1c4cb738b"
            },

            // Test Case 14
            new GcmTestVector
            {
                K = "0000000000000000000000000000000000000000000000000000000000000000",
                P = "00000000000000000000000000000000",
                IV = "000000000000000000000000",
                C = "cea7403d4d606b6e074ec5d3baf39d18",
                T = "d0d1c8a799996bf0265b98b5d48ab919"
            },

            // Test Case 15
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                IV = "cafebabefacedbaddecaf888",
                C = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                T = "b094dac5d93471bdec1a502270e3cc6c"
            },

            // Test Case 16
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "cafebabefacedbaddecaf888",
                C = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                T = "76fc6ece0f4e1768cddf8853bb2d551b"
            },

            // Test Case 17
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "cafebabefacedbad",
                C = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
                T = "3a337dbf46a792c45e454913fe2ea8f2"
            },

            // Test Case 18
            new GcmTestVector
            {
                K = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                P = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                A = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                IV = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
                C = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
                T = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
            }
        };

        // Test vectors that should succeed
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector1() { RunTestVector(s_testVectors[0]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector2() { RunTestVector(s_testVectors[1]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector3() { RunTestVector(s_testVectors[2]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector4() { RunTestVector(s_testVectors[3]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector7() { RunTestVector(s_testVectors[6]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector8() { RunTestVector(s_testVectors[7]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector9() { RunTestVector(s_testVectors[8]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector10() { RunTestVector(s_testVectors[9]); }        
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector13() { RunTestVector(s_testVectors[12]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector14() { RunTestVector(s_testVectors[13]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector15() { RunTestVector(s_testVectors[14]); }
        [TestMethod]
        public void AuthenticatedAesCngGcmTestVector16() { RunTestVector(s_testVectors[15]); }

        // Test vectors that fail in BCryptEncrypt due to a IV size which is not 12 bytes
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void AuthenticatedAesCngGcmTestVector5() { RunTestVector(s_testVectors[4]); }
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void AuthenticatedAesCngGcmTestVector6() { RunTestVector(s_testVectors[5]); }
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void AuthenticatedAesCngGcmTestVector11() { RunTestVector(s_testVectors[10]); }
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void AuthenticatedAesCngGcmTestVector12() { RunTestVector(s_testVectors[11]); }
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void AuthenticatedAesCngGcmTestVector17() { RunTestVector(s_testVectors[16]); }
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void AuthenticatedAesCngGcmTestVector18() { RunTestVector(s_testVectors[17]); }

        private void RunTestVector(GcmTestVector test)
        {
            // Encrypt the input
            byte[] ciphertext = null;
            using (AuthenticatedAesCng gcm = new AuthenticatedAesCng())
            {
                gcm.CngMode = CngChainingMode.Gcm;
                gcm.Key = test.Key;
                gcm.IV = test.IVBytes;
                gcm.AuthenticatedData = test.AuthenticationData;

                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = gcm.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    if (test.Plaintext != null)
                    {
                        cs.Write(test.Plaintext, 0, test.Plaintext.Length);
                    }

                    cs.FlushFinalBlock();
                    ciphertext = ms.ToArray();

                    // Verify the produced tag is what we expected it to be
                    Assert.IsTrue(Util.CompareBytes(test.Tag, encryptor.GetTag()));
                }
            }

            if (test.Ciphertext != null)
            {
                // Verify the ciphertext is what we expected it to be
                Assert.IsTrue(Util.CompareBytes(test.Ciphertext, ciphertext));

                // Round trip the data
                using (AuthenticatedAesCng gcm = new AuthenticatedAesCng())
                {
                    gcm.CngMode = CngChainingMode.Gcm;
                    gcm.Key = test.Key;
                    gcm.IV = test.IVBytes;
                    gcm.AuthenticatedData = test.AuthenticationData;
                    gcm.Tag = test.Tag;

                    using (MemoryStream ms = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ms, gcm.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(test.Ciphertext, 0, test.Ciphertext.Length);
                        cs.FlushFinalBlock();

                        byte[] plaintext = ms.ToArray();
                        Assert.IsTrue(Util.CompareBytes(test.Plaintext, plaintext));
                    }
                }
            }
        }
    }
}