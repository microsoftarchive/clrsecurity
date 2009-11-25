// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace Microsoft.Security.Cryptography.Test
{
    /// <summary>
    ///     Tests for the CngKey extension methods
    /// </summary>
    [TestClass]
    public sealed class CngKeyTests
    {
        /// <summary>
        ///     Test to ensure that making a default certificate works as expected
        /// </summary>
        [TestMethod]
        public void CreateDefaultCertificate()
        {
            DateTime preCreationTime = DateTime.UtcNow;
            DateTime postCreationTime = DateTime.UtcNow;
            byte[] pfx = null;

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;

            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa, null, keyCreationParameters))
            {
                preCreationTime = DateTime.UtcNow;
                X509Certificate2 cert = key.CreateSelfSignedCertificate(new X500DistinguishedName("CN=TestCert"));
                postCreationTime = DateTime.UtcNow;

                Assert.AreEqual("TestCert", cert.GetNameInfo(X509NameType.SimpleName, true));
                Assert.AreEqual("TestCert", cert.GetNameInfo(X509NameType.SimpleName, false));

                Assert.IsTrue(cert.NotBefore.ToUniversalTime().Date.Equals(preCreationTime.Date) ||
                              cert.NotBefore.ToUniversalTime().Date.Equals(postCreationTime.Date));
                Assert.IsTrue(cert.NotAfter.ToUniversalTime().Date.Equals(preCreationTime.Date.AddYears(1)) ||
                              cert.NotAfter.ToUniversalTime().Date.Equals(postCreationTime.Date.AddYears(1)));

                Assert.IsTrue(cert.HasCngKey());
                Assert.IsTrue(cert.HasPrivateKey);

                // Try to round trip through PFX
                pfx = cert.Export(X509ContentType.Pfx, "TestPassword");
            }

            // Make sure we can read back the PFX file even after the original key is gone
            X509Certificate2 rtCert = new X509Certificate2(pfx, "TestPassword");
            Assert.AreEqual("TestCert", rtCert.GetNameInfo(X509NameType.SimpleName, true));
            Assert.AreEqual("TestCert", rtCert.GetNameInfo(X509NameType.SimpleName, false));

            Assert.IsTrue(rtCert.NotBefore.ToUniversalTime().Date.Equals(preCreationTime.Date) ||
                          rtCert.NotBefore.ToUniversalTime().Date.Equals(postCreationTime.Date));
            Assert.IsTrue(rtCert.NotAfter.ToUniversalTime().Date.Equals(preCreationTime.Date.AddYears(1)) ||
                          rtCert.NotAfter.ToUniversalTime().Date.Equals(postCreationTime.Date.AddYears(1)));

            Assert.IsTrue(rtCert.HasCngKey());
            Assert.IsTrue(rtCert.HasPrivateKey);
        }

        /// <summary>
        ///     Test to ensure that the CngKey given to a certificate is no longer usable once the certificate
        ///     has taken ownership of that key.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ObjectDisposedException))]
        public void CreateCertificateReuseKey()
        {
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;

            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa, null, keyCreationParameters))
            {
                key.CreateSelfSignedCertificate(new X500DistinguishedName("CN=TestCert"));
                CngAlgorithm algorithm = key.Algorithm;
            }
        }

        /// <summary>
        ///     Test to ensure that creating a certificate without transferring ownership of the key
        ///     keeps the input CngKey in a usable state.
        /// </summary>
        [TestMethod]
        public void CreateCertificateNoOwnershipChangeReuseKey()
        {
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;

            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa, null, keyCreationParameters))
            {
                X509CertificateCreationParameters certCreationParameters =
                    new X509CertificateCreationParameters(new X500DistinguishedName("CN=TestCert"));
                certCreationParameters.TakeOwnershipOfKey = false;

                key.CreateSelfSignedCertificate(certCreationParameters);

                // Make sure the X509Certificate has been destroyed
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                GC.WaitForPendingFinalizers();

                Assert.AreEqual(CngAlgorithm2.Rsa, key.Algorithm);
            }
        }


        /// <summary>
        ///     Test to ensure we can create a certificate with multiple extensions in it
        /// </summary>
        [TestMethod]
        public void CreateCertificateWithExtensions()
        {
            byte[] pfx = null;

            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(new X500DistinguishedName("CN=TestCertWithExtensions"));
            creationParams.SignatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha512;

            creationParams.Extensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            creationParams.Extensions.Add(new X509BasicConstraintsExtension(false, true, 5, false));

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;
            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa, null, keyCreationParameters))
            {
                X509Certificate2 cert = key.CreateSelfSignedCertificate(creationParams);

                bool foundKeyUsageExtension = false;
                bool foundBasicConstraintExtension = false;

                foreach (X509Extension extension in cert.Extensions)
                {
                    X509KeyUsageExtension keyUsageExtension = extension as X509KeyUsageExtension;
                    X509BasicConstraintsExtension basicConstraintsExtension = extension as X509BasicConstraintsExtension;

                    if (keyUsageExtension != null)
                    {
                        foundKeyUsageExtension = true;
                        Assert.AreEqual(X509KeyUsageFlags.DigitalSignature, keyUsageExtension.KeyUsages);
                        Assert.IsTrue(keyUsageExtension.Critical);
                    }
                    else if (basicConstraintsExtension != null)
                    {
                        foundBasicConstraintExtension = true;
                        Assert.IsFalse(basicConstraintsExtension.CertificateAuthority);
                        Assert.IsTrue(basicConstraintsExtension.HasPathLengthConstraint);
                        Assert.AreEqual(5, basicConstraintsExtension.PathLengthConstraint);
                        Assert.IsFalse(basicConstraintsExtension.Critical);
                    }
                }

                Assert.IsTrue(foundKeyUsageExtension);
                Assert.IsTrue(foundBasicConstraintExtension);

                pfx = cert.Export(X509ContentType.Pfx, "TestPassword");
            }

            X509Certificate2 rtCert = new X509Certificate2(pfx, "TestPassword");

            bool foundRTKeyUsageExtension = false;
            bool foundRTBasicConstraintExtension = false;

            foreach (X509Extension extension in rtCert.Extensions)
            {
                X509KeyUsageExtension keyUsageExtension = extension as X509KeyUsageExtension;
                X509BasicConstraintsExtension basicConstraintsExtension = extension as X509BasicConstraintsExtension;

                if (keyUsageExtension != null)
                {
                    foundRTKeyUsageExtension = true;
                    Assert.AreEqual(X509KeyUsageFlags.DigitalSignature, keyUsageExtension.KeyUsages);
                    Assert.IsTrue(keyUsageExtension.Critical);
                }
                else if (basicConstraintsExtension != null)
                {
                    foundRTBasicConstraintExtension = true;
                    Assert.IsFalse(basicConstraintsExtension.CertificateAuthority);
                    Assert.IsTrue(basicConstraintsExtension.HasPathLengthConstraint);
                    Assert.AreEqual(5, basicConstraintsExtension.PathLengthConstraint);
                    Assert.IsFalse(basicConstraintsExtension.Critical);
                }
            }

            Assert.IsTrue(foundRTKeyUsageExtension);
            Assert.IsTrue(foundRTBasicConstraintExtension);
        }

        [TestMethod]
        public void CreateECDsaCertificate()
        {
            byte[] pfx = null;

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;
            keyCreationParameters.KeyUsage = CngKeyUsages.Signing;
      
            using (CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, keyCreationParameters))
            {
                X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(new X500DistinguishedName("CN=TestECDSACert"));
                creationParams.SignatureAlgorithm = X509CertificateSignatureAlgorithm.ECDsaSha256;

                X509Certificate2 cert = key.CreateSelfSignedCertificate(creationParams);
                pfx = cert.Export(X509ContentType.Pfx, "TestPassword");

                Assert.IsTrue(cert.HasPrivateKey);
                Assert.IsTrue(cert.HasCngKey());
            }

            X509Certificate2 rtCert = new X509Certificate2(pfx, "TestPassword");
            Assert.IsTrue(rtCert.HasPrivateKey);
            Assert.IsTrue(rtCert.HasCngKey());

            using (CngKey rtKey = rtCert.GetCngPrivateKey())
            {
                Assert.AreEqual(CngAlgorithmGroup.ECDsa, rtKey.AlgorithmGroup);
                Assert.AreEqual(256, rtKey.KeySize);
            }
        }

        [TestMethod]
        public void Create2048RsaCertificate()
        {
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;
            keyCreationParameters.KeyCreationOptions = CngKeyCreationOptions.None;
            keyCreationParameters.KeyUsage = CngKeyUsages.AllUsages;
            keyCreationParameters.Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

            int keySize = 2048;
            keyCreationParameters.Parameters.Add(new CngProperty("Length",
                                                                 BitConverter.GetBytes(keySize),
                                                                 CngPropertyOptions.None));
            byte[] pfx = null;
            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa, null, keyCreationParameters))
            {
                X509Certificate2 cert = key.CreateSelfSignedCertificate(new X500DistinguishedName("CN=TestRSAKey"));
                pfx = cert.Export(X509ContentType.Pfx, "TestPassword");

                Assert.IsTrue(cert.HasPrivateKey);
                Assert.IsTrue(cert.HasCngKey());
            }

            X509Certificate2 rtCert = new X509Certificate2(pfx, "TestPassword");
            Assert.IsTrue(rtCert.HasPrivateKey);
            Assert.IsTrue(rtCert.HasCngKey());

            using (CngKey rtKey = rtCert.GetCngPrivateKey())
            {
                Assert.AreEqual(CngAlgorithm2.Rsa, rtKey.Algorithm);
                Assert.AreEqual(2048, rtKey.KeySize);
            }
        }

        [TestMethod]
        public void CreateNamedKeyCertificate()
        {
            string keyName = "NamedKey_" + Guid.NewGuid().ToString();

            try
            {
                CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
                keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;

                X509Certificate2 cert = null;
                byte[] pfx = null;
                using (CngKey namedKey = CngKey.Create(CngAlgorithm2.Rsa, keyName, keyCreationParameters))
                {
                    cert = namedKey.CreateSelfSignedCertificate(new X500DistinguishedName("CN=TestNamedRSAKey"));
                    pfx = cert.Export(X509ContentType.Pfx, "TestPassword");

                    Assert.IsTrue(cert.HasPrivateKey);
                    Assert.IsTrue(cert.HasCngKey());

                    using (CngKey certKey = cert.GetCngPrivateKey())
                    {
                        Assert.AreEqual(CngAlgorithm2.Rsa, certKey.Algorithm);
                    }
                }
                GC.KeepAlive(cert);

                X509Certificate2 rtCert = new X509Certificate2(pfx, "TestPassword");
                Assert.IsTrue(rtCert.HasPrivateKey);
                Assert.IsTrue(rtCert.HasCngKey());

                using (CngKey rtKey = rtCert.GetCngPrivateKey())
                {
                    Assert.AreEqual(CngAlgorithm2.Rsa, rtKey.Algorithm);
                }
            }
            finally
            {
                if (CngKey.Exists(keyName))
                {
                    using (CngKey key = CngKey.Open(keyName))
                    {
                        key.Delete();
                    }
                }
            }
        }
    }
}
