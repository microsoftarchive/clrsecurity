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

            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa))
            {
                preCreationTime = DateTime.UtcNow;
                X509Certificate2 cert = key.CreateSelfSignedCertificate(new X500DistinguishedName("CN=TestCert"));
                postCreationTime = DateTime.UtcNow;

                Assert.AreEqual("TestCert", cert.GetNameInfo(X509NameType.SimpleName, true));
                Assert.AreEqual("TestCert", cert.GetNameInfo(X509NameType.SimpleName, false));

                Assert.IsTrue(cert.NotBefore.Date.Equals(preCreationTime.Date) ||
                              cert.NotBefore.Date.Equals(postCreationTime.Date));
                Assert.IsTrue(cert.NotAfter.Date.Equals(preCreationTime.Date.AddYears(1)) ||
                              cert.NotAfter.Date.Equals(postCreationTime.Date.AddYears(1)));

                // Try to round trip through PFX
                pfx = cert.Export(X509ContentType.Pfx, "TestPassword");
            }

            // Make sure we can read back the PFX file even after the original key is gone
            X509Certificate2 rtCert = new X509Certificate2(pfx, "TestPassword");
            Assert.AreEqual("TestCert", rtCert.GetNameInfo(X509NameType.SimpleName, true));
            Assert.AreEqual("TestCert", rtCert.GetNameInfo(X509NameType.SimpleName, false));

            Assert.IsTrue(rtCert.NotBefore.Date.Equals(preCreationTime.Date) ||
                          rtCert.NotBefore.Date.Equals(postCreationTime.Date));
            Assert.IsTrue(rtCert.NotAfter.Date.Equals(preCreationTime.Date.AddYears(1)) ||
                          rtCert.NotAfter.Date.Equals(postCreationTime.Date.AddYears(1)));
        }

        /// <summary>
        ///     Test to ensure we can create a certificate with multiple extensions in it
        /// </summary>
        [TestMethod]
        public void CreateCertificateWithExtensions()
        {
            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(new X500DistinguishedName("CN=TestCertWithExtensions"));
            creationParams.SignatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha512;

            creationParams.Extensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            creationParams.Extensions.Add(new X509BasicConstraintsExtension(false, true, 5, false));

            using (CngKey key = CngKey.Create(CngAlgorithm2.Rsa))
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
            }
        }
    }
}
