// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography.X509Certificates;

namespace Microsoft.Security.Cryptography.X509Certificates.Test
{
    /// <summary>
    ///     Tests for the X509CertificateCreationParameters class
    /// </summary>
    [TestClass]
    public sealed class X509CertificateCreationParametersTests
    {
        /// <summary>
        ///     Ensure all the properties are set to their correct defaults
        /// </summary>
        [TestMethod]
        public void X509CertificateCreationParametersDefaultPropertiesTest()
        {
            X500DistinguishedName dn = new X500DistinguishedName("CN=Test");

            DateTime preCreationTime = DateTime.UtcNow;
            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(dn);
            DateTime postCreationTime = DateTime.UtcNow;

            Assert.AreEqual(dn.Name, creationParams.SubjectName.Name);
            Assert.AreEqual(X509CertificateCreationOptions.None, creationParams.CertificateCreationOptions);
            Assert.AreEqual(X509CertificateSignatureAlgorithm.RsaSha1, creationParams.SignatureAlgorithm);

            // The cert should be valid for 1 year (allowing for leap years, so 366 days could be valid as well)
            int validDays = (creationParams.EndTime - creationParams.StartTime).Days;
            Assert.IsTrue(validDays == 365 || validDays == 366);

            // In theory we could have rolled over a day while since the parameters were created, so we'll
            // accept either the date before or after the parameters were created
            Assert.IsTrue(creationParams.StartTime.Day == preCreationTime.Day ||
                          creationParams.StartTime.Day == postCreationTime.Day);
            Assert.IsTrue(creationParams.StartTime.Month == preCreationTime.Month ||
                          creationParams.StartTime.Month == postCreationTime.Month);
            Assert.IsTrue(creationParams.StartTime.Year == preCreationTime.Year ||
                          creationParams.StartTime.Year == postCreationTime.Year);

            Assert.AreEqual(0, creationParams.Extensions.Count);

            Assert.IsTrue(creationParams.TakeOwnershipOfKey);
        }

        /// <summary>
        ///     Ensure that modifying the default properties works as expected
        /// </summary>
        [TestMethod]
        public void X509CertificateCreationParametersPropertiesTest()
        {
            X500DistinguishedName dn = new X500DistinguishedName("CN=Test");
            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(dn);

            creationParams.SubjectName = new X500DistinguishedName("CN=Test2");
            Assert.AreEqual(new X500DistinguishedName("CN=Test2").Name, creationParams.SubjectName.Name);

            creationParams.CertificateCreationOptions = X509CertificateCreationOptions.DoNotLinkKeyInformation |
                                                        X509CertificateCreationOptions.DoNotSignCertificate;
            Assert.AreEqual(X509CertificateCreationOptions.DoNotLinkKeyInformation | X509CertificateCreationOptions.DoNotSignCertificate,
                            creationParams.CertificateCreationOptions);

            DateTime newStart = new DateTime(2006, 08, 12);
            creationParams.StartTime = newStart;
            Assert.AreEqual(newStart, creationParams.StartTime);

            DateTime newEnd = new DateTime(2008, 09, 15);
            creationParams.EndTime = newEnd;
            Assert.AreEqual(newEnd, creationParams.EndTime);

            creationParams.SignatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha256;
            Assert.AreEqual(X509CertificateSignatureAlgorithm.RsaSha256, creationParams.SignatureAlgorithm);

            X509KeyUsageExtension keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyAgreement, true);
            creationParams.Extensions.Add(keyUsage);

            Assert.AreEqual(1, creationParams.Extensions.Count);
            Assert.IsInstanceOfType(creationParams.Extensions[0], typeof(X509KeyUsageExtension));
            Assert.AreEqual(X509KeyUsageFlags.KeyAgreement,
                            ((X509KeyUsageExtension)creationParams.Extensions[0]).KeyUsages);
        }

        /// <summary>
        ///     Ensures that setting an incorrect algorithm results in the correct exception
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void X509CertificateCreationParametersSetBadAlgorithmTest1()
        {
            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(new X500DistinguishedName("CN="));
            creationParams.SignatureAlgorithm = (X509CertificateSignatureAlgorithm)(-1);
        }

        /// <summary>
        ///     Ensures that setting an incorrect algorithm results in the correct exception
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void X509CertificateCreationParametersSetBadAlgorithmTest2()
        {
            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(new X500DistinguishedName("CN="));
            creationParams.SignatureAlgorithm = (X509CertificateSignatureAlgorithm)((int)X509CertificateSignatureAlgorithm.ECDsaSha512 + 1);
        }

        /// <summary>
        ///     Ensures that setting a null name results in the correct exception
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void X509CertificateCreationParametersCreateNullNameTest()
        {
            new X509CertificateCreationParameters(null);
        }

        /// <summary>
        ///     Ensures that setting a null name results in the correct exception
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void X509CertificateCreationParametersSetNullNameTest()
        {
            X500DistinguishedName name = new X500DistinguishedName("CN=");
            X509CertificateCreationParameters creationParams = new X509CertificateCreationParameters(name);
            creationParams.SubjectName = null;
        }
    }
}
