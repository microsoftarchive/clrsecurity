// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the Oid2 class
    /// </summary>
    [TestClass]
    public class Oid2Tests
    {
        /// <summary>
        ///     Basic construction tests
        /// </summary>
        [TestMethod]
        public void Oid2ConstructionTest()
        {
            // OIDs created with the value/name .ctor should only have a friendly name and value, no specific
            // group, and no algorithm 
            Oid2 oid = new Oid2("2.16.840.1.101.3.4.2.1", "sha256");
            Assert.AreEqual("2.16.840.1.101.3.4.2.1", oid.Value);
            Assert.AreEqual("sha256", oid.FriendlyName);
            Assert.AreEqual(OidGroup.AllGroups, oid.Group);
            Assert.IsFalse(oid.HasAlgorithmId);
            Assert.IsNull(oid.CngAlgorithm);
            Assert.IsNull(oid.CngExtraAlgorithm);

            // OIDs created with the value/name/group .ctor should only have a friendly name, value and group,
            // but no associated algorithms.
            oid = new Oid2("2.16.840.1.101.3.4.2.1", "sha256", OidGroup.HashAlgorithm);
            Assert.AreEqual("2.16.840.1.101.3.4.2.1", oid.Value);
            Assert.AreEqual("sha256", oid.FriendlyName);
            Assert.AreEqual(OidGroup.HashAlgorithm, oid.Group);
            Assert.IsFalse(oid.HasAlgorithmId);
            Assert.IsNull(oid.CngAlgorithm);
            Assert.IsNull(oid.CngExtraAlgorithm);

            // OIDs created with the CNG algorithm constructor should have all properties but CAPI algorithm set
            oid = new Oid2("2.16.840.1.101.3.4.2.1", "sha256", OidGroup.HashAlgorithm, CngAlgorithm.Sha256, CngAlgorithm.Sha512);
            Assert.AreEqual("2.16.840.1.101.3.4.2.1", oid.Value);
            Assert.AreEqual("sha256", oid.FriendlyName);
            Assert.AreEqual(OidGroup.HashAlgorithm, oid.Group);
            Assert.IsFalse(oid.HasAlgorithmId);
            Assert.AreEqual(CngAlgorithm.Sha256, oid.CngAlgorithm);
            Assert.AreEqual(CngAlgorithm.Sha512, oid.CngExtraAlgorithm);

            // OIDs created with the full constructor have all properties set
            oid = new Oid2("2.16.840.1.101.3.4.2.1", "sha256", OidGroup.HashAlgorithm, 0x800c, CngAlgorithm.Sha256, CngAlgorithm.Sha512);
            Assert.AreEqual("2.16.840.1.101.3.4.2.1", oid.Value);
            Assert.AreEqual("sha256", oid.FriendlyName);
            Assert.AreEqual(OidGroup.HashAlgorithm, oid.Group);
            Assert.IsTrue(oid.HasAlgorithmId);
            Assert.AreEqual(0x800c, oid.AlgorithmId);
            Assert.AreEqual(CngAlgorithm.Sha256, oid.CngAlgorithm);
            Assert.AreEqual(CngAlgorithm.Sha512, oid.CngExtraAlgorithm);
        }

        /// <summary>
        ///     Test to ensure we can't construct an OID with a null name
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Oid2ConstructNullFriendlyNameTest()
        {
            new Oid2("2.16.840.1.101.3.4.2.1", null);
        }

        /// <summary>
        ///     Test to ensure we can't construct an OID with a null value
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Oid2ConstructNullValueTest()
        {
            new Oid2(null, "sha256");
        }

        /// <summary>
        ///     Test to ensure we correctly enumerate OID groups.
        /// </summary>
        [TestMethod]
        public void Oid2EnumerateOidGroupTest()
        {
            // More specific testing here is difficult since the OIDs registered on each machine can and
            // will be different, so we won't check for specific OIDs but just that all returned OIDs are in
            // the group that we asked for.

            foreach (Oid2 oid in Oid2.EnumerateOidInformation(OidGroup.HashAlgorithm))
            {
                Assert.AreEqual(OidGroup.HashAlgorithm, oid.Group);
            }

            foreach (Oid2 oid in Oid2.EnumerateOidInformation(OidGroup.EncryptionAlgorithm))
            {
                Assert.AreEqual(OidGroup.EncryptionAlgorithm, oid.Group);
            }
        }

        /// <summary>
        ///     Test to ensure that we correctly find OIDs by friendly name
        /// </summary>
        [TestMethod]
        public void Oid2FindByFriendlyNameTest()
        {
            // First lookup using all groups
            Oid2 sha1 = Oid2.FindByFriendlyName("sha1");
            Assert.AreEqual("sha1", sha1.FriendlyName);
            Assert.AreEqual("1.3.14.3.2.26", sha1.Value);
            Assert.AreEqual(OidGroup.HashAlgorithm, sha1.Group);
            if (Environment.OSVersion.Version.Major >= 6)
            {
                Assert.AreEqual(CngAlgorithm.Sha1, sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }
            else
            {
                Assert.IsNull(sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }

            // Make sure it also works for search within a specific group
            sha1 = Oid2.FindByFriendlyName("sha1", OidGroup.HashAlgorithm);
            Assert.AreEqual("sha1", sha1.FriendlyName);
            Assert.AreEqual("1.3.14.3.2.26", sha1.Value);
            Assert.AreEqual(OidGroup.HashAlgorithm, sha1.Group);
            if (Environment.OSVersion.Version.Major >= 6)
            {
                Assert.AreEqual(CngAlgorithm.Sha1, sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }
            else
            {
                Assert.IsNull(sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }
        }

        /// <summary>
        ///     Test to ensure that we correctly find OIDs by value
        /// </summary>
        [TestMethod]
        public void Oid2FindByValueTest()
        {
            // First lookup using all groups
            Oid2 sha1 = Oid2.FindByValue("1.3.14.3.2.26");
            Assert.AreEqual("sha1", sha1.FriendlyName);
            Assert.AreEqual("1.3.14.3.2.26", sha1.Value);
            Assert.AreEqual(OidGroup.HashAlgorithm, sha1.Group);
            if (Environment.OSVersion.Version.Major >= 6)
            {
                Assert.AreEqual(CngAlgorithm.Sha1, sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }
            else
            {
                Assert.IsNull(sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }

            // Make sure it also works for search within a specific group
            sha1 = Oid2.FindByValue("1.3.14.3.2.26", OidGroup.HashAlgorithm);
            Assert.AreEqual("sha1", sha1.FriendlyName);
            Assert.AreEqual("1.3.14.3.2.26", sha1.Value);
            Assert.AreEqual(OidGroup.HashAlgorithm, sha1.Group);
            if (Environment.OSVersion.Version.Major >= 6)
            {
                Assert.AreEqual(CngAlgorithm.Sha1, sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }
            else
            {
                Assert.IsNull(sha1.CngAlgorithm);
                Assert.IsNull(sha1.CngExtraAlgorithm);
            }
        }

        /// <summary>
        ///     Test to ensure Oid2 objects correctly convert to Oid objects
        /// </summary>
        [TestMethod]
        public void Oid2ToOidTest()
        {
            Oid2 oid2  = new Oid2("2.16.840.1.101.3.4.2.1", "sha256", OidGroup.HashAlgorithm, 0x800c, CngAlgorithm.Sha256, CngAlgorithm.Sha512);
            Oid oid = oid2.ToOid();
            Assert.AreEqual(oid2.Value, oid.Value);
            Assert.AreEqual(oid2.FriendlyName, oid.FriendlyName);
        }
    }
}
