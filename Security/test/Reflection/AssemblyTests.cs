// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Reflection;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Reflection;

namespace Security.Reflection.Test
{
    /// <summary>
    ///     Tests for the extension methods to the Assembly class
    /// </summary>
    [TestClass]
    public sealed class AssemblyTests
    {
        private const string s_ecmaPublicKey = "00000000000000000400000000000000";
        private const string s_microsoftPublicKey = "002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293";

        /// <summary>
        ///     Tests for the IsStrongNamed extension method
        /// </summary>
        [TestMethod]
        public void IsStrongNamedTest()
        {
            Assert.IsTrue(typeof(object).Assembly.IsStrongNamed());
            Assert.IsTrue(typeof(System.Security.Cryptography.AesManaged).Assembly.IsStrongNamed());
            Assert.IsFalse(typeof(AssemblyTests).Assembly.IsStrongNamed());
        }

        [TestMethod]
        public void GetStrongNamePositiveTest()
        {
            StrongName mscorlibSn = typeof(object).Assembly.GetStrongName();
            Assert.IsTrue(String.Equals(s_ecmaPublicKey, mscorlibSn.PublicKey.ToString(), StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(String.Equals("mscorlib", mscorlibSn.Name, StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(mscorlibSn.Version.Major >= 2);

            StrongName systemCoreSn = typeof(System.Security.Cryptography.AesManaged).Assembly.GetStrongName();
            Assert.IsTrue(String.Equals(s_ecmaPublicKey, systemCoreSn.PublicKey.ToString(), StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(String.Equals("System.Core", systemCoreSn.Name, StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(systemCoreSn.Version.Major >= 3);

            StrongName systemSecuritySn = typeof(System.Security.Cryptography.Xml.SignedXml).Assembly.GetStrongName();
            Assert.IsTrue(String.Equals(s_microsoftPublicKey, systemSecuritySn.PublicKey.ToString(), StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(String.Equals("System.Security", systemSecuritySn.Name, StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(systemSecuritySn.Version.Major >= 2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GetStrongNameNegativeTest()
        {
            typeof(AssemblyTests).Assembly.GetStrongName();
        }
    }
}
