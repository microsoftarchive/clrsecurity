// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Policy;
using Security.Reflection;
using Security.Test;

namespace Security.Policy.Test
{
    /// <summary>
    ///     Tests for the ApplicationTrust extension methods
    /// </summary>
    [TestClass]
    public sealed class ApplicationTrustTests
    {
        private const string s_ecmaPublicKey = "00000000000000000400000000000000";
        private const string s_microsoftPublicKey = "002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293";

        /// <summary>
        ///     Tests for retrieving the full trust list from an ApplicationTrust object
        /// </summary>
        [TestMethod]
        public void GetFullTrustAssembliesListTest()
        {
            // We can only set a full trust list via the AppDomain creation code path
            AppDomainSetup ads = new AppDomainSetup();
            ads.ApplicationBase = AppDomain.CurrentDomain.BaseDirectory;

            PermissionSet sandbox = new PermissionSet(PermissionState.None);
            sandbox.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));

            StrongName[] fullTrustList = new StrongName[]
            {
                typeof(object).Assembly.GetStrongName(),
                typeof(System.Security.Cryptography.AesManaged).Assembly.GetStrongName(),
                typeof(System.Security.Cryptography.Xml.SignedXml).Assembly.GetStrongName()
            };

            AppDomain domain = AppDomainFactory.CreateHomogenousDomain(sandbox, fullTrustList);

            ApplicationTrust domainTrust = domain.ApplicationTrust;
            IList<StrongName> trustedAssemblies = domainTrust.GetFullTrustAssemblies();

            Assert.AreEqual(3, trustedAssemblies.Count);

            bool foundMscorlib = false;
            bool foundSystemCore = false;
            bool foundSystemSecurity = false;

            foreach (StrongName sn in trustedAssemblies)
            {
                if (String.Equals("mscorlib", sn.Name, StringComparison.OrdinalIgnoreCase) &&
                    String.Equals(s_ecmaPublicKey, sn.PublicKey.ToString(), StringComparison.OrdinalIgnoreCase) &&
                    sn.Version.Major >= 2)
                {
                    foundMscorlib = true;
                }
                else if (String.Equals("System.Core", sn.Name, StringComparison.OrdinalIgnoreCase) &&
                         String.Equals(s_ecmaPublicKey, sn.PublicKey.ToString(), StringComparison.OrdinalIgnoreCase) &&
                         sn.Version.Major >= 3)
                {
                    foundSystemCore = true;
                }
                else if (String.Equals("System.Security", sn.Name, StringComparison.OrdinalIgnoreCase) &&
                         String.Equals(s_microsoftPublicKey, sn.PublicKey.ToString(), StringComparison.OrdinalIgnoreCase) &&
                         sn.Version.Major >= 2)
                {
                    foundSystemSecurity = true;
                }
            }

            Assert.IsTrue(foundMscorlib);
            Assert.IsTrue(foundSystemCore);
            Assert.IsTrue(foundSystemSecurity);
        }
    }
}
