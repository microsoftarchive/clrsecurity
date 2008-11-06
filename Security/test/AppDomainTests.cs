// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security;

namespace Security.Test
{
    /// <summary>
    ///     Tests for the AppDomain extension methods
    /// </summary>
    [TestClass]
    public sealed class AppDomainTests
    {
        [TestMethod]
        public void GetGrantSetTest()
        {
            AppDomain homogenousTrusted = AppDomainFactory.CreateHomogenousDomain(new PermissionSet(PermissionState.Unrestricted));
            Assert.IsTrue(homogenousTrusted.GetPermissionSet().IsUnrestricted());

            PermissionSet execution = new PermissionSet(PermissionState.None);
            execution.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));
            AppDomain homogenousPartialTrust = AppDomainFactory.CreateHomogenousDomain(execution);

            PermissionSet homogenousPartialTrustGrant = homogenousPartialTrust.GetPermissionSet();
            Assert.IsTrue(homogenousPartialTrustGrant.IsSubsetOf(execution) &&
                          execution.IsSubsetOf(homogenousPartialTrustGrant));

            Evidence myComputer = new Evidence(new object[] { new Zone(SecurityZone.MyComputer) }, new object[] { });
            AppDomain legacyTrusted = AppDomainFactory.CreateLegacySandbox(myComputer);
            Assert.IsTrue(legacyTrusted.GetPermissionSet().IsUnrestricted());

            Evidence internet = new Evidence(new object[] { new Zone(SecurityZone.Internet) }, new object[] { });
            AppDomain legacyPartialTrust = AppDomainFactory.CreateLegacySandbox(internet);

            PermissionSet legacyPartialTrustGrant = legacyPartialTrust.GetPermissionSet();
            PermissionSet internetGrant = SecurityManager.ResolveSystemPolicy(internet);
            Assert.IsTrue(legacyPartialTrustGrant.IsSubsetOf(internetGrant) &&
                          internetGrant.IsSubsetOf(legacyPartialTrustGrant));
        }

        /// <summary>
        ///     Tests for the IsHomogenous extension method
        /// </summary>
        [TestMethod]
        public void IsHomogenousTest()
        {
            Assert.IsTrue(AppDomainFactory.CreateHomogenousDomain(new PermissionSet(PermissionState.Unrestricted)).IsHomogenous());
            Assert.IsFalse(AppDomainFactory.CreateLegacySandbox(AppDomain.CurrentDomain.Evidence).IsHomogenous());
        }

        /// <summary>
        ///     Tests for the IsSandbox extension method
        /// </summary>
        [TestMethod]
        public void IsSandboxedTest()
        {
            Assert.IsFalse(AppDomainFactory.CreateHomogenousDomain(new PermissionSet(PermissionState.Unrestricted)).IsSandboxed());

            PermissionSet execution = new PermissionSet(PermissionState.None);
            execution.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));
            Assert.IsTrue(AppDomainFactory.CreateHomogenousDomain(execution).IsSandboxed());

            Evidence myComputer = new Evidence(new object[] { new Zone(SecurityZone.MyComputer) }, new object[] { });
            Assert.IsFalse(AppDomainFactory.CreateLegacySandbox(myComputer).IsSandboxed());

            Evidence internet = new Evidence(new object[] { new Zone(SecurityZone.Internet) }, new object[] { });
            Assert.IsTrue(AppDomainFactory.CreateLegacySandbox(internet).IsSandboxed());
        }
    }
}
