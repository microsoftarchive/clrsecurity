// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security;
using Security.Policy;
using Security.Reflection;

namespace Security.Test
{
    /// <summary>
    ///     Tests for the SandboxFactory type
    /// </summary>
    [TestClass]
    public sealed class SandboxFactoryTests
    {
        /// <summary>
        ///     Test for the simple CreateSandbox overload
        /// </summary>
        [TestMethod]
        public void CreateSandboxSimpleTest()
        {
            PermissionSet sandboxSet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, new Url(Path.GetTempPath()));
            AppDomain sandbox = SandboxFactory.CreateSandbox(Path.GetTempPath(), sandboxSet);

            Assert.IsTrue(sandbox.IsSandboxed());
            Assert.IsTrue(sandbox.GetPermissionSet().IsSubsetOf(sandboxSet));
            Assert.IsTrue(sandboxSet.IsSubsetOf(sandbox.GetPermissionSet()));
            Assert.AreEqual(Path.GetTempPath(), sandbox.BaseDirectory);
        }

        /// <summary>
        ///     Test for creating a sandbox domain with a full trust list
        /// </summary>
        [TestMethod]
        public void CreateSandboxFullTrustListTest()
        {
            PermissionSet sandboxSet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, new Url(Path.GetTempPath()));
            
            // Yes, both mscorlib and System.dll are in the GAC and would therefore be fully trusted anyway,
            // without needing this list.  However, by adding them here we can ensure that the strong names
            // are flowing properly.
            AppDomain sandbox = SandboxFactory.CreateSandbox(Path.GetTempPath(),
                                                             sandboxSet,
                                                             typeof(object).Assembly,
                                                             typeof(System.Diagnostics.Debug).Assembly);

            Assert.IsTrue(sandbox.IsSandboxed());
            Assert.IsTrue(sandbox.GetPermissionSet().IsSubsetOf(sandboxSet));
            Assert.IsTrue(sandboxSet.IsSubsetOf(sandbox.GetPermissionSet()));
            Assert.AreEqual(Path.GetTempPath(), sandbox.BaseDirectory);

            IList<StrongName> fullTrustList = sandbox.ApplicationTrust.GetFullTrustAssemblies();
            Assert.AreEqual(2, fullTrustList.Count);

            Assert.IsTrue(fullTrustList.Contains(typeof(object).Assembly.GetStrongName()));
            Assert.IsTrue(fullTrustList.Contains(typeof(System.Diagnostics.Debug).Assembly.GetStrongName()));
        }

        /// <summary>
        ///     Ensure the expected exception is thrown for a null AppBase
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateSandboxNullAppBaseTest()
        {
            SandboxFactory.CreateSandbox(null, PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet));
        }

        /// <summary>
        ///     Ensure the expected exception is thrown for a null grant set
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateSandboxNullGrantTest()
        {
            SandboxFactory.CreateSandbox(Path.GetTempPath(), null);
        }
    }
}
