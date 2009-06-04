// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
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
    ///     Tests for the SandboxActivator type
    /// </summary>
    [TestClass]
    public sealed class SandboxActivatorTests
    {
        /// <summary>
        ///     Test to ensure that basic sandboxing works
        /// </summary>
        [TestMethod]
        public void CreateSandboxedInstanceDefaultTest()
        {
            RemoteDomainObject object1 = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>();

            // Ensure we got Execution permission
            Assert.IsTrue(object1.Demand(PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Execution)));
            Assert.IsFalse(object1.Demand(PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet)));

            // Ensure that we reuse the same domain for multiple objects
            RemoteDomainObject object2 = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>();
            Assert.AreEqual(object1.AppDomainId, object2.AppDomainId);
        }

        /// <summary>
        ///     Test to ensure that creating instances in an Internet sandbox works as expected
        /// </summary>
        [TestMethod]
        public void CreateSandboxedInstanceInternetTest()
        {
            PermissionSet internet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet);
            RemoteDomainObject object1 = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet);

            // Ensure we got Internet permissions
            Assert.IsTrue(object1.Demand(internet));
            Assert.IsFalse(object1.Demand(PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet)));

            // Ensure we reuse the same domain for multiple objects
            RemoteDomainObject object2 = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet);
            Assert.AreEqual(object1.AppDomainId, object2.AppDomainId);
        }

        /// <summary>
        ///     Test to ensure that creating sandboxed instances with full trust lists works as expected
        /// </summary>
        [TestMethod]
        public void CreateSandboxedInstanceWithFullTrustListTest()
        {
            PermissionSet internet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet);

            RemoteDomainObject fullTrustListInternet =
                SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet, new Assembly[] { typeof(object).Assembly, typeof(System.Diagnostics.Debug).Assembly });

            // Ensure we got Internet permissions
            Assert.IsTrue(fullTrustListInternet.Demand(internet));
            Assert.IsFalse(fullTrustListInternet.Demand(PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet)));

            // We should share with other objects having the same full trust list
            RemoteDomainObject fullTrustListInternet2 =
                SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet, new Assembly[] { typeof(object).Assembly, typeof(System.Diagnostics.Debug).Assembly });
            Assert.AreEqual(fullTrustListInternet.AppDomainId, fullTrustListInternet2.AppDomainId);

            // We shouldn't share with a non-full-trust-list bearing Internet object
            RemoteDomainObject noFullTrustListInternet =
                SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet, null);
            Assert.AreNotEqual(fullTrustListInternet.AppDomainId, noFullTrustListInternet.AppDomainId);

            // Nor should we share with assemblies with a different full trust list
            RemoteDomainObject differentFullTrustListInternet =
                SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet, new Assembly[] { typeof(object).Assembly });
            Assert.AreNotEqual(fullTrustListInternet.AppDomainId, differentFullTrustListInternet.AppDomainId);
        }

        /// <summary>
        ///     Test to ensure that assemblies with different sandbox sets go into different domains
        /// </summary>
        [TestMethod]
        public void CreateSandboxedInstanceMultipleSandboxesTest()
        {
            PermissionSet execution = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Execution);
            RemoteDomainObject executionObject = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(execution);
            Assert.IsTrue(executionObject.Demand(execution));
            Assert.IsFalse(executionObject.Demand(new PermissionSet(PermissionState.Unrestricted)));

            PermissionSet internet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet);
            RemoteDomainObject internetObject = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(internet);
            Assert.IsTrue(internetObject.Demand(internet));
            Assert.IsFalse(internetObject.Demand(new PermissionSet(PermissionState.Unrestricted)));

            PermissionSet intranet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet);
            RemoteDomainObject intranetObject = SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(intranet);
            Assert.IsTrue(intranetObject.Demand(intranet));
            Assert.IsFalse(intranetObject.Demand(new PermissionSet(PermissionState.Unrestricted)));

            Assert.AreNotEqual(executionObject.AppDomainId, internetObject.AppDomainId);
            Assert.AreNotEqual(executionObject.AppDomainId, intranetObject.AppDomainId);
            Assert.AreNotEqual(internetObject.AppDomainId, intranetObject.AppDomainId);
        }

        /// <summary>
        ///     Test to ensure that CreateSandboxedInstance requires a grant set
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateSandboxedInstanceNullGrantSetTest()
        {
            SandboxActivator.CreateSandboxedInstance<RemoteDomainObject>(null);
        }
    }

    /// <summary>
    ///     Helper class to activate in the sandboxed domains
    /// </summary>
    internal sealed class RemoteDomainObject : MarshalByRefObject
    {
        internal int AppDomainId
        {
            get { return AppDomain.CurrentDomain.Id; }
        }

        internal bool Demand(PermissionSet pset)
        {
            return DemandInternal(pset);
        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        private bool DemandInternal(PermissionSet pset)
        {
            try
            {
                pset.Demand();
                return true;
            }
            catch (SecurityException)
            {
                return false;
            }
        }
    }
}
