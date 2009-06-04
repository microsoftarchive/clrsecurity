// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Policy;
using Security.Reflection;

namespace Security
{
    /// <summary>
    ///     SandboxFactory can be used to wrap the process of making a simple homogenous AppDomain.
    /// </summary>
    public static class SandboxFactory
    {
        /// <summary>
        ///     Create a homogenous sandboxed AppDomain rooted at the specified AppBase
        /// </summary>
        /// <param name="applicationBase">location where the application to be sandboxed lives</param>
        /// <param name="grantSet">permissions to grant the sandbox</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="applicationBase"/> or <paramref name="grantSet"/> are null
        /// </exception>
        public static AppDomain CreateSandbox(string applicationBase, PermissionSet grantSet)
        {
            return CreateSandbox(applicationBase, grantSet, null);
        }

        /// <summary>
        ///     Create a homogenous AppDomain rooted at the specified AppBase, which has an optional
        ///     collection of full trust assemblies
        /// </summary>
        /// <param name="applicationBase">location where the application to be sandboxed lives</param>
        /// <param name="grantSet">permissions to grant the sandbox</param>
        /// <param name="fullTrustAssemblies">optional list of assemblies to grant full trust in the sandbox</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="applicationBase"/> or <paramref name="grantSet"/> are null
        /// </exception>
        public static AppDomain CreateSandbox(string applicationBase,
                                              PermissionSet grantSet,
                                              params Assembly[] fullTrustAssemblies)
        {
            if (applicationBase == null)
                throw new ArgumentNullException("applicationBase");
            if (grantSet == null)
                throw new ArgumentNullException("grantSet");

            IEnumerable<StrongName> fullTrustStrongNames = null;

            if (fullTrustAssemblies != null)
            {
                fullTrustStrongNames = from assembly in fullTrustAssemblies
                                       select assembly.GetStrongName();
            }
            else
            {
                fullTrustStrongNames = new StrongName[0];
            }

            AppDomainSetup setupInfo = new AppDomainSetup();
            setupInfo.ApplicationBase = applicationBase;

            return AppDomain.CreateDomain("Sandbox", null, setupInfo, grantSet, fullTrustStrongNames.ToArray());
        }
    }
}
