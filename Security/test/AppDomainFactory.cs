// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using System.Threading;

namespace Security.Test
{
    /// <summary>
    ///     Utility class to quickly create test AppDomains
    /// </summary>
    internal static class AppDomainFactory
    {
        private static int s_domainCounter = 0;

        /// <summary>
        ///     Utility method to create a homogenous AppDomain
        /// </summary>
        internal static AppDomain CreateHomogenousDomain(PermissionSet grantSet)
        {
            return CreateHomogenousDomain(grantSet, new StrongName[0]);
        }

        /// <summary>
        ///     Utility method to create a homogenous AppDomain
        /// </summary>
        internal static AppDomain CreateHomogenousDomain(PermissionSet grantSet, StrongName[] fullTrustList)
        {
            int domainId = Interlocked.Increment(ref s_domainCounter);

            AppDomainSetup ads = new AppDomainSetup();
            ads.ApplicationBase = AppDomain.CurrentDomain.BaseDirectory;

            return AppDomain.CreateDomain("Homogenous Domain " + domainId,
                                          AppDomain.CurrentDomain.Evidence,
                                          ads,
                                          grantSet,
                                          fullTrustList);
        }

        /// <summary>
        ///     Utility method to create a legacy sandboxed domain
        /// </summary>
        internal static AppDomain CreateLegacySandbox(Evidence evidence)
        {
            int domainId = Interlocked.Increment(ref s_domainCounter);
            return AppDomain.CreateDomain("Legacy Sandbox " + domainId, evidence);
        }
    }
}
