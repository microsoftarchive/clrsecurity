// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;

namespace Security
{
    /// <summary>
    ///     Extension methods for the AppDomain class
    /// </summary>
    public static class AppDomainExtensionMethods
    {
        /// <summary>
        ///     Get the permissions that an AppDomain is granted
        /// </summary>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        [PermissionSet(SecurityAction.Assert, Unrestricted = true)]
        public static PermissionSet GetPermissionSet(this AppDomain appDomain)
        {
            // If we're in a homogenous domain, then the grant set is simply the ApplicationTrust's default
            // grant set
            if (appDomain.IsHomogenous())
            {
                return appDomain.ApplicationTrust.DefaultGrantSet.PermissionSet.Copy();
            }
            // If there is a domain manager, it gets to determine the grant set of the domain
            else if (appDomain.DomainManager != null &&
                     appDomain.DomainManager.HostSecurityManager != null &&
                     (AppDomain.CurrentDomain.DomainManager.HostSecurityManager.Flags & HostSecurityManagerOptions.HostResolvePolicy) == HostSecurityManagerOptions.HostResolvePolicy)
            {
                return appDomain.DomainManager.HostSecurityManager.ResolvePolicy(appDomain.Evidence).Copy();
            }
            // If the domain has evidence, then the grant set is determined by resolving that evidence
            else if (appDomain.Evidence != null)
            {
                return SecurityManager.ResolveSystemPolicy(appDomain.Evidence);
            }
            // Otherwise we're not in a sandbox, so the domain grant set is full trust
            else
            {
                return new PermissionSet(PermissionState.Unrestricted);
            }
        }

        /// <summary>
        ///     Determine if an AppDomain is a simple sandbox domain
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Information about the speciifc trusted assemblies and default grant set is not exposed")]
        public static bool IsHomogenous(this AppDomain appDomain)
        {
            return appDomain.ApplicationTrust != null;
        }

        /// <summary>
        ///     Determine if an AppDomain is sandboxed
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Information about the specific partial trust grant set is not leaked")]
        public static bool IsSandboxed(this AppDomain appDomain)
        {
            return !GetPermissionSet(appDomain).IsUnrestricted();
        }
    }
}
