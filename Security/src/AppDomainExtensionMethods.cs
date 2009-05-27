// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;

namespace Security
{
    /// <summary>
    ///     AppDomainExtensionMethods provides several extension methods for the <see cref="AppDomain"/> class.
    ///     This type is in the Security namespace (not the System namespace), so in order to use these
    ///     extension methods, you will need to make sure you include this namespace as well as a reference to
    ///     Security.dll.
    /// </summary>
    public static class AppDomainExtensionMethods
    {
        /// <summary>
        ///     Get the permission set that the current AppDomain is sandboxed with. This is the permission
        ///     set which is used if a security demand crosses the AppDomain boundary. 
        /// </summary>
        /// <permission cref="PermissionSet">This method requries its immediate caller to be fully trusted</permission>
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
        ///     Detect if an AppDomain is a simple sandbox style domain, created by passing a PermissionSet to
        ///     the <see cref="AppDomain.CreateDomain(string, Evidence, AppDomainSetup, PermissionSet, StrongName[])"/>
        ///     call.
        /// </summary>
        /// <returns>
        ///     True if the domain is a simple sandbox; false if it is a legacy v1.x domain.
        /// </returns>
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
        /// <returns>
        ///     True if the AppDomain has a grant set other than FullTrust
        /// </returns>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Information about the specific partial trust grant set is not leaked")]
        public static bool IsSandboxed(this AppDomain appDomain)
        {
            return !GetPermissionSet(appDomain).IsUnrestricted();
        }
    }
}
