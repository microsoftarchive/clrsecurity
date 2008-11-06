// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Reflection.Emit;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Security.Properties;
using Security.Policy;

namespace Security.Reflection
{
    /// <summary>
    ///     Extension methods for the Assembly class
    /// </summary>
    public static class AssemblyExtensionMethods
    {
        /// <summary>
        ///     Get the permission set granted to the assembly
        /// </summary>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        [PermissionSet(SecurityAction.Assert, Unrestricted = true)]
        public static PermissionSet GetPermissionSet(this Assembly assembly)
        {
            // GAC assemblies are always fully trusted
            if (assembly.GlobalAssemblyCache)
            {
                return new PermissionSet(PermissionState.Unrestricted);
            }
            // If there is a HostSecurityManager it gets to determine the grant set of the assembly before
            // considering any AppDomain state
            else if (AppDomain.CurrentDomain.DomainManager != null &&
                     AppDomain.CurrentDomain.DomainManager.HostSecurityManager != null &&
                     (AppDomain.CurrentDomain.DomainManager.HostSecurityManager.Flags & HostSecurityManagerOptions.HostResolvePolicy) == HostSecurityManagerOptions.HostResolvePolicy)
            {
                return AppDomain.CurrentDomain.DomainManager.HostSecurityManager.ResolvePolicy(assembly.Evidence).Copy();
            }
            // If we're in a homogenous domain then this assembly is either granted the sandbox grant set or
            // full trust if it is on the trusted assemblies list.
            else if (AppDomain.CurrentDomain.IsHomogenous())
            {
                Evidence assemblyEvidence = assembly.Evidence;

                // Check to see if the assembly matches an entry on the strong name list
                foreach (StrongName fullTrustAssembly in AppDomain.CurrentDomain.ApplicationTrust.GetFullTrustAssemblies())
                {
                    StrongNameMembershipCondition mc = fullTrustAssembly.CreateMembershipCondition();
                    if (mc.Check(assemblyEvidence))
                    {
                        return new PermissionSet(PermissionState.Unrestricted);
                    }
                }

                // If there was no match on the strong name list, then the assembly is granted the sandbox
                // permission set.
                return AppDomain.CurrentDomain.ApplicationTrust.DefaultGrantSet.PermissionSet.Copy();
            }
            // Otherwise the grant set is simply obtained by resoilving policy on the assembly
            else
            {
                return SecurityManager.ResolvePolicy(assembly.Evidence);
            }
        }

        /// <summary>
        ///     Get an assembly's strong name
        /// </summary>
        public static StrongName GetStrongName(this Assembly assembly)
        {
            if (!assembly.IsStrongNamed())
                throw new ArgumentException(Resources.AssemblyNotStrongNamed, "assembly");

            AssemblyName assemblyName = assembly.GetName();
            StrongNamePublicKeyBlob strongNameKeyBlob = new StrongNamePublicKeyBlob(assemblyName.GetPublicKey());
            return new StrongName(strongNameKeyBlob, assemblyName.Name, assemblyName.Version);
        }

        /// <summary>
        ///     Determine if an assembly is granted full trust in the current domain
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Does not leak out information about the exact grant set")]
        public static bool IsFullyTrusted(this Assembly assembly)
        {
            return assembly.GetPermissionSet().IsUnrestricted();
        }

        /// <summary>
        ///     Determine if an assembly is strong name signed
        /// </summary>
        public static bool IsStrongNamed(this Assembly assembly)
        {
            AssemblyName assemblyName = assembly.GetName();
            byte[] publicKey = assemblyName.GetPublicKey();

            return publicKey != null && publicKey.Length > 0;
        }
    }
}
