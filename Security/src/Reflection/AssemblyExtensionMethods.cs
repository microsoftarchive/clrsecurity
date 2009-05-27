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
    ///     AssemblyExtensionMethods provides several extension methods for the <see cref="Assembly" /> class.
    ///     This type is in the Security.Reflection namespace (not the System.Reflection namespace), so in
    ///     order to use these extension methods, you will need to make sure you include this namespace as
    ///     well as a reference to Security.dll.
    /// </summary>
    public static class AssemblyExtensionMethods
    {
        /// <summary>
        ///     The GetPermissionSet method returns the permission set that an assembly is granted. This
        ///     method works for assemblies loaded via implicit loads, or explicit calls to <see
        ///     cref="Assembly.Load(string)" /> or <see cref="Assembly.LoadFrom(string)" />. Results may not be
        ///     accurate for assemblies loaded via <see cref="Assembly.Load(byte[])" />, or dynamic assemblies
        ///     created with <see cref="AppDomain.DefineDynamicAssembly(AssemblyName, AssemblyBuilderAccess)" />.
        /// </summary>
        /// <permission cref="PermissionSet">This method requries its immediate caller to be fully trusted</permission>
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
        ///     Get an assembly's strong name.
        /// </summary>
        /// <remarks>
        ///     The <see cref="StrongName" /> object returned may be different from the strong name in the
        ///     assembly's evidence if a host has chosen to customize the evidence the assembly was loaded
        ///     with.
        /// </remarks>
        /// <exception cref="ArgumentException">if the assembly is not strongly named</exception>
        public static StrongName GetStrongName(this Assembly assembly)
        {
            if (!assembly.IsStrongNamed())
                throw new ArgumentException(Resources.AssemblyNotStrongNamed, "assembly");

            AssemblyName assemblyName = assembly.GetName();
            StrongNamePublicKeyBlob strongNameKeyBlob = new StrongNamePublicKeyBlob(assemblyName.GetPublicKey());
            return new StrongName(strongNameKeyBlob, assemblyName.Name, assemblyName.Version);
        }

        /// <summary>
        ///     Determine if an assembly is granted full trust in the current domain.
        /// </summary>
        /// <remarks>
        ///     Results may not be accurate for assemblies loaded via <see cref="Assembly.Load(byte[])" />, or
        ///     dynamic assemblies created with
        ///     <see cref="AppDomain.DefineDynamicAssembly(AssemblyName, AssemblyBuilderAccess)" />
        /// </remarks>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Does not leak out information about the exact grant set")]
        public static bool IsFullyTrusted(this Assembly assembly)
        {
            return assembly.GetPermissionSet().IsUnrestricted();
        }

        /// <summary>
        ///     Determine if an assembly is strong name signed.  This method does not attempt to detect if
        ///     the assembly is delay signed and loaded because of a skip verification entry on the machine.
        /// </summary>
        public static bool IsStrongNamed(this Assembly assembly)
        {
            AssemblyName assemblyName = assembly.GetName();
            byte[] publicKey = assemblyName.GetPublicKey();

            return publicKey != null && publicKey.Length > 0;
        }
    }
}
