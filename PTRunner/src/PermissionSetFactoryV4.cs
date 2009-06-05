// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Data.OleDb;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Drawing.Printing;
using System.Net;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;

namespace Security.Tools.PartialTrustRunner
{
    /// <summary>
    ///     The PermissionSetFactoryV4 class is a version of the PermissionSetFactory class from Security.dll
    ///     which works with the new APIs present in the v4 framework.  We can't use the regular
    ///     PermissionSetFactory type because it uses CAS policy behind the scenes to determine the
    ///     standard permission sets.  Since CAS policy is deprecated in the v4 .NET Framework, we need to
    ///     use this alternate mechanism to get the standard permission sets.
    /// </summary>
    internal static class PermissionSetFactoryV4
    {
        /// <summary>
        ///     Get the Internet permission set
        /// </summary>
        /// <param name="sourceUrl">optional source URL to generate same-site permission for</param>
        private static PermissionSet GetInternetPermissionSet(Url sourceUrl)
        {
            Evidence evidence = new Evidence();
            evidence.AddHostEvidence(new Zone(SecurityZone.Internet));

            if (sourceUrl != null)
            {
                evidence.AddHostEvidence(sourceUrl);
            }

            return SecurityManager.GetStandardSandbox(evidence); 
        }
        
        /// <summary>
        ///     Get the LocalIntranet permission set
        /// </summary>
        /// <param name="sourceUrl">optional source URL to generate same-site permission for</param>
        private static PermissionSet GetLocalIntranetPermissionSet(Url sourceUrl)
        {
            Evidence evidence = new Evidence();
            evidence.AddHostEvidence(new Zone(SecurityZone.Intranet));

            if (sourceUrl != null)
            {
                evidence.AddHostEvidence(sourceUrl);
            }

            return SecurityManager.GetStandardSandbox(evidence);
        }

        /// <summary>
        ///     Get the Everything permission set
        /// </summary>
        private static PermissionSet GetEverythingPermissionSet()
        {
            PermissionSet ps = new PermissionSet(PermissionState.None);
            ps.AddPermission(new IsolatedStorageFilePermission(PermissionState.Unrestricted));
            ps.AddPermission(new EnvironmentPermission(PermissionState.Unrestricted));
            ps.AddPermission(new FileIOPermission(PermissionState.Unrestricted));
            ps.AddPermission(new FileDialogPermission(PermissionState.Unrestricted));
            ps.AddPermission(new ReflectionPermission(PermissionState.Unrestricted));
            ps.AddPermission(new SecurityPermission(SecurityPermissionFlag.Assertion | SecurityPermissionFlag.UnmanagedCode | SecurityPermissionFlag.Execution | SecurityPermissionFlag.ControlThread | SecurityPermissionFlag.ControlEvidence | SecurityPermissionFlag.ControlPolicy | SecurityPermissionFlag.ControlAppDomain | SecurityPermissionFlag.SerializationFormatter | SecurityPermissionFlag.ControlDomainPolicy | SecurityPermissionFlag.ControlPrincipal | SecurityPermissionFlag.RemotingConfiguration | SecurityPermissionFlag.Infrastructure | SecurityPermissionFlag.BindingRedirects));
            ps.AddPermission(new UIPermission(PermissionState.Unrestricted));
            ps.AddPermission(new SocketPermission(PermissionState.Unrestricted));
            ps.AddPermission(new WebPermission(PermissionState.Unrestricted));
            ps.AddPermission(new DnsPermission(PermissionState.Unrestricted));
            ps.AddPermission(new KeyContainerPermission(PermissionState.Unrestricted));
            ps.AddPermission(new RegistryPermission(PermissionState.Unrestricted));
            ps.AddPermission(new PrintingPermission(PermissionState.Unrestricted));
            ps.AddPermission(new EventLogPermission(PermissionState.Unrestricted));
            ps.AddPermission(new StorePermission(PermissionState.Unrestricted));
            ps.AddPermission(new PerformanceCounterPermission(PermissionState.Unrestricted));
            ps.AddPermission(new OleDbPermission(PermissionState.Unrestricted));
            ps.AddPermission(new SqlClientPermission(PermissionState.Unrestricted));
            ps.AddPermission(new DataProtectionPermission(PermissionState.Unrestricted));

            // WPF extends the Internet and LocalIntranet permission sets with additional permissions that
            // don't appear in the Everything permission set.  Since it's desirable to have Everything be a
            // superset of the other permission sets, if we find that Internet has been extended, we'll add
            // unrestricted versions of the extended permissions to our Everything set as well.
            foreach (IPermission perm in GetLocalIntranetPermissionSet(null))
            {
                if (ps.GetPermission(perm.GetType()) == null)
                {
                    ConstructorInfo permissionConstructor =
                        perm.GetType().GetConstructor(new Type[] { typeof(PermissionState) });

                    if (permissionConstructor != null)
                    {
                        IPermission extendedPermission =
                            permissionConstructor.Invoke(new object[] { PermissionState.Unrestricted }) as IPermission;
                        ps.AddPermission(extendedPermission);
                    }
                }
            }

            return ps;
        }
        
        /// <summary>
        ///     Build a copy of a given standard permission set, optionally extending it with same site
        ///     permission for the given source URL.
        /// </summary>
        /// <param name="permissionSet">standard permission set to generate</param>
        /// <param name="sourceUrl">optional source URL to generate same site permission for</param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if <paramref name="permissionSet" /> is not one of the standard permission sets
        /// </exception>
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Security", "CA2116:AptcaMethodsShouldOnlyCallAptcaMethods", Justification = "Reviewed")]
        internal static PermissionSet GetStandardPermissionSet(StandardPermissionSet permissionSet,
                                                               Url sourceUrl)
        {
            switch (permissionSet)
            {
                    // We need to handle Internet, LocalIntranet, and Everything ourselves, since
                    // PermissionSetFactory will use deprecated CAS policy to calculate those
                case StandardPermissionSet.Internet:
                    return GetInternetPermissionSet(sourceUrl);
                case StandardPermissionSet.LocalIntranet:
                    return GetLocalIntranetPermissionSet(sourceUrl);
                case StandardPermissionSet.Everything:
                    return GetEverythingPermissionSet();

                    // Everything else can be obtained through PermissionSetFactory
                default:
                    return PermissionSetFactory.GetStandardPermissionSet(permissionSet, sourceUrl);
            }
        }
    }
}
