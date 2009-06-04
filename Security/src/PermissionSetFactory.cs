// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Collections;
using System.Reflection;
using System.IO;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Security.Policy;

namespace Security
{
    /// <summary>
    ///     The PermissionSetFactory class provides methods to easily get copies of common permission sets.
    /// </summary>
    public static class PermissionSetFactory
    {
        private const string WpfPermissionXml = @"
            <PermissionSet class=""System.Security.NamedPermissionSet"" version=""1""
                <IPermission class=""System.Security.Permissions.MediaPermission, WindowsBase, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"" version=""1"" Audio=""SafeAudio"" Video=""SafeVideo"" Image=""SafeImage"" />
                <IPermission class=""System.Security.Permissions.WebBrowserPermission, WindowsBase, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"" version=""1"" Level=""Safe"" />
            </PermissionSet>";

        private static PolicyLevel s_machinePolicyLevel;
        private static PermissionSet s_wpfPermissionSet;

        /// <summary>
        ///     Get a copy of the Machine policy level which can be used to get at the standard permission sets
        /// </summary>
        private static PolicyLevel MachinePolicyLevel
        {
            get
            {
                if (s_machinePolicyLevel == null)
                {
                    IEnumerator policyEnumerator = SecurityManager.PolicyHierarchy();
                    while (policyEnumerator.MoveNext() && s_machinePolicyLevel == null)
                    {
                        PolicyLevel currentLevel = policyEnumerator.Current as PolicyLevel;
                        if (currentLevel.Type == PolicyLevelType.Machine)
                        {
                            s_machinePolicyLevel = currentLevel;
                        }
                    }
                }

                Debug.Assert(s_machinePolicyLevel != null, "Did not find the machine policy level");
                return s_machinePolicyLevel;
            }
        }

        /// <summary>
        ///     Get the WPF permissions to extend the internet and intranet permission sets with if WPF is on
        ///     the machine.
        /// </summary>
        private static PermissionSet WpfPermissionSet
        {
            get
            {
                if (s_wpfPermissionSet == null)
                {   
                    PermissionSet wpfPermissionSet = new PermissionSet(PermissionState.None);
                    try
                    {
                        SecurityElement wpfXml = SecurityElement.FromString(WpfPermissionXml);
                        wpfPermissionSet.FromXml(wpfXml);
                    }
                    catch (TypeLoadException)
                    {
                        // If we got a TypeLoadException, it means we can't find the WPF permissions, which
                        // likely means that WPF is not on the machine.  In this case, we'll just have an
                        // empty WPF permission set.
                    }

                    s_wpfPermissionSet = wpfPermissionSet;
                }

                return s_wpfPermissionSet;
            }
        }

        /// <summary>
        ///     Obtain a copy of the Everything permission set
        /// </summary>
        private static PermissionSet GetEverythingPermissionSet()
        {
            PermissionSet everything = MachinePolicyLevel.GetNamedPermissionSet("Everything");

            // WPF extends the Internet and LocalIntranet permission sets with additional permissions that
            // don't appear in the Everything permission set.  Since it's desirable to have Everything be a
            // superset of the other permission sets, if we find that Internet has been extended, we'll add
            // unrestricted versions of the extended permissions to our Everything set as well.
            foreach (IPermission permission in WpfPermissionSet)
            {
                if (everything.GetPermission(permission.GetType()) == null)
                {
                    // We found an extended permission - add a new version of it into our permission set
                    ConstructorInfo permissionConstructor = permission.GetType().GetConstructor(new Type[] { typeof(PermissionState) });
                    if (permissionConstructor != null)
                    {
                        IPermission extendedPermission =
                            permissionConstructor.Invoke(new object[] { PermissionState.Unrestricted }) as IPermission;
                        everything.AddPermission(extendedPermission);
                    }
                }
            }

            return everything;
        }

        /// <summary>
        ///     Generate a permission set with only the permission to execute in it
        /// </summary>
        private static PermissionSet GetExecutionPermissionSet()
        {
            PermissionSet execution = new PermissionSet(PermissionState.None);
            execution.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));
            return execution;
        }

        /// <summary>
        ///     Generate a copy of the full trust permission set.
        /// </summary>
        private static PermissionSet GetFullTrustPermissionSet()
        {
            return new PermissionSet(PermissionState.Unrestricted);
        }

        /// <summary>
        ///     Generate the LocalIntranet permission set, optionally extending it with same site permissions
        /// </summary>
        private static PermissionSet GetLocalIntranetPermissionSet(Url sourceUrl)
        {
            PermissionSet localIntranet = MachinePolicyLevel.GetNamedPermissionSet("LocalIntranet");

            // If we have a source URL, try to generate same-site web and file permissions to add to the
            // local intranet set
            if (sourceUrl != null)
            {
                Evidence evidence = new Evidence();
                evidence.AddHostEvidence(new Zone(SecurityZone.Intranet));
                evidence.AddHostEvidence(sourceUrl);

                PolicyStatement webPolicy =
                    new NetCodeGroup(new AllMembershipCondition()).Resolve(evidence);
                if (webPolicy != null)
                {
                    localIntranet = localIntranet.Union(webPolicy.PermissionSet);
                }
                
                PolicyStatement filePolicy =
                    new FileCodeGroup(new AllMembershipCondition(), FileIOPermissionAccess.Read | FileIOPermissionAccess.PathDiscovery).Resolve(evidence);
                if (filePolicy != null)
                {
                    localIntranet = localIntranet.Union(filePolicy.PermissionSet);
                }
            }

            // If WPF is available on the machine, then extend the permission set with some additional WPF
            // permissions as well.
            localIntranet = localIntranet.Union(WpfPermissionSet);

            return localIntranet;
        }

        /// <summary>
        ///     Generate the Internet permission set, optionally extending it with same site permissions
        /// </summary>
        private static PermissionSet GetInternetPermissionSet(Url sourceUrl)
        {
            PermissionSet internet = MachinePolicyLevel.GetNamedPermissionSet("Internet");

            // If we have a source URL, try to generate same-site web permissions to add to the internet set
            if (sourceUrl != null)
            {
                Evidence evidence = new Evidence();
                evidence.AddHostEvidence(new Zone(SecurityZone.Internet));
                evidence.AddHostEvidence(sourceUrl);

                PolicyStatement webPolicy =
                    new NetCodeGroup(new AllMembershipCondition()).Resolve(evidence);
                if (webPolicy != null)
                {
                    internet = internet.Union(webPolicy.PermissionSet);
                }
            }

            // If WPF is available on the machine, then extend the permission set with some additional WPF
            // permissions as well.
            internet = internet.Union(WpfPermissionSet);

            return internet;
        }

        /// <summary>
        ///     Generate a copy of the Nothing permission set
        /// </summary>
        private static PermissionSet GetNothingPermissionSet()
        {
            return new PermissionSet(PermissionState.None);
        }

        /// <summary>
        ///     Get a sandbox permission set which is safe to use for an assembly that has the given
        ///     evidence.  This is explicitly not a policy API - it instead provides guidance for hosts
        ///     which can use this set in their decisions as to how to sandbox an assembly best.  CAS policy
        ///     is not consulted when generating this suggested permission set.
        /// </summary>
        /// <param name="evidence">evidence to get a standard sandbox for</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="evidence" /> is null
        /// </exception>
        public static PermissionSet GetStandardSandbox(Evidence evidence)
        {
            if (evidence == null)
                throw new ArgumentNullException("evidence");

            // Gather the relevant evidence - zone and URL
            Zone zone = evidence.GetHostEvidence<Zone>();
            Url url = evidence.GetHostEvidence<Url>();

            // If we don't have a security zone, then we can't safely grant anything
            if (zone == null)
            {
                return GetStandardPermissionSet(StandardPermissionSet.Nothing);
            }

            switch (zone.SecurityZone)
            {
                    // Internet or Trusted -> Internet
                case SecurityZone.Internet:
                case SecurityZone.Trusted:
                    return GetStandardPermissionSet(StandardPermissionSet.Internet, url);

                    // Intranet -> LocalIntranet
                case SecurityZone.Intranet:
                    return GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, url);

                    // MyComputer -> FullTrust
                case SecurityZone.MyComputer:
                    return GetStandardPermissionSet(StandardPermissionSet.FullTrust);

                    // Anything else -> Nothing
                default:
                    return GetStandardPermissionSet(StandardPermissionSet.Nothing);
            }
        }

        /// <summary>
        ///     Build a copy of a given standard permission set, without including any same site permissions.
        /// </summary>
        /// <param name="permissionSet">standard permission set to generate</param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if <paramref name="permissionSet" /> is not one of the standard permission sets
        /// </exception>
        public static PermissionSet GetStandardPermissionSet(StandardPermissionSet permissionSet)
        {
            return GetStandardPermissionSet(permissionSet, null);
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
        public static PermissionSet GetStandardPermissionSet(StandardPermissionSet permissionSet,
                                                             Url sourceUrl)
        {
            switch (permissionSet)
            {
                case StandardPermissionSet.Everything:
                    return GetEverythingPermissionSet();
                case StandardPermissionSet.Execution:
                    return GetExecutionPermissionSet();
                case StandardPermissionSet.FullTrust:
                    return GetFullTrustPermissionSet();
                case StandardPermissionSet.Internet:
                    return GetInternetPermissionSet(sourceUrl);
                case StandardPermissionSet.LocalIntranet:
                    return GetLocalIntranetPermissionSet(sourceUrl);
                case StandardPermissionSet.Nothing:
                    return GetNothingPermissionSet();
                default:
                    throw new ArgumentOutOfRangeException("permissionSet");
            }
        }
    }
}
