// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace Security.Principal
{
    /// <summary>
    ///     Extension methods for the <see cref="System.Security.Principal.WindowsIdentity" /> class.  These
    ///     extension methods are in the Security.Principal namespace, so in order to use them both the
    ///     Security.Principal and System.Security.Principal namespaces must be included in your code.
    /// </summary>
    public static class WindowsIdentityExtensionMethods
    {
        /// <summary>
        ///     Get the group information for all of the groups that associated with the
        ///     <see cref="System.Security.Principal.WindowsIdentity" />.  This is different from the standard
        ///     <see cref="System.Security.Principal.WindowsIdentity.Groups" /> property in that none of the
        ///     returned groups are filtered out.  Before using any of the groups, it is important to ensure
        ///     that they are enabled and not for deny-only by checking their attributes.
        /// </summary>
        /// <returns>
        ///     A collection of <see cref="GroupSecurityIdentifierInformation" /> objects containing the group
        ///     SIDs which are attacked to the WindowsIdentity's token, as well as the associated attributes.
        /// </returns>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of Marshal")]
        public static IEnumerable<GroupSecurityIdentifierInformation> GetAllGroups(this WindowsIdentity windowsIdentity)
        {
            // Get the raw group information, which is a buffer starting with a TOKEN_GROUPS structure
            using (SafeBuffer groupInformation = Win32Native.GetTokenInformation(windowsIdentity.GetSafeTokenHandle(),
                                                                                 Win32Native.TokenInformationClass.TokenGroups))
            {
                // First, read the TOKEN_GROUPS header out of the buffer
                Win32Native.TOKEN_GROUPS tokenGroups = groupInformation.Read<Win32Native.TOKEN_GROUPS>(0);

                // The TOKEN_GROUPS.Group property is an array of SID_AND_ATTRIBUTES structures. Grab that
                // array of data.
                // Iterate that array, and create managed GroupSecurityIdentifierInformation types for them.
                Win32Native.SID_AND_ATTRIBUTES[] sids =
                    groupInformation.ReadArray<Win32Native.SID_AND_ATTRIBUTES>(Marshal.OffsetOf(typeof(Win32Native.TOKEN_GROUPS), "Groups").ToInt32(),
                                                                               tokenGroups.GroupCount);

                var sidInfo = from sid in sids
                              select new GroupSecurityIdentifierInformation(new SecurityIdentifier(sid.Sid), (GroupSecurityIdentifierAttributes)sid.Attributes);

                // Force the conversion to GroupSecurityIdentifierInformation now, rather than lazily since
                // we need to read the data out of the buffer which will be disposed of after this method exits.
                return sidInfo.ToArray();
            }
        }

        /// <summary>
        ///     Get a SafeHandle for the token that the WindowsIdentity represents.
        /// </summary>
        /// <returns>
        ///     A <see cref="SafeTokenHandle" /> for the token of the WindowsIdentity.  This token handle can
        ///     be used beyond the lifetime of the originating WindowsIdentity object and must be disposed of
        ///     seperately.
        /// </returns>
        [SecurityCritical]
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        [SuppressMessage("Microsoft.Reliability", "CA2004:RemoveCallsToGCKeepAlive")]
        public static SafeTokenHandle GetSafeTokenHandle(this WindowsIdentity windowsIdentity)
        {
            SafeTokenHandle safeTokenHandle = Win32Native.DuplicateTokenHandle(windowsIdentity.Token);

            // Make sure to keep the WindowsIdentity object alive until after the handle is duplicated -
            // otherwise the handle could be closed out from underneath us before we get to duplicate it into
            // our safe handle.
            GC.KeepAlive(windowsIdentity);

            return safeTokenHandle;
        }

        /// <summary>
        ///     Determine if the a WindowsIdentity is in the Administrator role
        /// </summary>
        public static bool IsAdministrator(this WindowsIdentity windowsIdentity)
        {
            WindowsPrincipal principal = new WindowsPrincipal(windowsIdentity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
