// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace Security.Principal
{
    /// <summary>
    ///     Extension methods for the <see cref="System.Security.Principal.NTAccount" /> class.  These
    ///     extension methods are in the Security.Principal namespace, so in order to use them both the
    ///     Security.Principal and System.Security.Principal namespaces must be included in your code.
    /// </summary>
    public static class NTAccountExtensionMethods
    {
        /// <summary>
        ///      Get the user name and domain name that correspond to an NTAccount for use with logon user
        /// </summary>
        private static void GetUserAndDomainName(NTAccount ntAccount, out string userName, out string domain)
        {
            string[] accountParts = ntAccount.Value.Split('\\');
            if (accountParts.Length == 2)
            {
                // The name is in domain\user format
                domain = accountParts[0];
                userName = accountParts[1];
            }
            else
            {
                // If we have no domain, or we're in another format (such as UPN) then just treat the whole
                // string as the user name and pass through null for the domain.
                userName = ntAccount.Value;
                domain = null;
            }
        }

        /// <summary>
        ///     Log a user on using a clear string password.  This method uses the default logon provider
        ///     and performs an interactive logon.
        /// </summary>
        /// <permission cref="SecurityPermission">This method demands SecurityPermission/ControlPrincipal</permission>
        public static WindowsIdentity LogOnUser(this NTAccount ntAccount, string password)
        {
            return ntAccount.LogOnUser(password, LogOnType.Interactive, LogOnProvider.Default);
        }

        /// <summary>
        ///     Log a user on using a clear string password, specifying the logon type and provider to use.
        /// </summary>
        /// <permission cref="SecurityPermission">This method demands SecurityPermission/ControlPrincipal</permission>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SecurityPermission(SecurityAction.Demand, ControlPrincipal = true)]
        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Justification = "Called within an AddRef / Release")]
        public static WindowsIdentity LogOnUser(this NTAccount ntAccount,
                                                string password,
                                                LogOnType logOnType,
                                                LogOnProvider logOnProvider)
        {
            string userName;
            string domain;
            GetUserAndDomainName(ntAccount, out userName, out domain);

            using (SafeTokenHandle token = Win32Native.LogOnUser(userName, domain, password, logOnType, logOnProvider))
            {
                bool addedRef = false;

                RuntimeHelpers.PrepareConstrainedRegions();
                try
                {
                    token.DangerousAddRef(ref addedRef);
                    return new WindowsIdentity(token.DangerousGetHandle());
                }
                finally
                {
                    if (addedRef)
                    {
                        token.DangerousRelease();
                    }
                }
            }
        }

        /// <summary>
        ///     Log a user on using a secure password.  This method uses the default logon provider and
        ///     performs an interactive logon.
        /// </summary>
        /// <permission cref="SecurityPermission">This method demands SecurityPermission/ControlPrincipal</permission>
        public static WindowsIdentity LogOnUser(this NTAccount ntAccount, SecureString password)
        {
            return ntAccount.LogOnUser(password, LogOnType.Interactive, LogOnProvider.Default);
        }

        /// <summary>
        ///     Log a user on using a secure password, specifying the logon type and provider to use.
        /// </summary>
        /// <permission cref="SecurityPermission">This method demands SecurityPermission/ControlPrincipal</permission>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SecurityPermission(SecurityAction.Demand, ControlPrincipal = true)]
        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Justification = "Called within an AddRef / Release")]
        public static WindowsIdentity LogOnUser(this NTAccount ntAccount,
                                                SecureString password,
                                                LogOnType logOnType,
                                                LogOnProvider logOnProvider)
        {
            string userName;
            string domain;
            GetUserAndDomainName(ntAccount, out userName, out domain);

            using (SafeTokenHandle token = Win32Native.LogOnUser(userName, domain, password, logOnType, logOnProvider))
            {
                bool addedRef = false;

                RuntimeHelpers.PrepareConstrainedRegions();
                try
                {
                    token.DangerousAddRef(ref addedRef);
                    return new WindowsIdentity(token.DangerousGetHandle());
                }
                finally
                {
                    if (addedRef)
                    {
                        token.DangerousRelease();
                    }
                }
            }
        }
    }
}
