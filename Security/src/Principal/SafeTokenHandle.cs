// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Security.Principal
{
    /// <summary>
    ///     <para>
    ///         SafeHandle class for a Win32 HANDLE representing a windows token.  This class can be used
    ///         instead of the raw IntPtr returned from <see cref="System.Security.Principal.WindowsIdentity.Token" />
    ///         in order to prevent the WindowsIdentity object from closing out the hande from underneath you
    ///         if it is garbage collected before your use of the handle is complete.
    ///     </para>
    ///     <para>
    ///         A SafeTokenHandle for a WindowsIdentity can be obtained by calling the
    ///         <see cref="WindowsIdentityExtensionMethods.GetSafeTokenHandle" /> extension method.
    ///     </para>
    /// </summary>
    /// <permission cref="SecurityPermission">
    ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
    /// </permission>
    [SecurityCritical(SecurityCriticalScope.Everything)]
    [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle() : base(true)
        {
        }

        [DllImport("kernel32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release method")]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }
}
