// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ConstrainedExecution;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Security
{
    /// <summary>
    ///     Native wrappers for Win32 APIs.
    ///     
    ///     The general pattern for this interop layer is that the Win32 type exports a wrapper method
    ///     for consumers of the interop methods.  This wrapper method puts a managed face on the raw
    ///     P/Invokes, by translating from native structures to managed types and converting from error
    ///     codes to exceptions.
    ///     
    ///     The native definitions here are generally found in windows.h, winbase.h, and winnt.h
    /// </summary>
    internal static class Win32Native
    {
        //
        // Enumerations
        // 

        /// <summary>
        ///     Flags for the DuplicateHandle API
        /// </summary>
        [Flags]
        internal enum DuplicateHandleOptions
        {
            None        = 0,
            SameAccess  = 0x00000002,       // DUPLICATE_SAME_ACCESS
        }

        /// <summary>
        ///     Token information type specifier for the GetTokenInformation API
        /// </summary>
        internal enum TokenInformationClass
        {
            None = 0,
            TokenGroups = 2,                    // TokenGroups
        }

        //
        // Structures
        // 

        [StructLayout(LayoutKind.Sequential)]
        internal struct SID_AND_ATTRIBUTES
        {
            internal IntPtr Sid;        // PSID
            internal int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_GROUPS
        {
            internal int GroupCount;
            internal SID_AND_ATTRIBUTES Groups;     // SID_AND_ATTRIBUTES[GroupCount]
        }

        //
        // P/Invokes
        // 

        [SecurityCritical(SecurityCriticalScope.Everything)]
        [SuppressUnmanagedCodeSecurity]
        private static class UnsafeNativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
                                                        IntPtr hSourceHandle,
                                                        IntPtr hTargetProcessHandle,
                                                        [Out] out SafeTokenHandle lpTargetHandle,
                                                        int dwDesiredAccess,
                                                        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
                                                        DuplicateHandleOptions options);

            [DllImport("kernel32.dll")]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetTokenInformation(SafeTokenHandle tokenHandle,
                                                            TokenInformationClass TokenInformationClass,
                                                            SafeBuffer TokenInformation,
                                                            int TokenInformationLength,
                                                            [Out] out int ReturnLength);
        }

        //
        // Wrapper APIs
        // 

        /// <summary>
        ///     Duplicate a raw IntPtr handle from a WindowsIdentity into a SafeTokenHandle
        /// </summary>
        [SecurityCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Guarded as a SecurityCritical method")]
        internal static SafeTokenHandle DuplicateTokenHandle(IntPtr tokenHandle)
        {
            Debug.Assert(tokenHandle != IntPtr.Zero);

            SafeTokenHandle safeTokenHandle = null;
            IntPtr currentProcessHandle = UnsafeNativeMethods.GetCurrentProcess();
            if (!UnsafeNativeMethods.DuplicateHandle(currentProcessHandle,
                                                     tokenHandle,
                                                     currentProcessHandle,
                                                     out safeTokenHandle,
                                                     0,
                                                     false,
                                                     DuplicateHandleOptions.SameAccess))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
            }

            return safeTokenHandle;
        }

        /// <summary>
        ///     Get raw token information
        /// </summary>
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Guarded as a SecurityCritical method")]
        [SecurityCritical]
        internal static SafeBuffer GetTokenInformation(SafeTokenHandle tokenHandle, TokenInformationClass informationClass)
        {
            Debug.Assert(tokenHandle != null && !tokenHandle.IsClosed && !tokenHandle.IsInvalid);

            // Figure out how much memory we need to hold this token information
            int bufferSize;
            UnsafeNativeMethods.GetTokenInformation(tokenHandle,
                                                    informationClass,
                                                    SafeBuffer.InvalidBuffer,
                                                    0,
                                                    out bufferSize);

            // Allocate a buffer and get the token information
            SafeBuffer buffer = SafeBuffer.Allocate(bufferSize);
            if (!UnsafeNativeMethods.GetTokenInformation(tokenHandle,
                                                         informationClass,
                                                         buffer,
                                                         bufferSize,
                                                         out bufferSize))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            return buffer;
        }
    }

    /// <summary>
    ///     Safe handle type wrapping a buffer that can be accessed as an array
    /// </summary>
    [SecurityCritical(SecurityCriticalScope.Everything)]
    internal sealed class SafeBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Protected as a SecurityCritical method")]
        internal SafeBuffer() : base(true)
        {
        }

        internal static SafeBuffer InvalidBuffer
        {
            get { return new SafeBuffer(); }
        }

        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Protected as a SecurityCritical method")]
        internal static SafeBuffer Allocate(int bytes)
        {
            Debug.Assert(bytes >= 0);

            SafeBuffer buffer = new SafeBuffer();

            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                buffer.SetHandle(Marshal.AllocCoTaskMem(bytes));
            }

            return buffer;
        }

        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Protected as a SecurityCritical method")]
        internal T Read<T>(int offset) where T : struct
        {
            bool addedRef = false;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref addedRef);

                unsafe
                {
                    IntPtr pBase = new IntPtr((byte*)handle.ToPointer() + offset);
                    return (T)Marshal.PtrToStructure(pBase, typeof(T));
                }
            }
            finally
            {
                if (addedRef)
                {
                    DangerousRelease();
                }
            }

        }

        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Protected as a SecurityCritical method")]
        internal T[] ReadArray<T>(int offset, int count) where T : struct
        {
            Debug.Assert(offset >= 0);
            Debug.Assert(count >= 0);

            T[] array = new T[count];
            checked
            {
                // Figure out how big each structure is within the buffer.
                uint structSize = (uint)Marshal.SizeOf(typeof(T));
                if (structSize % UIntPtr.Size != 0)
                {
                    structSize += (uint)(UIntPtr.Size - (structSize % UIntPtr.Size));
                }

                bool addedRef = false;
                RuntimeHelpers.PrepareConstrainedRegions();
                try
                {
                    DangerousAddRef(ref addedRef);

                    for (int i = 0; i < count; ++i)
                    {
                        unsafe
                        {
                            UIntPtr pElement = new UIntPtr((byte*)handle.ToPointer() + offset + (structSize * i));
                            array[i] = (T)Marshal.PtrToStructure(new IntPtr(pElement.ToPointer()), typeof(T));
                        }
                    }
                }
                finally
                {
                    if (addedRef)
                    {
                        DangerousRelease();
                    }
                }
            }

            return array;
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeCoTaskMem(handle);
            return true;
        }
    }
}
