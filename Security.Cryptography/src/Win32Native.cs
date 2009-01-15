// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace Security.Cryptography
{
    /// <summary>
    ///     Native interop layer for Win32 APIs
    /// </summary>
    internal static class Win32Native
    {
        //
        // Structures
        //

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEMTIME
        {
            internal ushort wYear;
            internal ushort wMonth;
            internal ushort wDayOfWeek;
            internal ushort wDay;
            internal ushort wHour;
            internal ushort wMinute;
            internal ushort wSecond;
            internal ushort wMilliseconds;

            internal SYSTEMTIME(DateTime time)
            {
                wYear = (ushort)time.Year;
                wMonth = (ushort)time.Month;
                wDayOfWeek = (ushort)time.DayOfWeek;
                wDay = (ushort)time.Day;
                wHour = (ushort)time.Hour;
                wMinute = (ushort)time.Minute;
                wSecond = (ushort)time.Second;
                wMilliseconds = (ushort)time.Millisecond;
            }
        }
    }

    /// <summary>
    ///     Safe handle base class for safe handles which are associated with an additional data buffer that
    ///     must be kept alive for the same amount of time as the handle itself.
    ///     
    ///     This is required rather than having a seperate safe handle own the key data buffer blob so
    ///     that we can ensure that the key handle is disposed of before the key data buffer is freed.
    /// </summary>
    [SecurityCritical(SecurityCriticalScope.Everything)]
    internal abstract class SafeHandleWithBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        private IntPtr m_dataBuffer;

        protected SafeHandleWithBuffer() : base(true)
        {
            return;
        }

        public override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero &&             // The handle is not valid
                       m_dataBuffer == IntPtr.Zero;         // And we don't own any native memory
            }
        }

        /// <summary>
        ///     Buffer that holds onto the key data object. This data must be allocated with CoAllocTaskMem, 
        ///     or the ReleaseBuffer method must be overriden to match the deallocation function with the
        ///     allocation function.  Once the buffer is assigned into the DataBuffer property, the safe
        ///     handle owns the buffer and users of this property should not attempt to free the memory.
        ///     
        ///     This property should be set only once, otherwise the first data buffer will leak.
        /// </summary>
        internal IntPtr DataBuffer
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            get { return m_dataBuffer; }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            set
            {
                Debug.Assert(m_dataBuffer == IntPtr.Zero, "SafeHandleWithBuffer already owns a data buffer - this will result in a native memory leak.");
                Debug.Assert(value != IntPtr.Zero, "value != IntPtr.Zero");

                m_dataBuffer = value;
            }
        }

        /// <summary>
        ///     Release the buffer associated with the handle
        /// </summary>
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected virtual bool ReleaseBuffer()
        {
            Marshal.FreeCoTaskMem(m_dataBuffer);
            return true;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected sealed override bool ReleaseHandle()
        {
            bool error = false;

            if (handle != IntPtr.Zero)
            {
                error = ReleaseNativeHandle();
            }

            if (m_dataBuffer != IntPtr.Zero)
            {
                error &= ReleaseBuffer();
            }

            return error;
        }

        /// <summary>
        ///     Release just the native handle associated with the safe handle
        /// </summary>
        /// <returns></returns>
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected abstract bool ReleaseNativeHandle();
    }
}
