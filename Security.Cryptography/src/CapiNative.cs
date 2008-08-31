// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Native wrappers for CAPI APIs.
    ///     
    ///     The general pattern for this interop layer is that the CapiNative type exports a wrapper method
    ///     for consumers of the interop methods.  This wrapper method puts a managed face on the raw
    ///     P/Invokes, by translating from native structures to managed types and converting from error
    ///     codes to exceptions.
    ///     
    ///     The native definitions here are generally found in wincrypt.h
    /// </summary>
    internal static class CapiNative
    {
        //
        // Enumerations
        //

        internal static class WellKnownOids
        {
            internal static string RsaSha1      = "1.2.840.113549.1.1.5";       // szOID_RSA_SHA1RSA
            internal static string RsaSha256    = "1.2.840.113549.1.1.11";      // szOID_RSA_SHA256RSA
            internal static string RsaSha384    = "1.2.840.113549.1.1.12";      // szOID_RSA_SHA384RSA
            internal static string RsaSha512    = "1.2.840.113549.1.1.13";      // szOID_RSA_SHA512RSA
        }

        //
        // Structures
        //

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszObjId;

            internal CRYPTOAPI_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        [SuppressMessage("Microsoft.Design", "CA1049:TypesThatOwnNativeResourcesShouldBeDisposable", Justification = "CRYPTOAPI_BLOB does not own any resources")]
        internal struct CRYPTOAPI_BLOB
        {
            internal int cbData;

            [SuppressMessage("Microsoft.Reliability", "CA2006:UseSafeHandleToEncapsulateNativeResources", Justification = "This field is for a byte *, not for a handle, and is cleaned up differently depending upon how the byte * was allocated")]
            internal IntPtr pbData; // BYTE*
        }
    }
}
