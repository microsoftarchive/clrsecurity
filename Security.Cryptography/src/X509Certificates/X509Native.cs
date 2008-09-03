// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Security.Cryptography.X509Certificates
{
    //
    // Public facing enumerations
    //

    /// <summary>
    ///     Flags for use when creating a new certificate
    /// </summary>
    [Flags]
    public enum X509CertificateCreationOptions
    {
        None                    = 0x00000000,
        DoNotSignCertificate    = 0x00000001,       // CERT_CREATE_SELFSIGN_NO_KEY_INFO
        DoNotLinkKeyInformation = 0x00000002,       // CERT_CREATE_SELFSIGN_NO_SIGN
    }

    /// <summary>
    ///     Signature algorithms which can be used to sign an X.509 certificate
    /// </summary>
    public enum X509CertificateSignatureAlgorithm
    {
        RsaSha1,
        RsaSha256,
        RsaSha384,
        RsaSha512,
    }

    /// <summary>
    ///     Native wrappers for X509 certificate APIs.
    ///     
    ///     The general pattern for this interop layer is that the X509Native type exports a wrapper method
    ///     for consumers of the interop methods.  This wrapper method puts a managed face on the raw
    ///     P/Invokes, by translating from native structures to managed types and converting from error
    ///     codes to exceptions.
    ///     
    ///     These APIs should strictly layer on top of the lower-level CNG and CAPI native APIs
    /// </summary>
    internal static class X509Native
    {
        //
        // Enumerations
        // 

        /// <summary>
        ///     Well known certificate property IDs
        /// </summary>
        internal enum CertificateProperty
        {
            KeyProviderInfo                     = 2,    // CERT_KEY_PROV_INFO_PROP_ID 
        }

        /// <summary>
        ///     Error codes returned from X509 APIs
        /// </summary>
        internal enum ErrorCode
        {
            Success                 = 0x00000000,       // ERROR_SUCCESS
            MoreData                = 0x000000ea,       // ERROR_MORE_DATA
        }

        //
        // Structures
        //

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_EXTENSION
        {
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszObjId;

            [MarshalAs(UnmanagedType.Bool)]
            internal bool fCritical;

            internal CapiNative.CRYPTOAPI_BLOB Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        [SuppressMessage("Microsoft.Design", "CA1049:TypesThatOwnNativeResourcesShouldBeDisposable", Justification = "Extensions have no single way to be cleaned up, and need to be maintained by their allocators")]
        internal struct CERT_EXTENSIONS
        {
            internal int cExtension;

            [SuppressMessage("Microsoft.Reliability", "CA2006:UseSafeHandleToEncapsulateNativeResources", Justification = "This buffer may be allocated in many different ways, so cleanup is done in a CER manually")]
            internal IntPtr rgExtension;                // CERT_EXTENSION[cExtension]
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszContainerName;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszProvName;

            internal int dwProvType;

            internal int dwFlags;

            internal int cProvParam;

            internal IntPtr rgProvParam;        // PCRYPT_KEY_PROV_PARAM

            internal int dwKeySpec;
        }

        //
        // P/Invokes
        //

        [SecurityCritical(SecurityCriticalScope.Everything)]
        [SuppressUnmanagedCodeSecurity]
        internal static class UnsafeNativeMethods
        {
            [DllImport("crypt32.dll", SetLastError = true)]
            internal static extern SafeCertificateContextHandle CertCreateSelfSignCertificate(SafeNCryptKeyHandle hCryptProvOrNCryptKey,
                                                                                              [In] ref CapiNative.CRYPTOAPI_BLOB pSubjectIssuerBlob,
                                                                                              X509CertificateCreationOptions dwFlags,
                                                                                              IntPtr pKeyProvInfo, // PCRYPT_KEY_PROV_INFO
                                                                                              [In] ref CapiNative.CRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
                                                                                              [In] ref Win32Native.SYSTEMTIME pStartTime,
                                                                                              [In] ref Win32Native.SYSTEMTIME pEndTime,
                                                                                              [In] ref CERT_EXTENSIONS pExtensions);

            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CertGetCertificateContextProperty(IntPtr pCertContext,          // PCERT_CONTEXT
                                                                          CertificateProperty dwPropId,
                                                                          [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pvData,
                                                                          [In, Out] ref int pcbData);
        }

        //
        // Wrapper methods
        //

        /// <summary>
        ///     Create a self signed certificate around a CNG key
        /// </summary>
        [SecurityCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "SecurityCritical API which requires review from any other API that calls it")]
        internal static SafeCertificateContextHandle CreateSelfSignedCertificate(SafeNCryptKeyHandle key,
                                                                                 byte[] subjectName,
                                                                                 X509CertificateCreationOptions creationOptions,
                                                                                 string signatureAlgorithmOid,
                                                                                 DateTime startTime,
                                                                                 DateTime endTime,
                                                                                 X509ExtensionCollection extensions)
        {
            Debug.Assert(key != null, "key != null");
            Debug.Assert(!key.IsClosed && !key.IsInvalid, "!key.IsClosed && !key.IsInvalid");
            Debug.Assert(subjectName != null, "subjectName != null");
            Debug.Assert(!String.IsNullOrEmpty(signatureAlgorithmOid), "!String.IsNullOrEmpty(signatureAlgorithmOid)");
            Debug.Assert(extensions != null, "extensions != null");

            // Create an algorithm identifier structure for the signature algorithm
            CapiNative.CRYPT_ALGORITHM_IDENTIFIER nativeSignatureAlgorithm = new CapiNative.CRYPT_ALGORITHM_IDENTIFIER();
            nativeSignatureAlgorithm.pszObjId = signatureAlgorithmOid;
            nativeSignatureAlgorithm.Parameters = new CapiNative.CRYPTOAPI_BLOB();
            nativeSignatureAlgorithm.Parameters.cbData = 0;
            nativeSignatureAlgorithm.Parameters.pbData = IntPtr.Zero;

            // Convert the begin and expire dates to system time structures
            Win32Native.SYSTEMTIME nativeStartTime = new Win32Native.SYSTEMTIME(startTime);
            Win32Native.SYSTEMTIME nativeEndTime = new Win32Native.SYSTEMTIME(endTime);

            // Map the extensions into CERT_EXTENSIONS.  This involves several steps to get the
            // CERT_EXTENSIONS ready for interop with the native APIs.
            //   1. Build up the CERT_EXTENSIONS structure in managed code
            //   2. For each extension, create a managed CERT_EXTENSION structure; this requires allocating
            //      native memory for the blob pointer in the CERT_EXTENSION. These extensions are stored in
            //      the nativeExtensionArray variable.
            //   3. Get a block of native memory that can hold a native array of CERT_EXTENSION structures.
            //      This is the block referenced by the CERT_EXTENSIONS structure.
            //   4. For each of the extension structures created in step 2, marshal the extension into the
            //      native buffer allocated in step 3.
            CERT_EXTENSIONS nativeExtensions = new CERT_EXTENSIONS();
            nativeExtensions.cExtension = extensions.Count;
            CERT_EXTENSION[] nativeExtensionArray = new CERT_EXTENSION[extensions.Count];

            // Run this in a CER to ensure that we release any native memory allocated for the certificate
            // extensions.
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Copy over each extension into a native extension structure, including allocating native
                // memory for its blob if necessary.
                for (int i = 0; i < extensions.Count; ++i)
                {
                    nativeExtensionArray[i] = new CERT_EXTENSION();
                    nativeExtensionArray[i].pszObjId = extensions[i].Oid.Value;
                    nativeExtensionArray[i].fCritical = extensions[i].Critical;

                    nativeExtensionArray[i].Value = new CapiNative.CRYPTOAPI_BLOB();
                    nativeExtensionArray[i].Value.cbData = extensions[i].RawData.Length;
                    if (nativeExtensionArray[i].Value.cbData > 0)
                    {
                        nativeExtensionArray[i].Value.pbData =
                            Marshal.AllocCoTaskMem(nativeExtensionArray[i].Value.cbData);
                        Marshal.Copy(extensions[i].RawData,
                                     0,
                                     nativeExtensionArray[i].Value.pbData,
                                     nativeExtensionArray[i].Value.cbData);
                    }
                }

                // Now that we've built up the extension array, create a block of native memory to marshal
                // them into.
                if (nativeExtensionArray.Length > 0)
                {
                    checked
                    {
                        // CERT_EXTENSION structures end with a pointer field, which means on all supported
                        // platforms they won't require any padding between elements of the array.
                        nativeExtensions.rgExtension =
                            Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(CERT_EXTENSION)) * nativeExtensionArray.Length);

                        for (int i = 0; i < nativeExtensionArray.Length; ++i)
                        {
                            ulong offset = (uint)i * (uint)Marshal.SizeOf(typeof(CERT_EXTENSION));
                            ulong next = offset + (ulong)nativeExtensions.rgExtension.ToInt64();
                            IntPtr nextExtensionAddr = new IntPtr((long)next);

                            Marshal.StructureToPtr(nativeExtensionArray[i], nextExtensionAddr, false);
                        }
                    }
                }

                //
                // Now that all of the needed data structures are setup, we can create the certificate
                //

                unsafe
                {
                    fixed (byte* pSubjectName = &subjectName[0])
                    {
                        // Create a CRYPTOAPI_BLOB for the subject of the cert
                        CapiNative.CRYPTOAPI_BLOB nativeSubjectName = new CapiNative.CRYPTOAPI_BLOB();
                        nativeSubjectName.cbData = subjectName.Length;
                        nativeSubjectName.pbData = new IntPtr(pSubjectName);

                        // Now that we've converted all the inputs to native data structures, we can generate
                        // the self signed certificate for the input key.
                        SafeCertificateContextHandle selfSignedCertHandle =
                            UnsafeNativeMethods.CertCreateSelfSignCertificate(key,
                                                                              ref nativeSubjectName,
                                                                              creationOptions,
                                                                              IntPtr.Zero,
                                                                              ref nativeSignatureAlgorithm,
                                                                              ref nativeStartTime,
                                                                              ref nativeEndTime,
                                                                              ref nativeExtensions);
                        if (selfSignedCertHandle.IsInvalid)
                        {
                            throw new CryptographicException(Marshal.GetLastWin32Error());
                        }

                        return selfSignedCertHandle;
                    }
                }

            }
            finally
            {
                //
                // In order to release all resources held by the CERT_EXTENSIONS we need to do three things
                //   1. Destroy each structure marshaled into the native CERT_EXTENSION array
                //   2. Release the memory used for the CERT_EXTENSION array
                //   3. Release the memory used in each individual CERT_EXTENSION
                //

                // Release each extension marshaled into the native buffer as well
                if (nativeExtensions.rgExtension != IntPtr.Zero)
                {
                    for (int i = 0; i < nativeExtensionArray.Length; ++i)
                    {
                        ulong offset = (uint)i * (uint)Marshal.SizeOf(typeof(CERT_EXTENSION));
                        ulong next = offset + (ulong)nativeExtensions.rgExtension.ToInt64();
                        IntPtr nextExtensionAddr = new IntPtr((long)next);

                        Marshal.DestroyStructure(nextExtensionAddr, typeof(CERT_EXTENSION));
                    }

                    Marshal.FreeCoTaskMem(nativeExtensions.rgExtension);
                }

                // If we allocated memory for any extensions, make sure to free it now
                for (int i = 0; i < nativeExtensionArray.Length; ++i)
                {
                    if (nativeExtensionArray[i].Value.pbData != IntPtr.Zero)
                    {
                        Marshal.FreeCoTaskMem(nativeExtensionArray[i].Value.pbData);
                    }
                }
            }
        }

        /// <summary>
        ///     Get an arbitrary property of a certificate
        /// </summary>
        [SecurityCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "SecurityCritical API which requires review to call")]
        internal static byte[] GetCertificateProperty(IntPtr certificateContext,
                                                      CertificateProperty property)
        {
            Debug.Assert(certificateContext != IntPtr.Zero, "certificateContext != IntPtr.Zero");

            byte[] buffer = null;
            int bufferSize = 0;
            if (!UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext,
                                                                       property,
                                                                       buffer,
                                                                       ref bufferSize))
            {
                ErrorCode errorCode = (ErrorCode)Marshal.GetLastWin32Error();
                if (errorCode != ErrorCode.MoreData)
                {
                    throw new CryptographicException((int)errorCode);
                }
            }

            buffer = new byte[bufferSize];
            if (!UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext,
                                                                       property,
                                                                       buffer,
                                                                       ref bufferSize))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            return buffer;
        }

        /// <summary>
        ///     Get a property of a certificate formatted as a structure
        /// </summary>
        [SecurityCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "SecurityCritical API which requires review to call")]
        internal static T GetCertificateProperty<T>(IntPtr certificateContext,
                                                    CertificateProperty property) where T : struct
        {
            Debug.Assert(certificateContext != IntPtr.Zero, "certificateContext != IntPtr.Zero");

            byte[] rawProperty = GetCertificateProperty(certificateContext, property);
            Debug.Assert(rawProperty.Length >= Marshal.SizeOf(typeof(T)), "Property did not return expected structure");

            unsafe
            {
                fixed (byte* pRawProperty = &rawProperty[0])
                {
                    return (T)Marshal.PtrToStructure(new IntPtr(pRawProperty), typeof(T));
                }
            }
        }

        /// <summary>
        ///     Determine if a certificate has a specific property
        /// </summary>
        [SecurityCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "SecurityCritical API which requires review to call")]
        internal static bool HasCertificateProperty(IntPtr certificateContext,
                                                    CertificateProperty property)
        {
            Debug.Assert(certificateContext != IntPtr.Zero, "certificateContext != IntPtr.Zero");

            byte[] buffer = null;
            int bufferSize = 0;
            bool gotProperty = UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext,
                                                                                     property,
                                                                                     buffer,
                                                                                     ref bufferSize);
            return gotProperty ||
                   (ErrorCode)Marshal.GetLastWin32Error() == ErrorCode.MoreData;
        }

        /// <summary>
        ///     Get the corresponding OID for an X509 certificate signature algorithm
        /// </summary>
        internal static string MapCertificateSignatureAlgorithm(X509CertificateSignatureAlgorithm signatureAlgorithm)
        {
            Debug.Assert(signatureAlgorithm >= X509CertificateSignatureAlgorithm.RsaSha1 &&
                         signatureAlgorithm <= X509CertificateSignatureAlgorithm.RsaSha512,
                         "Invalid signature algorithm");

            switch (signatureAlgorithm)
            {
                case X509CertificateSignatureAlgorithm.RsaSha1:
                    return CapiNative.WellKnownOids.RsaSha1;

                case X509CertificateSignatureAlgorithm.RsaSha256:
                    return CapiNative.WellKnownOids.RsaSha256;

                case X509CertificateSignatureAlgorithm.RsaSha384:
                    return CapiNative.WellKnownOids.RsaSha384;

                case X509CertificateSignatureAlgorithm.RsaSha512:
                    return CapiNative.WellKnownOids.RsaSha512;

                default:
                    Debug.Assert(false, "Unknown certificate signature algorithm");
                    return null;
            }
        }
    }

    /// <summary>
    ///     Safe handle to represent a native CERT_CONTEXT
    /// </summary>
    [SecurityCritical(SecurityCriticalScope.Everything)]
    internal sealed class SafeCertificateContextHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeCertificateContextHandle()
            : base(true)
        {
        }

        [DllImport("crypt32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release method")]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        protected override bool ReleaseHandle()
        {
            return CertFreeCertificateContext(handle);
        }
    }
}
