// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Security.Cryptography
{
    //
    // Public facing enumerations
    //

    /// <summary>
    ///     Padding modes 
    /// </summary>
    [SuppressMessage("Microsoft.Design", "CA1027:MarkEnumsWithFlags", Justification = "Public use of the enum is not as flags")]
    [SuppressMessage("Microsoft.Design", "CA1008:EnumsShouldHaveZeroValue", Justification = "The native BCRYPT_PAD_NONE value is 1, not 0, and this is for interop.")]
    public enum AsymmetricPaddingMode
    {
        /// <summary>
        ///     No padding
        /// </summary>
        None = 1,                       // BCRYPT_PAD_NONE

        /// <summary>
        ///     PKCS #1 padding
        /// </summary>
        Pkcs1 = 2,                      // BCRYPT_PAD_PKCS1

        /// <summary>
        ///     Optimal Asymmetric Encryption Padding
        /// </summary>
        Oaep = 4,                       // BCRYPT_PAD_OAEP

        /// <summary>
        ///     Probabilistic Signature Scheme padding
        /// </summary>
        Pss = 8                         // BCRYPT_PAD_PSS
    }

    /// <summary>
    ///     Native wrappers for bcrypt CNG APIs.
    ///     
    ///     The general pattern for this interop layer is that the BCryptNative type exports a wrapper method
    ///     for consumers of the interop methods.  This wrapper method puts a managed face on the raw
    ///     P/Invokes, by translating from native structures to managed types and converting from error
    ///     codes to exceptions.
    /// </summary>
    internal static class BCryptNative
    {
        //
        // Enumerations
        //

        /// <summary>
        ///     Well known algorithm names
        /// </summary>
        internal static class AlgorithmName
        {
            internal const string Aes = "AES";                          // BCRYPT_AES_ALGORITHM
            internal const string Rng = "RNG";                          // BCRYPT_RNG_ALGORITHM
            internal const string Rsa = "RSA";                          // BCRYPT_RSA_ALGORITHM
            internal const string TripleDes = "3DES";                   // BCRYPT_3DES_ALOGORITHM
        }

        /// <summary>
        ///     Well known chaining modes
        /// </summary>
        internal static class ChainingMode
        {
            internal const string Cbc = "ChainingModeCBC";              // BCRYPT_CHAIN_MODE_CBC
            internal const string Cfb = "ChainingModeCFB";              // BCRYPT_CHAIN_MODE_CFB
            internal const string Ecb = "ChainingModeECB";              // BCRYPT_CHAIN_MODE_ECB
        }

        /// <summary>
        ///     Result codes from BCrypt APIs
        /// </summary>
        internal enum ErrorCode
        {
            Success = 0x00000000,                                       // STATUS_SUCCESS
            BufferToSmall = unchecked((int)0xC0000023),                 // STATUS_BUFFER_TOO_SMALL
        }

        /// <summary>
        ///     Magic numbers for different key blobs
        /// </summary>
        internal enum KeyBlobMagicNumber
        {
            RsaPublic = 0x31415352,                                     // BCRYPT_RSAPUBLIC_MAGIC
            RsaPrivate = 0x32415352,                                    // BCRYPT_RSAPRIVATE_MAGIC
            KeyDataBlob = 0x4d42444b,                                   // BCRYPT_KEY_DATA_BLOB_MAGIC
        }

        /// <summary>
        ///     Well known key blob tyes
        /// </summary>
        internal static class KeyBlobType
        {
            internal const string KeyDataBlob = "KeyDataBlob";                  // BCRYPT_KEY_DATA_BLOB
            internal const string RsaFullPrivateBlob = "RSAFULLPRIVATEBLOB";    // BCRYPT_RSAFULLPRIVATE_BLOB
            internal const string RsaPrivateBlob = "RSAPRIVATEBLOB";            // BCRYPT_RSAPRIVATE_BLOB
            internal const string RsaPublicBlob = "RSAPUBLICBLOB";              // BCRYPT_PUBLIC_KEY_BLOB
        }

        /// <summary>
        ///     Well known BCrypt object property names
        /// </summary>
        internal static class ObjectPropertyName
        {
            internal const string BlockLength = "BlockLength";          // BCRYPT_BLOCK_LENGTH
            internal const string ChainingMode = "ChainingMode";        // BCRYPT_CHAINING_MODE
            internal const string InitializationVector = "IV";          // BCRYPT_INITIALIZATION_VECTOR
            internal const string KeyLength = "KeyLength";              // BCRYPT_KEY_LENGTH
            internal const string ObjectLength = "ObjectLength";        // BCRYPT_OBJECT_LENGTH
        }

        /// <summary>
        ///     Well known BCrypt provider names
        /// </summary>
        internal static class ProviderName
        {
            internal const string MicrosoftPrimitiveProvider = "Microsoft Primitive Provider";      // MS_PRIMITIVE_PROVIDER
        }

        //
        // Structures
        //

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_KEY_DATA_BLOB
        {
            internal KeyBlobMagicNumber dwMagic;
            internal int dwVersion;
            internal int cbKeyData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_OAEP_PADDING_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pszAlgId;

            internal IntPtr pbLabel;

            internal int cbLabel;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_PKCS1_PADDING_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pszAlgId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_PSS_PADDING_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pszAlgId;

            internal int cbSalt;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_RSAKEY_BLOB
        {
            internal KeyBlobMagicNumber Magic;
            internal int BitLength;
            internal int cbPublicExp;
            internal int cbModulus;
            internal int cbPrime1;
            internal int cbPrime2;
        }

        //
        // P/Invokes
        //

        [SecurityCritical(SecurityCriticalScope.Everything)]
        [SuppressUnmanagedCodeSecurity]
        private static class UnsafeNativeMethods
        {
            [DllImport("bcrypt.dll")]
            internal static extern ErrorCode BCryptDecrypt(SafeBCryptKeyHandle hKey,
                                                           [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                           int cbInput,
                                                           IntPtr pPaddingInfo,
                                                           [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbIV,
                                                           int cbIV,
                                                           [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                                           int cbOutput,
                                                           [Out] out int pcbResult,
                                                           int dwFlags);

            [DllImport("bcrypt.dll")]
            internal static extern ErrorCode BCryptEncrypt(SafeBCryptKeyHandle hKey,
                                                           [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                           int cbInput,
                                                           IntPtr pPaddingInfo,
                                                           [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbIV,
                                                           int cbIV,
                                                           [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                                           int cbOutput,
                                                           [Out] out int pcbResult,
                                                           int dwFlags);

            [DllImport("bcrypt.dll")]
            internal static extern ErrorCode BCryptGenRandom(SafeBCryptAlgorithmHandle hAlgorithm,
                                                             [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbBuffer,
                                                             int cbBuffer,
                                                             int dwFlags);

            [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty")]
            internal static extern ErrorCode BCryptGetAlgorithmProperty(SafeBCryptAlgorithmHandle hObject,
                                                                        [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
                                                                        [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                                                        int cbOutput,
                                                                        [In, Out] ref int pcbResult,
                                                                        int flags);

            [DllImport("bcrypt.dll")]
            internal static extern ErrorCode BCryptImportKey(SafeBCryptAlgorithmHandle hAlgorithm,
                                                             IntPtr hImportKey,
                                                             [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                             [Out] out SafeBCryptKeyHandle phKey,
                                                             [In, Out] IntPtr pbKeyObject,          // BYTE *
                                                             int cbKeyObject,
                                                             [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                             int cbInput,
                                                             int dwFlags);
                                                 
            [DllImport("bcrypt.dll")]
            internal static extern ErrorCode BCryptOpenAlgorithmProvider([Out] out SafeBCryptAlgorithmHandle phAlgorithm,
                                                                         [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
                                                                         [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
                                                                         int dwFlags);

            [DllImport("bcrypt.dll", EntryPoint = "BCryptSetProperty")]
            internal static extern ErrorCode BCryptSetAlgorithmProperty(SafeBCryptAlgorithmHandle hObject,
                                                                        [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
                                                                        [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                                        int cbInput,
                                                                        int dwFlags);
        }

        /// <summary>
        ///     Adapter to wrap specific BCryptGetProperty P/Invokes with a generic BCrypt handle type
        /// </summary>
        [SecurityCritical]
        private delegate ErrorCode BCryptPropertyGetter<T>(T hObject,
                                                           string pszProperty,
                                                           byte[] pbOutput,
                                                           int cbOutput,
                                                           ref int pcbResult,
                                                           int dwFlags) where T : SafeHandle;

        /// <summary>
        ///     Adapter to wrap specific BCryptSetProperty P/Invokes with a generic BCrypt handle type
        /// </summary>
        [SecurityCritical]
        private delegate ErrorCode BCryptPropertySetter<T>(T hObject,
                                                           string pszProperty,
                                                           byte[] pbInput,
                                                           int cbInput,
                                                           int dwFlags) where T : SafeHandle;

        //
        // Wrapper APIs
        //

        /// <summary>
        ///     Fill a buffer with radom bytes
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        internal static void GenerateRandomBytes(SafeBCryptAlgorithmHandle algorithm, byte[] buffer)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(!algorithm.IsClosed && !algorithm.IsInvalid, "!algorithm.IsClosed && !algorithm.IsInvalid");
            Debug.Assert(buffer != null, "buffer != null");

            ErrorCode error = UnsafeNativeMethods.BCryptGenRandom(algorithm,
                                                                  buffer,
                                                                  buffer.Length,
                                                                  0);
            if (error != ErrorCode.Success)
            {
                throw new CryptographicException((int)error);
            }
        }

        /// <summary>
        ///     Get an integer valued named property from a BCrypt object.
        /// </summary>
        [SecurityCritical]
        internal static int GetInt32Property<T>(T bcryptObject, string property) where T : SafeHandle
        {
            Debug.Assert(bcryptObject != null, "bcryptObject != null");
            Debug.Assert(!bcryptObject.IsClosed && !bcryptObject.IsInvalid, "!bcryptObject.IsClosed && !bcryptObject.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(property), "!String.IsNullOrEmpty(property)");

            return BitConverter.ToInt32(GetProperty(bcryptObject, property), 0);
        }

        /// <summary>
        ///     Get a string valued named property from a BCrypt object
        /// </summary>
        [SecurityCritical]
        internal static string GetStringProperty<T>(T bcryptObject, string property) where T : SafeHandle
        {
            Debug.Assert(bcryptObject != null, "bcryptObject != null");
            Debug.Assert(!bcryptObject.IsClosed && !bcryptObject.IsInvalid, "!bcryptObject.IsClosed && !bcryptObject.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(property), "!String.IsNullOrEmpty(property)");

            byte[] rawProperty = GetProperty(bcryptObject, property);

            if (rawProperty == null)
            {
                return null;
            }
            else if (rawProperty.Length == 0)
            {
                return string.Empty;
            }
            else
            {
                unsafe
                {
                    fixed (byte *pPropertyBytes = rawProperty)
                    {
                        return Marshal.PtrToStringUni(new IntPtr(pPropertyBytes));
                    }
                }
            }
        }

        /// <summary>
        ///     Get the value of a named property from a BCrypt object
        /// </summary>
        [SecurityCritical]
        internal static byte[] GetProperty<T>(T bcryptObject, string property) where T : SafeHandle
        {
            Debug.Assert(bcryptObject != null, "bcryptObject != null");
            Debug.Assert(!bcryptObject.IsClosed && !bcryptObject.IsInvalid, "!bcryptObject.IsClosed && !bcryptObject.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(property), "!String.IsNullOrEmpty(property)");

            // Figure out which P/Invoke to use for the specific SafeHandle type we were given. For now we
            // only need to get properties of BCrypt algorithms, so we only check for SafeBCryptAlgorithmHandles.
            BCryptPropertyGetter<T> propertyGetter = null;
            if (typeof(T) == typeof(SafeBCryptAlgorithmHandle))
            {
                propertyGetter = new BCryptPropertyGetter<SafeBCryptAlgorithmHandle>(UnsafeNativeMethods.BCryptGetAlgorithmProperty) as BCryptPropertyGetter<T>;
            }

            Debug.Assert(propertyGetter != null, "Unknown bcrypt object type");

            // Figure out how big of a buffer is needed to hold the property
            int propertySize = 0;
            ErrorCode error = propertyGetter(bcryptObject, property, null, 0, ref propertySize, 0);
            if (error != ErrorCode.Success && error != ErrorCode.BufferToSmall)
            {
                throw new CryptographicException((int)error);
            }

            // Get the property value
            byte[] propertyValue = new byte[propertySize];
            error = propertyGetter(bcryptObject,
                                   property,
                                   propertyValue,
                                   propertyValue.Length,
                                   ref propertySize,
                                   0);
            if (error != ErrorCode.Success)
            {
                throw new CryptographicException((int)error);
            }

            return propertyValue;
        }

        /// <summary>
        ///     Import a raw symmetric key into a key handle
        /// </summary>
        [SecurityCritical]
        internal static SafeBCryptKeyHandle ImportSymmetricKey(SafeBCryptAlgorithmHandle algorithm, byte[] key)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(!algorithm.IsClosed && !algorithm.IsInvalid, "!algorithm.IsClosed && !algorithm.IsInvalid");
            Debug.Assert(key != null, "buffer != null");

            IntPtr keyDataBuffer = IntPtr.Zero;
            SafeBCryptKeyHandle keyHandle = null;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Build up the key blob structure in memory.  BCryptImportKey requries a
                // BCRYPT_KEY_DATA_BLOB header immediately followed by the raw key data.
                byte[] keyBlob = new byte[Marshal.SizeOf(typeof(BCRYPT_KEY_DATA_BLOB)) + key.Length];
                unsafe
                {
                    fixed (byte* pbKeyBlob = keyBlob)
                    {
                        BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)pbKeyBlob;
                        pkeyDataBlob->dwMagic = KeyBlobMagicNumber.KeyDataBlob;
                        pkeyDataBlob->dwVersion = 1;
                        pkeyDataBlob->cbKeyData = key.Length;
                    }
                }
                Buffer.BlockCopy(key, 0, keyBlob, Marshal.SizeOf(typeof(BCRYPT_KEY_DATA_BLOB)), key.Length);

                // Figure out how big of a key data buffer we need and allocate space on the native heap for
                // it.  We cannot use a managed array here because the address needs to stay constant for
                // the lifetime of the algorithm handle.  Pinning for a potentially long lifetime is
                // undesirable, so we use a native heap allocation instead.
                int keyDataSize = GetInt32Property(algorithm, ObjectPropertyName.ObjectLength);
                keyDataBuffer = Marshal.AllocCoTaskMem(keyDataSize);

                // Import the key
                ErrorCode error = UnsafeNativeMethods.BCryptImportKey(algorithm,
                                                                      IntPtr.Zero,
                                                                      KeyBlobType.KeyDataBlob,
                                                                      out keyHandle,
                                                                      keyDataBuffer,
                                                                      keyDataSize,
                                                                      keyBlob,
                                                                      keyBlob.Length,
                                                                      0);
                if (error != ErrorCode.Success)
                {
                    throw new CryptographicException((int)error);
                }

                // Give the key ownership of the key data buffer
                keyHandle.KeyDataBuffer = keyDataBuffer;

                return keyHandle;
            }
            finally
            {
                // If we allocated a key data buffer, but never transfered ownership to the key handle, then
                // we need to free it now otherwise it will leak.
                if (keyDataBuffer != IntPtr.Zero && keyHandle.KeyDataBuffer == IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(keyDataBuffer);
                }
            }
        }

        /// <summary>
        ///     Map a managed cipher mode to a BCrypt chaining mode
        /// </summary>
        internal static string MapChainingMode(CipherMode mode)
        {
            switch (mode)
            {
                case CipherMode.CBC:
                    return ChainingMode.Cbc;
                case CipherMode.CFB:
                    return ChainingMode.Cfb;
                case CipherMode.ECB:
                    return ChainingMode.Ecb;
                default:
                    throw new ArgumentException(Properties.Resources.UnsupportedCipherMode, "mode");
            }
        }

        /// <summary>
        ///     Map a BCrypt chaining mode to a managed cipher mode
        /// </summary>
        internal static CipherMode MapChainingMode(string mode)
        {
            Debug.Assert(mode != null, "mode != null");

            if (String.Equals(mode, ChainingMode.Cbc, StringComparison.Ordinal))
            {
                return CipherMode.CBC;
            }
            else if (String.Equals(mode, ChainingMode.Cfb, StringComparison.Ordinal))
            {
                return CipherMode.CFB;
            }
            else if (String.Equals(mode, ChainingMode.Ecb, StringComparison.Ordinal))
            {
                return CipherMode.ECB;
            }
            else
            {
                throw new ArgumentException(Properties.Resources.UnsupportedCipherMode, "mode");
            }
        }

        /// <summary>
        ///     Open a handle to a BCrypt algorithm provider
        /// </summary>
        [SecurityCritical]
        internal static SafeBCryptAlgorithmHandle OpenAlgorithm(string algorithm, string implementation)
        {
            Debug.Assert(!String.IsNullOrEmpty(algorithm), "!String.IsNullOrEmpty(algorithm)");
            Debug.Assert(!String.IsNullOrEmpty(implementation), "!String.IsNullOrEmpty(implementation)");

            SafeBCryptAlgorithmHandle algorithmHandle = null;
            ErrorCode error = UnsafeNativeMethods.BCryptOpenAlgorithmProvider(out algorithmHandle,
                                                                              algorithm,
                                                                              implementation,
                                                                              0);
            if (error != ErrorCode.Success)
            {
                throw new CryptographicException((int)error);
            }

            return algorithmHandle;
        }

        /// <summary>
        ///     Set an integer valued property on a BCrypt object
        /// </summary>
        [SecurityCritical]
        internal static void SetInt32Property<T>(T bcryptObject, string property, int value) where T : SafeHandle
        {
            Debug.Assert(bcryptObject != null, "bcryptObject != null");
            Debug.Assert(!bcryptObject.IsClosed && !bcryptObject.IsInvalid, "!bcryptObject.IsClosed && !bcryptObject.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(property), "!String.IsNullOrEmpty(property)");

            SetProperty(bcryptObject, property, BitConverter.GetBytes(value));
        }

        /// <summary>
        ///     Set a string valued property on a BCrypt object
        /// </summary>
        [SecurityCritical]
        internal static void SetStringProperty<T>(T bcryptObject, string property, string value) where T : SafeHandle
        {
            Debug.Assert(bcryptObject != null, "bcryptObject != null");
            Debug.Assert(!bcryptObject.IsClosed && !bcryptObject.IsInvalid, "!bcryptObject.IsClosed && !bcryptObject.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(property), "!String.IsNullOrEmpty(property)");
            Debug.Assert(value != null, "value != null");

            SetProperty(bcryptObject, property, Encoding.Unicode.GetBytes(value));
        }

        /// <summary>
        ///     Set a named property value on a BCrypt object
        /// </summary>
        [SecurityCritical]
        internal static void SetProperty<T>(T bcryptObject, string property, byte[] value) where T : SafeHandle
        {
            Debug.Assert(bcryptObject != null, "bcryptObject != null");
            Debug.Assert(!bcryptObject.IsClosed && !bcryptObject.IsInvalid, "!bcryptObject.IsClosed && !bcryptObject.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(property), "!String.IsNullOrEmpty(property)");
            Debug.Assert(value != null, "value != null");

            // Figure out which P/Invoke to use for the specific handle type we were given. For now we
            // only need to set properties of BCrypt algorithms, so we only check for SafeBCryptAlgorithmHandles.
            BCryptPropertySetter<T> propertySetter = null;
            if (typeof(T) == typeof(SafeBCryptAlgorithmHandle))
            {
                propertySetter = new BCryptPropertySetter<SafeBCryptAlgorithmHandle>(UnsafeNativeMethods.BCryptSetAlgorithmProperty) as BCryptPropertySetter<T>;
            }

            Debug.Assert(propertySetter != null, "Unknown object type");

            // Set the property
            ErrorCode error = propertySetter(bcryptObject,
                                             property,
                                             value,
                                             value.Length,
                                             0);
            if (error != ErrorCode.Success)
            {
                throw new CryptographicException((int)error);
            }
        }

        /// <summary>
        ///     Decrypt some blocks of data
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        internal static byte[] SymmetricDecrypt(SafeBCryptKeyHandle key, byte[] iv, byte[] input)
        {
            Debug.Assert(key != null, "key != null");
            Debug.Assert(!key.IsClosed && !key.IsInvalid, "!key.IsClosed && !key.IsInvalid");
            Debug.Assert(input != null, "input != null");

            // Do the decryption
            byte[] output = new byte[input.Length];
            int outputSize = 0;
            ErrorCode error = UnsafeNativeMethods.BCryptDecrypt(key,
                                                                input,
                                                                input.Length,
                                                                IntPtr.Zero,
                                                                iv,
                                                                iv != null ? iv.Length : 0,
                                                                output,
                                                                output.Length,
                                                                out outputSize,
                                                                0);
            if (error != ErrorCode.Success)
            {
                throw new CryptographicException((int)error);
            }

            // If we didn't use the whole output array, trim down to the portion that was used
            if (outputSize != output.Length)
            {
                byte[] trimmedOutput = new byte[outputSize];
                Buffer.BlockCopy(output, 0, trimmedOutput, 0, trimmedOutput.Length);
                output = trimmedOutput;
            }

            return output;
        }

        /// <summary>
        ///     Encrypt some blocks of data
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        internal static byte[] SymmetricEncrypt(SafeBCryptKeyHandle key, byte[] iv, byte[] input)
        {
            Debug.Assert(key != null, "key != null");
            Debug.Assert(!key.IsClosed && !key.IsInvalid, "!key.IsClosed && !key.IsInvalid");
            Debug.Assert(input != null, "input != null");

            // Do the encryption
            byte[] output = new byte[input.Length];
            int outputSize = 0;
            ErrorCode error = UnsafeNativeMethods.BCryptEncrypt(key,
                                                                input,
                                                                input.Length,
                                                                IntPtr.Zero,
                                                                iv,
                                                                iv != null ? iv.Length : 0,
                                                                output,
                                                                output.Length,
                                                                out outputSize,
                                                                0);
            if (error != ErrorCode.Success)
            {
                throw new CryptographicException((int)error);
            }

            // If we didn't use the whole output array, trim down to the portion that was used
            if (outputSize != output.Length)
            {
                byte[] trimmedOutput = new byte[outputSize];
                Buffer.BlockCopy(output, 0, trimmedOutput, 0, trimmedOutput.Length);
                output = trimmedOutput;
            }

            return output;
        }
    }

    /// <summary>
    ///     SafeHandle for a native BCRYPT_ALG_HANDLE
    /// </summary>
    [SecurityCritical(SecurityCriticalScope.Everything)]
    internal sealed class SafeBCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeBCryptAlgorithmHandle() : base(true)
        {
            return;
        }

        [DllImport("bcrypt.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release P/Invoke")]
        private static extern BCryptNative.ErrorCode BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags);

        protected override bool ReleaseHandle()
        {
            return BCryptCloseAlgorithmProvider(handle, 0) == BCryptNative.ErrorCode.Success;
        }
    }

    /// <summary>
    ///     SafeHandle for a native BCRYPT_KEY_HANDLE.
    ///     
    ///     Since BCrypt keys require a buffer for object data, this safe handle owns two resources - the
    ///     BCRYPT_KEY_HANDLE itself, along with a buffer on the native heap which was allocated with
    ///     CoAllocTaskMem.
    ///     
    ///     This is required rather than having a seperate safe handle own the key data buffer blob so
    ///     that we can ensure that the key handle is disposed of before the key data buffer is freed.
    /// </summary>
    [SecurityCritical(SecurityCriticalScope.Everything)]
    internal sealed class SafeBCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private IntPtr m_keyDataBuffer;

        private SafeBCryptKeyHandle() : base(true)
        {
            return;
        }

        [DllImport("bcrypt.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release P/Invoke")]
        private static extern BCryptNative.ErrorCode BCryptDestroyKey(IntPtr hKey);

        public override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero &&             // The BCRYPT_KEY_HANDLE is not valid
                       m_keyDataBuffer == IntPtr.Zero;      // And we don't own any native memory
            }
        }

        /// <summary>
        ///     Buffer that holds onto the key data object. This data must be allocated with CoAllocTaskMem.
        ///     Once the buffer is assigned into the KeyDataBuffer property, the safe handle owns the buffer
        ///     and users of this property should not attempt to free the memory.
        ///     
        ///     This property should be set only once, otherwise the first data buffer will leak.
        /// </summary>
        internal IntPtr KeyDataBuffer
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            get { return m_keyDataBuffer; }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            set
            {
                Debug.Assert(m_keyDataBuffer == IntPtr.Zero, "SafeBCryptKeyHandle already owns a data buffer - this will result in a native memory leak.");
                Debug.Assert(value != IntPtr.Zero, "value != IntPtr.Zero"); 

                m_keyDataBuffer = value;
            }
        }

        protected override bool ReleaseHandle()
        {
            BCryptNative.ErrorCode error = BCryptNative.ErrorCode.Success;

            if (handle != IntPtr.Zero)
            {
                error = BCryptDestroyKey(handle);
            }

            if (m_keyDataBuffer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(m_keyDataBuffer);
            }

            return error == BCryptNative.ErrorCode.Success;
        }
    }
}
