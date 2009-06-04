// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using Security.Cryptography.X509Certificates;

namespace Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The CngKeyExtensionMethods class provides several extension methods for the
    ///         <see cref="CngKey" />.  This type is in the Security.Cryptography namespace (not the
    ///         System.Security.Cryptography namespace), so in order to use these extension methods, you will
    ///         need to make sure you include this namespace as well as a reference to
    ///         Security.Cryptography.dll.
    ///     </para>
    ///     <para>
    ///         CngKey uses the NCrypt layer of CNG, and requires Windows Vista and the .NET Framework 3.5.
    ///     </para>
    /// </summary>
    public static class CngKeyExtensionMethods
    {
        /// <summary>
        ///     CreateSelfSignedCertificate creates a new self signed certificate issued to the specified
        ///     subject. The certificate will contain the key used to create the self signed certificate.
        ///     Since the certificate needs to be signed, the CngKey used must be usable for signing, which
        ///     means it must also contain a private key. If there is no private key, the operation will fail
        ///     with a CryptographicException indicating that "The key does not exist."
        /// </summary>
        /// <param name="key">key to wrap in a self signed certificate</param>
        /// <param name="subjectName">the name of hte subject the self-signed certificate will be issued to</param>
        /// <exception cref="ArgumentNullException">if <paramref name="subjectName" /> is null</exception>
        /// <exception cref="CryptographicException">if the certificate cannot be created</exception>
        public static X509Certificate2 CreateSelfSignedCertificate(this CngKey key,
                                                                   X500DistinguishedName subjectName)
        {
            return CreateSelfSignedCertificate(key, new X509CertificateCreationParameters(subjectName));
        }

        /// <summary>
        ///     CreateSelfSignedCertificate creates a new self signed certificate issued to the specified
        ///     subject. The certificate will contain the key used to create the self signed certificate.
        ///     Since the certificate needs to be signed, the CngKey used must be usable for signing, which
        ///     means it must also contain a private key. If there is no private key, the operation will fail
        ///     with a CryptographicException indicating that "The key does not exist."
        /// </summary>
        /// <param name="key">key to wrap in a self signed certificate</param>
        /// <param name="creationParameters">parameters to customize the self-signed certificate</param>
        /// <exception cref="ArgumentNullException">if <paramref name="creationParameters" /> is null</exception>
        /// <exception cref="CryptographicException">if the certificate cannot be created</exception>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of LinkDemand protected methods")]
        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Justification = "Used in a CER block with AddRef and Release")]
        public static X509Certificate2 CreateSelfSignedCertificate(this CngKey key,
                                                                   X509CertificateCreationParameters creationParameters)
        {
            if (creationParameters == null)
                throw new ArgumentNullException("creationParameters");

            using (SafeNCryptKeyHandle keyHandle = key.Handle)
            {
                using (SafeCertContextHandle selfSignedCertHandle =
                    X509Native.CreateSelfSignedCertificate(keyHandle,
                                                           creationParameters.SubjectName.RawData,
                                                           creationParameters.CertificateCreationOptions,
                                                           X509Native.MapCertificateSignatureAlgorithm(creationParameters.SignatureAlgorithm),
                                                           creationParameters.StartTime,
                                                           creationParameters.EndTime,
                                                           creationParameters.ExtensionsNoDemand))
                {
                    // We need to get the raw handle out of the safe handle because X509Certificate2 only
                    // exposes an IntPtr constructor.  To do that we'll temporarially bump the ref count on
                    // the handle.
                    //
                    // X509Certificate2 will duplicate the handle value in the .ctor, so once we've created
                    // the certificate object, we can safely drop the ref count and dispose of our handle.
                    bool addedRef = false;
                    RuntimeHelpers.PrepareConstrainedRegions();
                    try
                    {
                        selfSignedCertHandle.DangerousAddRef(ref addedRef);
                        return new X509Certificate2(selfSignedCertHandle.DangerousGetHandle());
                    }
                    finally
                    {
                        if (addedRef)
                        {
                            selfSignedCertHandle.DangerousRelease();
                        }
                    }
                }
            }
        }
    }
}
