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
    ///     Extension methods for the CngKey class
    /// </summary>
    public static class CngKeyExtensionMethods
    {
        /// <summary>
        ///     Create a self signed certificate for this key, issued to the given subject
        /// </summary>
        public static X509Certificate2 CreateSelfSignedCertificate(this CngKey key,
                                                                   X500DistinguishedName subjectName)
        {
            return CreateSelfSignedCertificate(key, new X509CertificateCreationParameters(subjectName));
        }

        /// <summary>
        ///     Create a self signed certificate for this key, using the given creation parameters to
        ///     configure the certificate.
        /// </summary>
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
