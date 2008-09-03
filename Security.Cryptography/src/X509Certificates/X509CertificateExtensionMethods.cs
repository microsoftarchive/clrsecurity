// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Security.Cryptography.X509Certificates;

namespace Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     Extension methods for the X509Certificate type
    /// </summary>
    public static class X509CertificateExtensionMethods
    {
        /// <summary>
        ///     Determine if a certificate's key is a CNG key instead of a CAPI key
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of LinkDemand members")]
        public static bool HasCngKey(this X509Certificate certificate)
        {
            if (X509Native.HasCertificateProperty(certificate.Handle,
                                                  X509Native.CertificateProperty.KeyProviderInfo))
            {
                X509Native.CERT_KEY_PROV_INFO keyProvInfo =
                    X509Native.GetCertificateProperty<X509Native.CERT_KEY_PROV_INFO>(certificate.Handle, X509Native.CertificateProperty.KeyProviderInfo);

                return keyProvInfo.dwProvType == 0;
            }
            else
            {
                return false;
            }
        }
    }
}
