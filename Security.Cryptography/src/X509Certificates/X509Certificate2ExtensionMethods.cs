// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Permissions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     Extension methods for the X509Certificate2 type
    /// </summary>
    public static class X509Certificate2ExtensionMethods
    {
        /// <summary>
        ///     Get the private key of a certificate that has its key stored with NCrypt
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of LinkDemand methods")]
        public static CngKey GetCngPrivateKey(this X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey || !certificate.HasCngKey())
            {
                return null;
            }

            using (SafeNCryptKeyHandle privateKeyHandle = X509Native.AcquireCngPrivateKey(certificate.Handle))
            {
                // We need to assert for full trust when opening the CNG key because
                // CngKey.Open(SafeNCryptKeyHandle) does a full demand for full trust, and we want to allow
                // access to a certificate's private key by anyone who has access to the certificate itself.
                new PermissionSet(PermissionState.Unrestricted).Assert();
                return CngKey.Open(privateKeyHandle, CngKeyHandleOpenOptions.None);
            }
        }
    }
}
