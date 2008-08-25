// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Signature description type for the http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 signature
    ///     type. Registering this type allows XML digitial signatures to be created and verified using
    ///     RSA-SHA256 signatures.
    ///     
    ///     This description can be registered in machine.config in a section similar to:
    ///     <configuration>
    ///       <mscorlib>
    ///         <cryptographySettings>
    ///           <cryptoNameMapping>
    ///             <cryptoClasses>
    ///               <cryptoClass RSASHA256SignatureDescription="Security.Cryptography.RSAPKCS1SHA256SignatureDescription, Security.Cryptography, Version=1.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
    ///             </cryptoClasses>
    ///             <nameEntry name="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" class="RSASHA256SignatureDescription" />
    ///           </cryptoNameMapping>
    ///         </cryptographySettings>
    ///       </mscorlib>
    ///     </configuration>
    ///     
    ///     Where the assembly name is update to refer to the assembly the signature description is hosted in.
    ///     
    ///     This signature description type requires .NET 3.5 SP 1 and Windows 2003 or higher in order to work.
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSAPKCS", Justification = "This casing is to match the existing RSAPKCS1SHA1SignatureDescription type")]
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA", Justification = "This casing is to match the use of SHA throughout the framework")]
    public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        public RSAPKCS1SHA256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName;   // Note - SHA256CryptoServiceProvider is not registered with CryptoConfig
            FormatterAlgorithm = typeof (RSAPKCS1SignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }
    }
}

