// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;

namespace Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     The CertificateCreationOptions type provides the inputs used to create an X509Certificate2.
    ///     These parameters can be combined with a key to create a self signed certificate.
    /// </summary>
    public sealed class X509CertificateCreationParameters
    {
        private X500DistinguishedName m_subjectName;
        private X509CertificateCreationOptions m_certificateCreationOptions = X509CertificateCreationOptions.DoNotLinkKeyInformation;
        private X509CertificateSignatureAlgorithm m_signatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha1;
        private DateTime m_endTime = DateTime.UtcNow.AddYears(1);
        private DateTime m_startTime = DateTime.UtcNow;
        private X509ExtensionCollection m_extensions = new X509ExtensionCollection();

        public X509CertificateCreationParameters(X500DistinguishedName subjectName)
        {
            if (subjectName == null)
                throw new ArgumentNullException("subjectName");

            m_subjectName = new X500DistinguishedName(subjectName);
        }

        /// <summary>
        ///     Flags to use when creating the certificate
        /// </summary>
        public X509CertificateCreationOptions CertificateCreationOptions
        {
            get { return m_certificateCreationOptions; }
            set { m_certificateCreationOptions = value; }
        }

        /// <summary>
        ///     Time that the certificate stops being valid
        /// </summary>
        public DateTime EndTime
        {
            get { return m_endTime; }
            set { m_endTime = value; }
        }

        /// <summary>
        ///     Extensions to apply to the certificate
        /// </summary>
        public X509ExtensionCollection Extensions
        {
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            [SecurityCritical]
            [SecurityTreatAsSafe]
            get
            {
                return ExtensionsNoDemand;
            }
        }

        internal X509ExtensionCollection ExtensionsNoDemand
        {
            [SecurityCritical]
            get
            {
                return m_extensions;
            }
        }

        /// <summary>
        ///     Algorithm the certificate will be signed with
        /// </summary>
        public X509CertificateSignatureAlgorithm SignatureAlgorithm
        {
            get { return m_signatureAlgorithm; }

            set
            {
                if (value < X509CertificateSignatureAlgorithm.RsaSha1 ||
                    value > X509CertificateSignatureAlgorithm.RsaSha512)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                m_signatureAlgorithm = value;
            }
        }

        /// <summary>
        ///     Name of the certificate subject
        /// </summary>
        public X500DistinguishedName SubjectName
        {
            get { return new X500DistinguishedName(m_subjectName); }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_subjectName = new X500DistinguishedName(value);
            }
        }

        /// <summary>
        ///     Time that the certificate will become valid
        /// </summary>
        public DateTime StartTime
        {
            get { return m_startTime; }
            set { m_startTime = value; }
        }
    }
}
