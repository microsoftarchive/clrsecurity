// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace Security.Cryptography
{
    /// <summary>
    ///     Enhanced OID type over the System.Security.Cryptography.Oid type.  Oid2 provides some
    ///     performance benefits when it is used to lookup OID information since it can do more directed
    ///     queries than Oid does.  It also exposes additional information about the OID, such as group and
    ///     algortihm mappings for CAPI and CNG.
    ///     
    ///     Constructing an Oid2 object does not do lookup as constructing an Oid object does - instead
    ///     specific queries must be issued in order to do lookups on OID inputs.
    /// </summary>
    public sealed class Oid2
    {
        private string m_oid;
        private string m_name;
        private OidGroup m_group;

        // Algorithm identifiers for both CAPI and CNG for CRYPT_*_ALG_OID_GROUP_ID OIDs
        private int? m_algorithmId;
        private CngAlgorithm m_cngAlgorithm;    
        private CngAlgorithm m_cngExtraAlgorithm;

        /// <summary>
        ///     Create an Oid2 object for an OID with no algorithm representation and in no particular group
        /// </summary>
        public Oid2(string oid, string friendlyName)
            : this(oid, friendlyName, OidGroup.AllGroups)
        {
            return;
        }

        /// <summary>
        ///     Create an Oid2 object for an OID with no algorithm representation
        /// </summary>
        public Oid2(string oid, string friendlyName, OidGroup group)
            : this (oid, friendlyName, group, null, null)
        {
            return;
        }

        /// <summary>
        ///     Create an Oid2 object for an OID which has no CAPI algorithm representation
        /// </summary>
        public Oid2(string oid,
                    string friendlyName,
                    OidGroup group,
                    CngAlgorithm cngAlgorithm,
                    CngAlgorithm extraCngAlgorithm)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");
            if (friendlyName == null)
                throw new ArgumentNullException("friendlyName");

            m_oid = oid;
            m_name = friendlyName;
            m_group = group;
            m_cngAlgorithm = cngAlgorithm;
            m_cngExtraAlgorithm = extraCngAlgorithm;
        }

        /// <summary>
        ///     Create an Oid2 object for an OID which can have both a CAPI and CNG algorithm representation
        /// </summary>
        public Oid2(string oid,
                    string friendlyName,
                    OidGroup group,
                    int capiAlgorithm,
                    CngAlgorithm cngAlgorithm,
                    CngAlgorithm extraCngAlgorithm)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");
            if (friendlyName == null)
                throw new ArgumentNullException("friendlyName");

            m_oid = oid;
            m_name = friendlyName;
            m_group = group;
            m_algorithmId = capiAlgorithm;
            m_cngAlgorithm = cngAlgorithm;
            m_cngExtraAlgorithm = extraCngAlgorithm;
        }

        /// <summary>
        ///     Unpack a CAPI CRYPT_OID_INFO structure into an Oid2
        /// </summary>
        private Oid2(CapiNative.CRYPT_OID_INFO oidInfo)
        {
            m_oid = oidInfo.pszOID ?? String.Empty;
            m_name = oidInfo.pwszName ?? String.Empty;
            m_group = oidInfo.dwGroupId;

            // Algorithm information is only set for specific OID groups
            if (oidInfo.dwGroupId == OidGroup.EncryptionAlgorithm ||
                oidInfo.dwGroupId == OidGroup.HashAlgorithm ||
                oidInfo.dwGroupId == OidGroup.PublicKeyAlgorithm ||
                oidInfo.dwGroupId == OidGroup.SignatureAlgorithm)
            {
                // Values of 0 or -1 indicate that there is no CAPI algorithm mapping
                if (oidInfo.dwValue != 0 && oidInfo.dwValue != -1)
                {
                    m_algorithmId = oidInfo.dwValue;
                }

                if (!String.IsNullOrEmpty(oidInfo.pwszCNGAlgid))
                {
                    m_cngAlgorithm = new CngAlgorithm(oidInfo.pwszCNGAlgid);
                }

                if (!String.IsNullOrEmpty(oidInfo.pwszCNGExtraAlgid))
                {
                    m_cngExtraAlgorithm = new CngAlgorithm(oidInfo.pwszCNGExtraAlgid);
                }
            }
        }

        //
        // Acccessor properties
        //

        public int AlgorithmId
        {
            get { return m_algorithmId.Value; }
        }

        public CngAlgorithm CngAlgorithm
        {
            get { return m_cngAlgorithm; }
        }

        public CngAlgorithm CngExtraAlgorithm
        {
            get { return m_cngExtraAlgorithm; }
        }

        public string FriendlyName
        {
            get { return m_name; }
        }

        public OidGroup Group
        {
            get { return m_group; }
        }

        public bool HasAlgorithmId
        {
            get { return m_algorithmId.HasValue; }
        }

        public string Value
        {
            get { return m_oid; }
        }

        //
        // Utility methods
        //

        /// <summary>
        ///     Enumerate all the OIDs on the machine
        /// </summary>
        public static IEnumerable<Oid2> EnumerateOidInformation()
        {
            return EnumerateOidInformation(OidGroup.AllGroups);
        }

        /// <summary>
        ///     Enumerate the OIDs registered as belonging to a certain group
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public static IEnumerable<Oid2> EnumerateOidInformation(OidGroup group)
        {
            foreach (CapiNative.CRYPT_OID_INFO oidInfo in CapiNative.EnumerateOidInformation(group))
            {
                yield return new Oid2(oidInfo);
            }
        }

        /// <summary>
        ///     Search for an OID based upon its friendly name, looking in all groups
        /// </summary>
        public static Oid2 FindByFriendlyName(string friendlyName)
        {
            return FindByFriendlyName(friendlyName, OidGroup.AllGroups);
        }

        /// <summary>
        ///     Search for an OID based upon its friendly name, looking only in a specific group
        /// </summary>
        public static Oid2 FindByFriendlyName(string friendlyName, OidGroup group)
        {
            return FindByFriendlyName(friendlyName, group, false);
        }

        /// <summary>
        ///     Search for an OID based upon its friendly name, looking only in a specific group, optionally
        ///     looking for the value in Active Directory.
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public static Oid2 FindByFriendlyName(string friendlyName, OidGroup group, bool useNetworkLookup)
        {
            CapiNative.CRYPT_OID_INFO oidInfo = new CapiNative.CRYPT_OID_INFO();
            if (CapiNative.TryFindOidInfo(friendlyName, group, CapiNative.OidKeyType.Name, useNetworkLookup, out oidInfo))
            {
                return new Oid2(oidInfo);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        ///     Search for an OID based upon its OID value, looking in all groups
        /// </summary>
        public static Oid2 FindByValue(string oid)
        {
            return FindByValue(oid, OidGroup.AllGroups);
        }

        /// <summary>
        ///     Search for an OID based upon its OID value, looking only in a specific group
        /// </summary>
        public static Oid2 FindByValue(string oid, OidGroup group)
        {
            return FindByValue(oid, group, false);
        }

        /// <summary>
        ///     Search for an OID based upon its OID value, looking only in a specific group, optionally
        ///     looking for the value in Active Directory.
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        public static Oid2 FindByValue(string oid, OidGroup group, bool useNetworkLookup)
        {
            CapiNative.CRYPT_OID_INFO oidInfo = new CapiNative.CRYPT_OID_INFO();
            if (CapiNative.TryFindOidInfo(oid, group, CapiNative.OidKeyType.Oid, useNetworkLookup, out oidInfo))
            {
                return new Oid2(oidInfo);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        ///     Register an OID on the machine.  This requires the user to be an administrator on the
        ///     machine, and also may not take effect within the current process if the registered OIDs have
        ///     already been read in this process by CAPI.
        /// </summary>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public void Register()
        {
            Register(OidRegistrationOptions.None);
        }

        /// <summary>
        ///     Register an OID on the machine.  This requires the user to be an administrator on the
        ///     machine, and also may not take effect within the current process if the registered OIDs have
        ///     already been read in this process by CAPI.
        /// </summary>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public void Register(OidRegistrationOptions registrationOptions)
        {
            CapiNative.RegisterOid(ToOidInfo(), registrationOptions);
        }

        /// <summary>
        ///     Ensure that the OID -> ALG_ID mapping for the SHA2 algorithms is registered in a way that the
        ///     CLR can understand it for enabling RSA-SHA2 signatures.  Note that this operation requires
        ///     the user to be an administrator, and may also not take effect in the current process if the
        ///     registered OID information has already been read by CAPI.
        /// </summary>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public static void RegisterSha2OidInformationForRsa()
        {
            // On Windows 2003, the default ALGID -> OID mapping for the SHA2 comes back with an unknown
            // ALG_ID of 0.  The v2.0 CLR however expects unknown ALG_IDs to be mapped to -1, and therefore
            // fails to map this unknown value to the correct SHA-256 ALG_ID.  If we're on Windows 2003 and
            // CLR 2.0, we'll re-register the SHA-256 OID so that the CLR can pick it up.
            if (Environment.OSVersion.Platform == PlatformID.Win32NT &&
                Environment.OSVersion.Version.Major == 5 &&
                Environment.OSVersion.Version.Minor == 2 &&
                Environment.Version.Major == 2)
            {
                Oid2[] sha2Oids = new Oid2[]
                {
                    new Oid2(CapiNative.WellKnownOids.Sha256, "sha256", OidGroup.HashAlgorithm, (int)CapiNative.AlgorithmID.Sha256, CngAlgorithm.Sha256, null),
                    new Oid2(CapiNative.WellKnownOids.Sha384, "sha384", OidGroup.HashAlgorithm, (int)CapiNative.AlgorithmID.Sha384, CngAlgorithm.Sha384, null),
                    new Oid2(CapiNative.WellKnownOids.Sha512, "sha512", OidGroup.HashAlgorithm, (int)CapiNative.AlgorithmID.Sha512, CngAlgorithm.Sha512, null)
                };

                foreach (Oid2 sha2Oid in sha2Oids)
                {
                    // If the OID is currently registered to an ALG_ID other than 0, we don't want to break
                    // that registration (or duplicate it) by overwriting our own.
                    Oid2 currentOid = Oid2.FindByValue(sha2Oid.Value, sha2Oid.Group, false);

                    if (currentOid == null || !currentOid.HasAlgorithmId || currentOid.AlgorithmId == 0)
                    {
                        // There is either no current OID registration for the algorithm, or it contains a
                        // CAPI algorithm mapping which will not be understood by the v2.0 CLR.  Register a
                        // new mapping which will have the CAPI algorithm ID in it.
                        sha2Oid.Register(OidRegistrationOptions.InstallBeforeDefaultEntries);
                    }
                }
            }
        }

        /// <summary>
        ///     Convert an Oid2 into an Oid object
        /// </summary>
        public Oid ToOid()
        {
            return new Oid(m_oid, m_name);
        }

        /// <summary>
        ///     Convert an Oid2 into a CAPI OID_INFO
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        private CapiNative.CRYPT_OID_INFO ToOidInfo()
        {
            CapiNative.CRYPT_OID_INFO oidInfo = new CapiNative.CRYPT_OID_INFO();
            oidInfo.cbSize = Marshal.SizeOf(typeof(CapiNative.CRYPT_OID_INFO));
            oidInfo.pszOID = m_oid;
            oidInfo.pwszName = m_name;
            oidInfo.dwGroupId = m_group;

            if (m_algorithmId.HasValue)
            {
                oidInfo.dwValue = m_algorithmId.Value;
            }

            if (m_cngAlgorithm != null)
            {
                oidInfo.pwszCNGAlgid = m_cngAlgorithm.Algorithm;
            }

            if (m_cngExtraAlgorithm != null)
            {
                oidInfo.pwszCNGExtraAlgid = m_cngExtraAlgorithm.Algorithm;
            }

            return oidInfo;
        }

        /// <summary>
        ///     Unregister the OID from the machine.  This requires the user to be an administrator on the
        ///     machine, and also may not take effect within the current process if the registered OIDs have
        ///     already been read in this process by CAPI.
        /// </summary>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public void Unregister()
        {
            CapiNative.UnregisterOid(ToOidInfo());
        }
    }
}
