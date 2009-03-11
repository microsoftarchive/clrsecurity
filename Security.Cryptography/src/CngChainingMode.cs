// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     Pseudo-enum for chaining modes used with CNG, in the same style as CngAlgorithm and CngProvider
    /// </summary>
    [Serializable]
    public sealed class CngChainingMode : IEquatable<CngChainingMode>
    {
        private static CngChainingMode s_cbc;
        private static CngChainingMode s_ccm;
        private static CngChainingMode s_cfb;
        private static CngChainingMode s_ecb;
        private static CngChainingMode s_gcm;

        private string m_chainingMode;

        public CngChainingMode(string chainingMode)
        {
            if (chainingMode == null)
                throw new ArgumentNullException("chainingMode");
            if (chainingMode.Length == 0)
                throw new ArgumentException(Resources.InvalidChainingModeName, "chainingMode");

            m_chainingMode = chainingMode;
        }

        public string ChainingMode
        {
            get { return m_chainingMode; }
        }

        public static bool operator ==(CngChainingMode left, CngChainingMode right)
        {
            if (Object.ReferenceEquals(left, null))
            {
                return Object.ReferenceEquals(right, null);
            }

            return left.Equals(right);
        }

        public static bool operator !=(CngChainingMode left, CngChainingMode right)
        {
            if (Object.ReferenceEquals(left, null))
            {
                return !Object.ReferenceEquals(right, null);
            }

            return !left.Equals(right);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as CngChainingMode);
        }

        public bool Equals(CngChainingMode other)
        {
            if (Object.ReferenceEquals(other, null))
            {
                return false;
            }

            return m_chainingMode.Equals(other.ChainingMode);
        }

        public override int GetHashCode()
        {
            return m_chainingMode.GetHashCode();
        }

        public override string ToString()
        {
            return m_chainingMode;
        }

        //
        // Well known chaining modes
        //

        public static CngChainingMode Cbc
        {
            get
            {
                if (s_cbc == null)
                {
                    s_cbc = new CngChainingMode(BCryptNative.ChainingMode.Cbc);
                }

                return s_cbc;
            }
        }

        public static CngChainingMode Ccm
        {
            get
            {
                if (s_ccm == null)
                {
                    s_ccm = new CngChainingMode(BCryptNative.ChainingMode.Ccm);
                }

                return s_ccm;
            }
        }

        public static CngChainingMode Cfb
        {
            get
            {
                if (s_cfb == null)
                {
                    s_cfb = new CngChainingMode(BCryptNative.ChainingMode.Cfb);
                }

                return s_cfb;
            }
        }

        public static CngChainingMode Ecb
        {
            get
            {
                if (s_ecb == null)
                {
                    s_ecb = new CngChainingMode(BCryptNative.ChainingMode.Ecb);
                }

                return s_ecb;
            }
        }

        public static CngChainingMode Gcm
        {
            get
            {
                if (s_gcm == null)
                {
                    s_gcm = new CngChainingMode(BCryptNative.ChainingMode.Gcm);
                }

                return s_gcm;
            }
        }
    }
}
