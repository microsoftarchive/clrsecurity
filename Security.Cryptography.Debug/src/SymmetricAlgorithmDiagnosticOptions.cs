// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Configuration options for setting up the types of diagnostic checks that will be done by the
    ///     the verification process.
    /// </summary>
    public sealed class SymmetricAlgorithmDiagnosticOptions
    {
        private bool m_checkThreadSafety;
        private Predicate<CryptographyLockContext<SymmetricAlgorithm>> m_lockCheckCallback;
        private object m_lockCheckParameter;

        /// <summary>
        ///     Should the symmetric algorithm diagnostics do thread safety checks
        /// </summary>
        public bool CheckThreadSafety
        {
            get { return m_checkThreadSafety; }
            set { m_checkThreadSafety = value; }
        }

        /// <summary>
        ///     Callback to determine if the correct lock is held
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures", Justification = "Reuse of standard library delegate types")]
        public Predicate<CryptographyLockContext<SymmetricAlgorithm>> LockCheckCallback
        {
            get { return m_lockCheckCallback; }
            set { m_lockCheckCallback = value; }
        }

        /// <summary>
        ///     Parameter to pass to the lock check callback in its context
        /// </summary>
        public object LockCheckParameter
        {
            get { return m_lockCheckParameter; }
            set { m_lockCheckParameter = value; }
        }
    }
}
