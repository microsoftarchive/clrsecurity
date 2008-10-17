// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Policy;

namespace Security.Policy
{
    /// <summary>
    ///     Extension methods for the Evidence type
    /// </summary>
    public static class EvidenceExtensionMethods
    {
        /// <summary>
        ///     Get a specific piece of assembly provided evidence
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification = "This allows for a strongly typed return value. The alternate design also requires providing the type name explicitly.")]
        public static T GetAssemblyEvidence<T>(this Evidence evidence) where T : class
        {
            return GetEvidence<T>(evidence.GetAssemblyEnumerator());
        }

        /// <summary>
        ///     Find the requested piece of evidence in an evidence enumerator
        /// </summary>
        private static T GetEvidence<T>(IEnumerator enumerator) where T : class
        {
            Debug.Assert(enumerator != null, "enumerator != null");

            while (enumerator.MoveNext())
            {
                T evidence = enumerator.Current as T;
                if (evidence != null)
                {
                    return evidence;
                }
            }

            return null;
        }

        /// <summary>
        ///     Get a specific piece of host provided evidence
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification = "This allows for a strongly typed return value. The alternate design also requires providing the type name explicitly.")]
        public static T GetHostEvidence<T>(this Evidence evidence) where T : class
        {
            return GetEvidence<T>(evidence.GetHostEnumerator());
        }
    }
}
