// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Policy;
using Security.Properties;

namespace Security.Policy
{
    /// <summary>
    ///     EvidenceExtensionMethods provides several extension methods for the <see cref="Evidence" /> class.
    ///     This type is in the Security.Policy namespace (not the System.Security.Policy namespace), so in
    ///     order to use these extension methods, you will need to make sure you include this namespace as
    ///     well as a reference to Security.dll.
    /// </summary>
    public static class EvidenceExtensionMethods
    {
        /// <summary>
        ///     Add an object to the host evidence list, ensuring that only one item of evidence of the
        ///     given type exists in the final evidence collection.
        /// </summary>
        /// <typeparam name="T">Type of evidence being added</typeparam>
        /// <param name="evidence">evidence collection to add to</param>
        /// <param name="evidenceObject">object to add to the evidence collection</param>
        /// <exception cref="ArgumentNullException">if <paramref name="evidenceObject" /> is null</exception>
        /// <exception cref="InvalidOperationException">
        ///     if the evidence collection already contains an evidence object of type <typeparamref name="T"/>
        /// </exception>
        public static void AddHostEvidence<T>(this Evidence evidence, T evidenceObject) where T : class
        {
            if (evidenceObject == null)
                throw new ArgumentNullException("evidenceObject");
            if (evidence.GetHostEvidence<T>() != null)
                throw new InvalidOperationException(String.Format(Resources.Culture, Resources.DuplicateEvidence, typeof(T).ToString()));

            evidence.AddHost(evidenceObject);
        }

        /// <summary>
        ///     Get the first evidence object of type <typeparamref name="T"/> supplied by the assembly that
        ///     the Evidence collection is for.
        /// </summary>
        /// <typeparam name="T">Type of assembly evidence that should be obtained.</typeparam>
        /// <returns>
        ///     The first evidence object of type <typeparamref name="T"/> that is in the assembly supplied
        ///     evidence, or null if the assembly has not supplied any evidence of type <typeparamref name="T"/>.
        /// </returns>
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
        ///     Get the first evidence object of type <typeparamref name="T"/> supplied by the host in the
        ///     Evidence collection.
        /// </summary>
        /// <typeparam name="T">Type of host evidence that should be obtained.</typeparam>
        /// <returns>
        ///     The first evidence object of type <typeparamref name="T"/> that is in the host supplied
        ///     evidence, or null if the host has not supplied any evidence of type <typeparamref name="T"/>.
        /// </returns>
        [SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification = "This allows for a strongly typed return value. The alternate design also requires providing the type name explicitly.")]
        public static T GetHostEvidence<T>(this Evidence evidence) where T : class
        {
            return GetEvidence<T>(evidence.GetHostEnumerator());
        }
    }
}
