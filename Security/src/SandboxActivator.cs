// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Security.Policy;
using Security.Reflection;
using System.Runtime.Remoting;

namespace Security
{
    /// <summary>
    ///     <para>
    ///         SandboxActivator allows you to create a sandboxed instance of an object.  It creates sandboxed
    ///         AppDomains and activates objects in the remote domains, return a reference to the remote
    ///         sandboxed object.  Objects created with the same grant sets will share AppDomains, rather than
    ///         each object getting its own AppDomain.
    ///     </para>
    ///     <para>
    ///         For example, to get an instance of an object which runs in an Internet sandbox:
    ///         <example>
    ///             PermissionSet internetGrantSet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet);
    ///             SandboxedObject sandboxed = SandboxActivator.CreateSandboxedInstance&lt;SandboxedObject&gt;(internetGrantSet);
    ///         </example>
    ///     </para>
    /// </summary>
    public static class SandboxActivator
    {
        private static List<AppDomain> s_sandboxes = new List<AppDomain>();
        private static object s_sandboxesLock = new object();

        /// <summary>
        ///     <para>
        ///         Create an instance of type <typeparamref name="T"/> in an execute-only AppDomain.
        ///     </para>
        ///     <para>
        ///         This method is thread safe.
        ///     </para>
        /// </summary>
        /// <typeparam name="T">Type to create an execution-only instance of</typeparam>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "This API only allows creation at execute-only level, so it cannot be used to elevate")]
        [SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification = "This matches the Activator.CreateInstance<T> pattern")]
        public static T CreateSandboxedInstance<T>()
            where T : MarshalByRefObject
        {
            return CreateSandboxedInstance<T>(PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Execution));
        }

        /// <summary>
        ///     <para>
        ///         Create an instance of type <typeparamref name="T" />  in an AppDomain with the specified
        ///         grant set.
        ///     </para>
        /// </summary>
        /// <typeparam name="T">Type to create a sandboxed instance of</typeparam>
        /// <param name="grantSet">Permissions to grant the object</param>
        /// <exception cref="ArgumentNullException">if <paramref name="grantSet"/> is null</exception>
        /// <permission cref="PermissionSet">
        ///     This API requires that its immediate caller be fully trusted
        /// </permission>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        [SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification = "This matches the Activator.CreateInstance<T> pattern")]
        public static T CreateSandboxedInstance<T>(PermissionSet grantSet)
            where T : MarshalByRefObject
        {
            return CreateSandboxedInstance<T>(grantSet, null);
        }

        /// <summary>
        ///     <para>
        ///         Create an instance of type <typeparamref name="T"/> in an AppDomain with the specified
        ///         grant set.  Additionally, this domain will allow some extra full trust asemblies to be
        ///         loaded into it for use by the partial trust code.
        ///     </para>
        ///     <para>
        ///         This method is thread safe.
        ///     </para>
        /// </summary>
        /// <typeparam name="T">Type to create a sandboxed instance of</typeparam>
        /// <param name="grantSet">Permission set to grant the object</param>
        /// <param name="fullTrustList">Optional list of fullly trusted assemblies for the object to work with</param>
        /// <exception cref="ArgumentNullException">if <paramref name="grantSet"/> is null</exception>
        /// <permission cref="PermissionSet">
        ///     This API requires that its immediate caller be fully trusted
        /// </permission>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        [SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification = "This matches the Activator.CreateInstance<T> pattern")]
        public static T CreateSandboxedInstance<T>(PermissionSet grantSet, IEnumerable<Assembly> fullTrustList)
            where T : MarshalByRefObject
        {
            if (grantSet == null)
                throw new ArgumentNullException("grantSet");

            lock (s_sandboxesLock)
            {
                string sandboxAppBase = Path.GetDirectoryName(typeof(T).Assembly.Location);

                // Narrow down the sandboxes to ones which have the correct AppBase, grant set, and number
                // of full trust assemblies
                var candidateSandboxes = from candidateSandbox in s_sandboxes
                                         where IsCandidateSandbox(candidateSandbox, sandboxAppBase, grantSet, fullTrustList)
                                         select candidateSandbox;

                // Pick the first matching candidate sandbox domain
                AppDomain sandbox = candidateSandboxes.FirstOrDefault();

                // If no suitable existing sandboxes were found, then create a new one and save it away
                if (sandbox == null)
                {
                    sandbox = SandboxFactory.CreateSandbox(sandboxAppBase,
                                                           grantSet,
                                                           fullTrustList != null ? fullTrustList.ToArray() : null);
                    s_sandboxes.Add(sandbox);
                }

                // Now that we have somewhere to create the partial trust instance, create it
                ObjectHandle sandboxedInstance = Activator.CreateInstance(sandbox,
                                                                          typeof(T).Assembly.FullName,
                                                                          typeof(T).FullName,
                                                                          false,
                                                                          BindingFlags.Instance | BindingFlags.CreateInstance | BindingFlags.Public | BindingFlags.NonPublic,
                                                                          null,
                                                                          null,
                                                                          null,
                                                                          null,
                                                                          null);
                return sandboxedInstance.Unwrap() as T;
            }
        }

        /// <summary>
        ///     Determine if a sandboxed AppDomain is a candidate for being used for a new object
        /// </summary>
        [SecurityCritical]
        [SecurityTreatAsSafe]
        private static bool IsCandidateSandbox(AppDomain candidateSandbox,
                                               string requiredAppBase,
                                               PermissionSet requiredGrantSet,
                                               IEnumerable<Assembly> requiredFullTrustList)
        {
            Debug.Assert(candidateSandbox != null, "candidateSandbox != null");
            Debug.Assert(!String.IsNullOrEmpty(requiredAppBase), "!String.IsNullOrEmpty(requiredAppBase)");
            Debug.Assert(requiredGrantSet != null, "requiredGrantSet != null");
            
            // The candidate sandbox must have the correct AppBase
            if (!String.Equals(candidateSandbox.SetupInformation.ApplicationBase,
                               requiredAppBase,
                               StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            
            // It must have the same grant set
            PermissionSet candidateGrantSet = candidateSandbox.GetPermissionSet();
            if (!requiredGrantSet.IsSubsetOf(candidateGrantSet) ||
                !candidateGrantSet.IsSubsetOf(requiredGrantSet))
            {
                return false;
            }

            // If there is no required full trust list, then the candidate must not have one either
            IList<StrongName> candidateFullTrustList = candidateSandbox.ApplicationTrust.GetFullTrustAssemblies();
            if (requiredFullTrustList == null)
            {
                return candidateFullTrustList.Count == 0;
            }

            // If there is a required full trust list, the candidate must have the same number of trusted
            // assemblies
            if (requiredFullTrustList.Count() != candidateFullTrustList.Count)
            {
                return false;
            }

            // And each assembly in the candidate list must be in the required list
            if (requiredFullTrustList.Any(a => !candidateFullTrustList.Contains(a.GetStrongName())))
            {
                return false;
            }

            return true;
        }
    }
}
