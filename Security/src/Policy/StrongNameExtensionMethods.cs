// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Policy;

namespace Security.Policy
{
    /// <summary>
    ///     StrongNameExtensionMethods provides several extension methods for the <see cref="StrongName" />
    ///     class. This type is in the Security.Policy namespace (not the System.Security.Policy namespace),
    ///     so in order to use these extension methods, you will need to make sure you include this namespace
    ///     as well as a reference to Security.dll.
    /// </summary>
    public static class StrongNameExtensionMethods
    {
        /// <summary>
        ///     The CreateMembershipCondition method builds a membership condition which exactly matches the
        ///     strong name (including version).
        /// </summary>
        public static StrongNameMembershipCondition CreateMembershipCondition(this StrongName strongName)
        {
            return new StrongNameMembershipCondition(strongName.PublicKey, strongName.Name, strongName.Version);
        }
    }
}
