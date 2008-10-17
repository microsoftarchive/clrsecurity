// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Policy;

namespace Security.Policy
{
    /// <summary>
    ///     Extension methods for the StrongName class
    /// </summary>
    public static class StrongNameExtensionMethods
    {
        /// <summary>
        ///     Create a membership condition which will match this strong name
        /// </summary>
        public static StrongNameMembershipCondition CreateMembershipCondition(this StrongName strongName)
        {
            return new StrongNameMembershipCondition(strongName.PublicKey, strongName.Name, strongName.Version);
        }
    }
}
