// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;

namespace Security
{
    /// <summary>
    ///     The StandardPermissionSet enumeration identifies the standard built-in permission sets that the
    ///     CLR uses.
    /// </summary>
    public enum StandardPermissionSet
    {
        /// <summary>
        ///     The empty permission set
        /// </summary>
        Nothing,

        /// <summary>
        ///     A permission set which only contains permission to execute
        /// </summary>
        Execution,

        /// <summary>
        ///     A permission set which is safe to grant applications from the Internet.
        /// </summary>
        Internet,

        /// <summary>
        ///     A permission set which is safe to grant applications from the local network.
        /// </summary>
        LocalIntranet,

        /// <summary>
        ///     The Everything permission set contains unrestricted versions of all built in permissions,
        ///     with the exception of SecurityPermission which does not contain the skip verification flag. 
        ///     This permission set should not be used as a sandbox, and is generally interesting only for
        ///     testing purposes.
        /// </summary>
        Everything,

        /// <summary>
        ///     The FullTrust permission set is a superset of all other permission sets.
        /// </summary>
        FullTrust
    }
}
