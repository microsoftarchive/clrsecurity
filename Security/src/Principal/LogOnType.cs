// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;

namespace Security.Principal
{
    /// <summary>
    ///     The LogOnType enumeration contains the types of logon operations that may be performed.
    /// </summary>
    public enum LogOnType
    {
        /// <summary>
        ///     No logon type - this is not a valid logon type to use with LogonUser
        /// </summary>
        None = 0,

        /// <summary>
        ///     Logon as an interactive user, which may cause additional caching and therefore not be
        ///     appropriate for some server scenarios.  This is equivalent to the LOGON32_LOGON_INTERACTIVE
        ///     logon type.
        /// </summary>
        Interactive = 2,

        /// <summary>
        ///     Logon type for servers to check cleartext passwords.  No caching is done for this type of
        ///     logon.  This is equivalent to the LOGON32_LOGON_NETWORK logon type.
        /// </summary>
        Network = 3,

        /// <summary>
        ///     Logon type for servers who act on behalf of users without their intervention, or who
        ///     processs many cleartext passwords at time.  This is equivalent to the LOGON32_LOGON_BATCH
        ///     logon type.
        /// </summary>
        Batch = 4,

        /// <summary>
        ///     Logon as a service.  The account being logged on must have privilege to act as a service. 
        ///     This is equivalent to the LOGON32_LOGON_SERVICE logon type.
        /// </summary>
        Service = 5,

        /// <summary>
        ///     Logon type for GINA DLLs to unlock the machine with.  This is equivalent to the
        ///     LOGON32_LOGON_UNLOCK logon type.
        /// </summary>
        Unlock = 7,

        /// <summary>
        ///     Logon type which allows caching of the text password in the authentication provider in order
        ///     to allow connections to multiple network services with the same credentials.  This is
        ///     equivalent to the LOGON32_LOGON_NETWORK_CLEARTEXT logon type.
        /// </summary>
        NetworkClearText = 8,

        /// <summary>
        ///     Logon type which creates a token with the same identity as the current user token for the
        ///     local proces, but provides new credentials for outbound network connections.  This is
        ///     equivalent to the LOGON32_LOGON_NEW_CREDENTIALS logon type.
        /// </summary>
        NewCredentials = 9,
    }
}
