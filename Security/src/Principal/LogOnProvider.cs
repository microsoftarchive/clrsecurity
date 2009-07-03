// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;

namespace Security.Principal
{
    /// <summary>
    ///     The LogOnProvider enumeration contains the types of logon providers which may be used to perform
    ///     the logon operation.
    /// </summary>
    public enum LogOnProvider
    {
        /// <summary>
        ///     Use the default logon provider.  This is equivalent to the LOGON32_PROVIDER_DEFAULT provider.
        /// </summary>
        Default = 0,

        /// <summary>
        ///     Use the NTLM logon provider.  This is equivalent to the LOGON32_PROVIDER_WINNT40 provider.
        /// </summary>
        WinNT40 = 2,

        /// <summary>
        ///     Use the negotiate logon provider.  This is equivalent to the LOGON32_PROVIDER_WINNT50 provider.
        /// </summary>
        WinNT50 = 3,

        /// <summary>
        ///     Use the virtual logon provider.  This is equivalent to the LOGON32_PROVIDER_VIRTUAL provider.
        /// </summary>
        Virtual = 4,
    }
}
