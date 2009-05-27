// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Security.Principal
{
    /// <summary>
    ///     <para>
    ///         Attributes that can be associated with a group's SecurityIdentifier.
    ///    </para>
    ///    <para>
    ///         These values map to the group attributes documented on
    ///         http://msdn.microsoft.com/en-us/library/aa379624.aspx
    ///    </para>
    /// </summary>
    [Flags]
    [SuppressMessage("Microsoft.Usage", "CA2217:DoNotMarkEnumsWithFlags", Justification = "These flags are mapped from Win32 definitions")]
    public enum GroupSecurityIdentifierAttributes
    {
        /// <summary>
        ///     No attributes are set on the group SID.
        /// </summary>
        None                    = 0x00000000,

        /// <summary>
        ///     The group cannot have its Enabled bit removed.  This maps to the SE_GROUP_MANDATORY attribute.
        /// </summary>
        Mandatory               = 0x00000001,

        /// <summary>
        ///     The group is enabled by default.  This maps to the SE_GROUP_ENABLED_BY_DEFAULT attribute.
        /// </summary>
        EnabledByDefault        = 0x00000002,

        /// <summary>
        ///     The group is enabled for use in access checks.  This maps to the SE_GROUP_ENABLED attribute.
        /// </summary>
        Enabled                 = 0x00000004,

        /// <summary>
        ///     The token that the group is pulled from is the owner of the group.  This maps to the
        ///     SE_GROUP_OWNER attribute.
        /// </summary>
        Owner                   = 0x00000008,

        /// <summary>
        ///     The group can only be used to match deny ACEs, and will not match allow ACEs.  This maps to
        ///     the SE_GROUP_USE_FOR_DENY_ONLY attribute.
        /// </summary>
        DenyOnly                = 0x00000010,

        /// <summary>
        ///     The group is used to set the integrity level of the token.  This maps to the
        ///     SE_GROUP_INTEGRITY attribute.
        /// </summary>
        Integrity               = 0x00000020,

        /// <summary>
        ///     The group is used to set the integrity level of the token.  This maps to the
        ///     SE_GROUP_INTEGRITY_ENABLED attribute.
        /// </summary>
        IntegrityEnabled        = 0x00000040,

        /// <summary>
        ///     The group is domain-local.  This maps to the SE_GROUP_RESOURCE attribute.
        /// </summary>
        Resource                = 0x20000000,

        /// <summary>
        ///     The group identifies the logon session of the token.  This maps to the SE_GROUP_LOGON_ID
        ///     attribute.
        /// </summary>
        LogOnIdentifier         = unchecked((int)0xC0000000),
    }
}
