// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Principal;

namespace Security.Principal
{
    /// <summary>
    ///     SecurityIdentifierInformation contains a group SID and an associated set of attributes for that
    ///     group.
    /// </summary>
    public sealed class GroupSecurityIdentifierInformation
    {
        private SecurityIdentifier m_sid;
        private GroupSecurityIdentifierAttributes m_attributes;

        /// <summary>
        ///     Create a GroupSecurityIdentifierInformation object for a SID.
        /// </summary>
        /// <param name="sid">group SID to associate attributes with</param>
        /// <param name="attributes">attributes associated with the SID</param>
        /// <exception cref="ArgumentNullException">
        ///     If <paramref name="sid"/> is null.
        /// </exception>
        public GroupSecurityIdentifierInformation(SecurityIdentifier sid,
                                                  GroupSecurityIdentifierAttributes attributes)
        {
            if (sid == null)
                throw new ArgumentNullException("sid");

            m_sid = sid;
            m_attributes = attributes;
        }

        /// <summary>
        ///     Get the attributes associated with a group SID.
        /// </summary>
        public GroupSecurityIdentifierAttributes Attributes
        {
            get { return m_attributes; }
        }

        /// <summary>
        ///     Get the group SID associated with the attributes.
        /// </summary>
        public SecurityIdentifier SecurityIdentifier
        {
            get { return m_sid; }
        }
    }
}
