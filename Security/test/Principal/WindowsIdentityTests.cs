// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Principal;

namespace Security.Principal.Test
{
    /// <summary>
    ///     Tests for the WindowsIdentity extension methods
    /// </summary>
    [TestClass]
    public sealed class WindowsIdentityTests
    {
        /// <summary>
        ///     Tests for the GetAllGroups extension method
        /// </summary>
        [TestMethod]
        public void GetAllGroupsTest()
        {
            using (WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent())
            {
                IEnumerable<GroupSecurityIdentifierInformation> allGroups = currentIdentity.GetAllGroups();

                // Ensure that all SIDs in the WindowsIdentity Groups are present in the AllGroups list
                var standardGroupSids = from groupReference in currentIdentity.Groups
                                        where groupReference.IsValidTargetType(typeof(SecurityIdentifier))
                                        select groupReference.Translate(typeof(SecurityIdentifier)) as SecurityIdentifier;

                foreach (SecurityIdentifier sid in standardGroupSids)
                {
                    var matchingAllGroupSids = from groupInfo in allGroups
                                               where groupInfo.SecurityIdentifier == sid
                                               select groupInfo;
                    Assert.AreEqual(1, matchingAllGroupSids.Count());
                }

                // Ensure that any SIDs that did not show up in the WindowsIdentity groups are disabled,
                // logon, or deny-only SIDs
                var extraGroups = from groupInfo in allGroups
                                  where !standardGroupSids.Any(sid => sid == groupInfo.SecurityIdentifier)
                                  select groupInfo;

                GroupSecurityIdentifierAttributes filteredMask =
                        GroupSecurityIdentifierAttributes.DenyOnly |
                        GroupSecurityIdentifierAttributes.LogOnIdentifier;

                foreach (GroupSecurityIdentifierInformation extraGroup in extraGroups)
                {
                    if ((extraGroup.Attributes & filteredMask) == GroupSecurityIdentifierAttributes.None)
                    {
                        // This group was not for deny only, and was not the logon group, so it must not be enabled.
                        Assert.IsTrue((extraGroup.Attributes & GroupSecurityIdentifierAttributes.Enabled) == GroupSecurityIdentifierAttributes.None);
                    }
                }
            }
        }

        /// <summary>
        ///     Tests for the IsAdministrator extension method
        /// </summary>
        [TestMethod]
        public void IsAdministratorTest()
        {
            using (WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent())
            {
                // We should only return true from IsAdministrator if our token contains the Administrators
                // token in the Enabled and not DenyOnly state.
                GroupSecurityIdentifierAttributes filter = GroupSecurityIdentifierAttributes.DenyOnly |
                                                           GroupSecurityIdentifierAttributes.Enabled;
                var enabledGroupSids = from groupInfo in currentIdentity.GetAllGroups()
                                       where (groupInfo.Attributes & filter) == GroupSecurityIdentifierAttributes.Enabled
                                       select groupInfo.SecurityIdentifier;
                bool isAdmin = enabledGroupSids.Any(sid => sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

                if (isAdmin)
                {
                    Assert.IsTrue(currentIdentity.IsAdministrator());
                }
                else
                {
                    Assert.IsFalse(currentIdentity.IsAdministrator());
                }
            }
        }
    }
}
