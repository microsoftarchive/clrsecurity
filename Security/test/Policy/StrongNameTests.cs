// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Reflection;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Policy;
using Security.Reflection;

namespace Security.Policy.Test
{
    /// <summary>
    ///     Tests for the StrongName extension methods
    /// </summary>
    [TestClass]
    public sealed class StrongNameTests
    {
        /// <summary>
        ///     Tests for creating membership conditions out of a strong name
        /// </summary>
        [TestMethod]
        public void CreateMembershipConditionTest()
        {
            StrongName[] strongNames = new StrongName[]
            {
                typeof(object).Assembly.GetStrongName(),
                typeof(System.Security.Cryptography.AesManaged).Assembly.GetStrongName(),
                typeof(System.Security.Cryptography.Xml.SignedXml).Assembly.GetStrongName()
            };

            for (int i = 0; i < strongNames.Length; ++i)
            {
                StrongNameMembershipCondition mc = strongNames[i].CreateMembershipCondition();

                for (int j = 0; j < strongNames.Length; ++j)
                {
                    Evidence evidence = new Evidence(new object[] { strongNames[j] }, new object[0]);

                    if (i == j)
                    {
                        Assert.IsTrue(mc.Check(evidence));
                    }
                    else
                    {
                        Assert.IsFalse(mc.Check(evidence));
                    }
                }
            }
        }
    }
}
