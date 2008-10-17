// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Policy;

namespace Security.Policy.Test
{
    [TestClass]
    public sealed class EvidenceTests
    {
        [TestMethod]
        public void GetAssemblyEvidenceTest()
        {
            object[] hostEvidence =
            {
                new Zone(SecurityZone.Internet),
                new Url("http://www.codeplex.com/clrsecurity/hostevidence")
            };

            object[] assemblyEvidence =
            {
                new Zone(SecurityZone.MyComputer),
                new GacInstalled(),
                new Url("http://www.codeplex.com/clrsecurity/assemblyevidence")
            };

            Evidence evidence = new Evidence(hostEvidence, assemblyEvidence);

            Assert.IsNotNull(evidence.GetAssemblyEvidence<Zone>());
            Assert.AreEqual(SecurityZone.MyComputer, evidence.GetAssemblyEvidence<Zone>().SecurityZone);

            Assert.IsNotNull(evidence.GetAssemblyEvidence<GacInstalled>());
            Assert.IsNull(evidence.GetAssemblyEvidence<StrongName>());

            Assert.IsNotNull(evidence.GetAssemblyEvidence<Url>());
            Assert.AreEqual("http://www.codeplex.com/clrsecurity/assemblyevidence", evidence.GetAssemblyEvidence<Url>().Value);
        }

        [TestMethod]
        public void GetHostEvidenceTest()
        {
            object[] hostEvidence =
            {
                new Zone(SecurityZone.Internet),
                new Url("http://www.codeplex.com/clrsecurity/hostevidence")
            };

            object[] assemblyEvidence =
            {
                new Zone(SecurityZone.MyComputer),
                new GacInstalled(),
                new Url("http://www.codeplex.com/clrsecurity/assemblyevidence")
            };

            Evidence evidence = new Evidence(hostEvidence, assemblyEvidence);

            Assert.IsNotNull(evidence.GetHostEvidence<Zone>());
            Assert.AreEqual(SecurityZone.Internet, evidence.GetHostEvidence<Zone>().SecurityZone);

            Assert.IsNull(evidence.GetHostEvidence<GacInstalled>());
            Assert.IsNull(evidence.GetHostEvidence<StrongName>());

            Assert.IsNotNull(evidence.GetHostEvidence<Url>());
            Assert.AreEqual("http://www.codeplex.com/clrsecurity/hostevidence", evidence.GetHostEvidence<Url>().Value);
        }
    }
}
