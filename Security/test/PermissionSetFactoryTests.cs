// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Drawing.Printing;
using System.Net;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security;

namespace Security.Test
{
    /// <summary>
    ///     Tests for the PermissionSetFactory type
    /// </summary>
    [TestClass]
    public sealed class PermissionSetFactoryTests
    {
        /// <summary>
        ///     Test to ensure the Everything permission set comes back as expected
        /// </summary>
        [TestMethod]
        public void GetStandardPermissionSetEverythingPermissionSetTest()
        {
            PermissionSet everything = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Everything);

            // Everything should neither be empty nor full trust
            Assert.IsFalse(everything.IsUnrestricted());
            Assert.IsFalse(everything.IsEmpty());

            // Each permission in Everything should be unrestricted, except for SecurityPermission
            foreach (IPermission permission in everything)
            {
                IUnrestrictedPermission unrestricted = permission as IUnrestrictedPermission;
                SecurityPermission securityPermission = permission as SecurityPermission;

                if (securityPermission != null)
                {
                    SecurityPermissionFlag everythingFlags = SecurityPermissionFlag.Assertion |
                                                             SecurityPermissionFlag.BindingRedirects |
                                                             SecurityPermissionFlag.ControlAppDomain |
                                                             SecurityPermissionFlag.ControlDomainPolicy |
                                                             SecurityPermissionFlag.ControlEvidence |
                                                             SecurityPermissionFlag.ControlPolicy |
                                                             SecurityPermissionFlag.ControlPrincipal |
                                                             SecurityPermissionFlag.ControlThread |
                                                             SecurityPermissionFlag.Execution |
                                                             SecurityPermissionFlag.Infrastructure |
                                                             SecurityPermissionFlag.RemotingConfiguration |
                                                             SecurityPermissionFlag.SerializationFormatter |
                                                             SecurityPermissionFlag.UnmanagedCode;
                    Assert.AreEqual(everythingFlags, securityPermission.Flags);
                }
                else if (unrestricted != null)
                {
                    Assert.IsTrue(unrestricted.IsUnrestricted());
                }
            }

            // Everything should be a superset of Internet and LocalIntranet
            PermissionSet internet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet);
            Assert.IsTrue(internet.IsSubsetOf(everything));
            Assert.IsFalse(everything.IsSubsetOf(internet));

            PermissionSet localIntranet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet);
            Assert.IsTrue(localIntranet.IsSubsetOf(everything));
            Assert.IsFalse(everything.IsSubsetOf(localIntranet));
        }

        /// <summary>
        ///     Test to ensure the Execution permission set comes back as expected
        /// </summary>
        [TestMethod]
        public void GetStandardPermissionSetExecutionPermissionSetTest()
        {
            PermissionSet execution = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Execution);

            // Execution should neither be empty nor full trust
            Assert.IsFalse(execution.IsUnrestricted());
            Assert.IsFalse(execution.IsEmpty());

            // The Execution set should have a single permission in it
            Assert.AreEqual(1, execution.Count);

            // We should have a security permission granting only Execution
            SecurityPermission securityPermission = execution.GetPermission(typeof(SecurityPermission)) as SecurityPermission;
            Assert.IsNotNull(securityPermission);
            Assert.AreEqual(SecurityPermissionFlag.Execution, securityPermission.Flags);
        }

        /// <summary>
        ///     Test to ensure the FullTrust permission set comes back as expected
        /// </summary>
        [TestMethod]
        public void GetStandardPermissionSetFullTrustPermissionSetTest()
        {
            PermissionSet fullTrust = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.FullTrust);
            
            // FullTrust should be, well, FullTrust
            Assert.IsTrue(fullTrust.IsUnrestricted());
        }

        /// <summary>
        ///     Test to ensure the Internet permission set comes back as expected
        /// </summary>
        [TestMethod]
        public void GetStandardPermissionSetInternetPermissionSetTest()
        {
            // Get a copy of Internet which is not extended with any same-site permission
            PermissionSet internetBase = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet, null);

            // It shouldn't be fully trusted, and should contain a set of well known permissions
            Assert.IsFalse(internetBase.IsUnrestricted());
            Assert.IsTrue(internetBase.Count == 5 || internetBase.Count == 7);

            // We should have SecurityPermission/Execution
            SecurityPermission baseSecurityPermission = internetBase.GetPermission(typeof(SecurityPermission)) as SecurityPermission;
            Assert.IsNotNull(baseSecurityPermission);
            Assert.AreEqual(SecurityPermissionFlag.Execution, baseSecurityPermission.Flags);

            // FileDialogPermission/Open
            FileDialogPermission baseFileDialogPermission = internetBase.GetPermission(typeof(FileDialogPermission)) as FileDialogPermission;
            Assert.IsNotNull(baseFileDialogPermission);
            Assert.AreEqual(FileDialogPermissionAccess.Open, baseFileDialogPermission.Access);

            // IsolatedStorageFilePermission/ApplicationIsolationByUser
            IsolatedStorageFilePermission baseIsostorePermission = internetBase.GetPermission(typeof(IsolatedStorageFilePermission)) as IsolatedStorageFilePermission;
            Assert.IsNotNull(baseIsostorePermission);
            Assert.AreEqual(IsolatedStorageContainment.ApplicationIsolationByUser, baseIsostorePermission.UsageAllowed);

            // UIPermission/SafeTopLevelWindows and UIPermission/OwnClipboard
            UIPermission baseUIPermission = internetBase.GetPermission(typeof(UIPermission)) as UIPermission;
            Assert.IsNotNull(baseUIPermission);
            Assert.AreEqual(UIPermissionWindow.SafeTopLevelWindows, baseUIPermission.Window);
            Assert.AreEqual(UIPermissionClipboard.OwnClipboard, baseUIPermission.Clipboard);

            // PrintingPermission/SafePrinting
            PrintingPermission basePrintingPermission = internetBase.GetPermission(typeof(PrintingPermission)) as PrintingPermission;
            Assert.IsNotNull(basePrintingPermission);
            Assert.AreEqual(PrintingPermissionLevel.SafePrinting, basePrintingPermission.Level);

            // Also check for WPF extensions
            MediaPermission baseMediaPermission = internetBase.GetPermission(typeof(MediaPermission)) as MediaPermission;
            if (baseMediaPermission != null)
            {
                Assert.AreEqual(MediaPermissionAudio.SafeAudio, baseMediaPermission.Audio);
                Assert.AreEqual(MediaPermissionImage.SafeImage, baseMediaPermission.Image);
                Assert.AreEqual(MediaPermissionVideo.SafeVideo, baseMediaPermission.Video);
            }

            WebBrowserPermission baseWebPermission = internetBase.GetPermission(typeof(WebBrowserPermission)) as WebBrowserPermission;
            if (baseWebPermission != null)
            {
                Assert.AreEqual(WebBrowserPermissionLevel.Safe, baseWebPermission.Level);
            }

            // Now try to extend with a local URL - we should get no extensions
            Url localUrl = new Url(@"file://c:\windows");
            PermissionSet internetLocalExtended = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet, localUrl);
            Assert.IsTrue(internetLocalExtended.IsSubsetOf(internetBase));
            Assert.IsTrue(internetBase.IsSubsetOf(internetLocalExtended));

            // Finally, try to extend with a Web URL, which should provide same site web access
            Url webUrl = new Url("htt://www.microsoft.com/");
            PermissionSet internetWebExtended = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet, webUrl);
            Assert.IsTrue(internetBase.IsSubsetOf(internetWebExtended));
            Assert.IsFalse(internetWebExtended.IsUnrestricted());
            Assert.AreEqual(internetBase.Count + 1, internetWebExtended.Count);

            WebPermission webPermission = internetWebExtended.GetPermission(typeof(WebPermission)) as WebPermission;
            Assert.IsNotNull(webPermission);
            Assert.IsFalse(webPermission.IsUnrestricted());
        }

        /// <summary>
        ///     Test to ensure the LocalIntranet permission set comes back as expected
        /// </summary>
        [TestMethod]
        public void GetStandardPermissionSetLocalIntranetPermissionSetTest()
        {
            // Get a copy of LocalIntranet which is not extended with any same-site permission
            PermissionSet intranetBase = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, null);

            // It shouldn't be fully trusted, and should contain a set of well known permissions
            Assert.IsFalse(intranetBase.IsUnrestricted());
            Assert.IsTrue(intranetBase.Count == 8 || intranetBase.Count == 10);

            // We should have SecurityPermission/Execution,Assertion,BindingRedirects
            SecurityPermission baseSecurityPermission = intranetBase.GetPermission(typeof(SecurityPermission)) as SecurityPermission;
            Assert.IsNotNull(baseSecurityPermission);
            Assert.AreEqual(SecurityPermissionFlag.Execution | SecurityPermissionFlag.Assertion | SecurityPermissionFlag.BindingRedirects, baseSecurityPermission.Flags);

            // Unrestricted FileDialogPermission
            FileDialogPermission baseFileDialogPermission = intranetBase.GetPermission(typeof(FileDialogPermission)) as FileDialogPermission;
            Assert.IsNotNull(baseFileDialogPermission);
            Assert.IsTrue(baseFileDialogPermission.IsUnrestricted());

            // IsolatedStorageFilePermission/AssemblyIsolationByUser
            IsolatedStorageFilePermission baseIsostorePermission = intranetBase.GetPermission(typeof(IsolatedStorageFilePermission)) as IsolatedStorageFilePermission;
            Assert.IsNotNull(baseIsostorePermission);
            Assert.AreEqual(IsolatedStorageContainment.AssemblyIsolationByUser, baseIsostorePermission.UsageAllowed);

            // Unrestricted UIPermission
            UIPermission baseUIPermission = intranetBase.GetPermission(typeof(UIPermission)) as UIPermission;
            Assert.IsNotNull(baseUIPermission);
            Assert.IsTrue(baseUIPermission.IsUnrestricted());

            // PrintingPermission/DefaultPrinting
            PrintingPermission basePrintingPermission = intranetBase.GetPermission(typeof(PrintingPermission)) as PrintingPermission;
            Assert.IsNotNull(basePrintingPermission);
            Assert.AreEqual(PrintingPermissionLevel.DefaultPrinting, basePrintingPermission.Level);

            // EnvironmentPermission/Read USERNAME
            EnvironmentPermission baseEnvironmentPermission = intranetBase.GetPermission(typeof(EnvironmentPermission)) as EnvironmentPermission;
            Assert.IsNotNull(baseEnvironmentPermission);
            Assert.AreEqual("USERNAME", baseEnvironmentPermission.GetPathList(EnvironmentPermissionAccess.Read));

            // ReflectionPermission/ReflectionEmit
            ReflectionPermission baseReflectionPermission = intranetBase.GetPermission(typeof(ReflectionPermission)) as ReflectionPermission;
            Assert.IsNotNull(baseReflectionPermission);
            Assert.AreEqual(ReflectionPermissionFlag.ReflectionEmit, baseReflectionPermission.Flags);

            // Unrestricted DNS permission
            DnsPermission baseDnsPermission = intranetBase.GetPermission(typeof(DnsPermission)) as DnsPermission;
            Assert.IsNotNull(baseDnsPermission);
            Assert.IsTrue(baseDnsPermission.IsUnrestricted());

            // Also check for WPF extensions
            MediaPermission baseMediaPermission = intranetBase.GetPermission(typeof(MediaPermission)) as MediaPermission;
            if (baseMediaPermission != null)
            {
                Assert.AreEqual(MediaPermissionAudio.SafeAudio, baseMediaPermission.Audio);
                Assert.AreEqual(MediaPermissionImage.SafeImage, baseMediaPermission.Image);
                Assert.AreEqual(MediaPermissionVideo.SafeVideo, baseMediaPermission.Video);
            }

            WebBrowserPermission baseWebPermission = intranetBase.GetPermission(typeof(WebBrowserPermission)) as WebBrowserPermission;
            if (baseWebPermission != null)
            {
                Assert.AreEqual(WebBrowserPermissionLevel.Safe, baseWebPermission.Level);
            }

            // Now try to extend with a local URL - we should get FileIOPermission
            Url localUrl = new Url(@"file://c:\windows");
            PermissionSet intranetLocalExtended = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, localUrl);
            Assert.IsTrue(intranetBase.IsSubsetOf(intranetLocalExtended));
            Assert.IsFalse(intranetLocalExtended.IsUnrestricted());
            Assert.AreEqual(intranetBase.Count + 1, intranetLocalExtended.Count);

            FileIOPermission filePermission = intranetLocalExtended.GetPermission(typeof(FileIOPermission)) as FileIOPermission;
            Assert.IsNotNull(filePermission);
            Assert.IsFalse(filePermission.IsUnrestricted());

            // Finally, try to extend with a Web URL, which should provide same site web access
            Url webUrl = new Url("htt://www.microsoft.com/");
            PermissionSet intranetWebExtended = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, webUrl);
            Assert.IsTrue(intranetBase.IsSubsetOf(intranetWebExtended));
            Assert.IsFalse(intranetWebExtended.IsUnrestricted());
            Assert.AreEqual(intranetBase.Count + 1, intranetWebExtended.Count);

            WebPermission webPermission = intranetWebExtended.GetPermission(typeof(WebPermission)) as WebPermission;
            Assert.IsNotNull(webPermission);
            Assert.IsFalse(webPermission.IsUnrestricted());
        }

        /// <summary>
        ///     Test to ensure the Nothing permission set comes back as expected
        /// </summary>
        [TestMethod]
        public void GetStandardPermissionSetNothingPermissionSetTest()
        {
            PermissionSet nothing = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Nothing);

            // Nothing should not be unrestricted and should be empty
            Assert.IsFalse(nothing.IsUnrestricted());
            Assert.IsTrue(nothing.IsEmpty());
            Assert.AreEqual(0, nothing.Count);
        }

        /// <summary>
        ///     Test to ensure that the GetStandardPermissionSet type fails when given an incorrect permsision 
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void GetStandardPermissionSetInvalidSetTest()
        {
            PermissionSetFactory.GetStandardPermissionSet((StandardPermissionSet)21);
        }

        /// <summary>
        ///     Test to ensure the standard sandboxes returned from GetStandardSandbox are correct
        /// </summary>
        [TestMethod]
        public void GetStandardSandboxTest()
        {
            Url fileUrl = new Url(@"\\server\share\app");
            Url webUrl = new Url("http://www.microsoft.com");

            PermissionSet nothing = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Nothing);
            PermissionSet internet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet, webUrl);
            PermissionSet localIntranet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.LocalIntranet, fileUrl);

            // No zone -> nothing
            Evidence noZone = new Evidence();
            PermissionSet noZoneSandbox = PermissionSetFactory.GetStandardSandbox(noZone);
            Assert.IsTrue(nothing.IsSubsetOf(noZoneSandbox) && noZoneSandbox.IsSubsetOf(nothing));

            // Untrusted -> Nothing
            Evidence untrustedZone = new Evidence(new object[] { new Zone(SecurityZone.Untrusted), webUrl }, null);
            PermissionSet untrustedSandbox = PermissionSetFactory.GetStandardSandbox(untrustedZone);
            Assert.IsTrue(nothing.IsSubsetOf(untrustedSandbox) && untrustedSandbox.IsSubsetOf(nothing));

            // Internet -> Internet
            Evidence internetZone = new Evidence(new object[] { new Zone(SecurityZone.Internet), webUrl }, null);
            PermissionSet internetSandbox = PermissionSetFactory.GetStandardSandbox(internetZone);
            Assert.IsTrue(internet.IsSubsetOf(internetSandbox) && internetSandbox.IsSubsetOf(internet));

            // Trusted -> Internet
            Evidence trustedZone = new Evidence(new object[] { new Zone(SecurityZone.Trusted), webUrl }, null);
            PermissionSet trustedSandbox = PermissionSetFactory.GetStandardSandbox(trustedZone);
            Assert.IsTrue(internet.IsSubsetOf(trustedSandbox) && trustedSandbox.IsSubsetOf(internet));

            // Intranet -> LocalIntranet
            Evidence intranetZone = new Evidence(new object[] { new Zone(SecurityZone.Intranet), fileUrl }, null);
            PermissionSet intranetSandbox = PermissionSetFactory.GetStandardSandbox(intranetZone);
            Assert.IsTrue(localIntranet.IsSubsetOf(intranetSandbox) && intranetSandbox.IsSubsetOf(localIntranet));

            // MyComputer -> FullTrust
            Evidence myComputerZone = new Evidence(new object[] { new Zone(SecurityZone.MyComputer), fileUrl }, null);
            PermissionSet myComputerSandbox = PermissionSetFactory.GetStandardSandbox(myComputerZone);
            Assert.IsTrue(myComputerSandbox.IsUnrestricted());
        }

        /// <summary>
        ///     Test to ensure that GetStandardSandbox fails on null evidence
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void GetStandardSandboxNullEvidenceTest()
        {
            PermissionSetFactory.GetStandardSandbox(null);
        }
    }
}
