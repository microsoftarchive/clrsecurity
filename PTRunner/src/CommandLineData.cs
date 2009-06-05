// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;

namespace Security.Tools.PartialTrustRunner
{
    /// <summary>
    ///     This class holds the data that was parsed from the command line
    /// </summary>
    internal class CommandLineData
    {
        internal CommandLineData()
        {
            ProgramName = null;
            StandardPermissionSet = StandardPermissionSet.Execution;
            PermissionSetXml = null;
            Arguments = null;
            NoRunnerOutput = false;
            FullTrustAssemblies = new List<Assembly>();
            SourceUrl = null;
        }
        
        /// <summary>
        ///     Arguments for the program to be run
        /// </summary>
        internal string[] Arguments { get; set; }

        /// <summary>
        ///     The list of FullTrustAssemblies
        /// </summary>
        internal List<Assembly> FullTrustAssemblies { get; set; }

        /// <summary>
        ///     Flag that we will print less output
        /// </summary>
        internal bool NoRunnerOutput { get; set; }

        /// <summary>
        ///     PermissionSet XML data
        /// </summary>
        internal SecurityElement PermissionSetXml { get; set; }

        /// <summary>
        ///     The name of the program to be run
        /// </summary>
        internal string ProgramName { get; set; }

        /// <summary>
        ///     URL to provide same-site access back to within the sandboxed domain
        /// </summary>
        internal Url SourceUrl { get; set; }

        /// <summary>
        ///     The granted permission for the new program
        /// </summary>
        internal StandardPermissionSet StandardPermissionSet { get; set; }

        /// <summary>
        ///     PermissionSet to run the sandboxed application in
        /// </summary>
        internal PermissionSet PermissionSet
        {
            get
            {
                // If we got any command line XML, use that.  Otherwise use the standard permission
                // set specified.
                if (PermissionSetXml != null)
                {
                    PermissionSet grantSet = new PermissionSet(PermissionState.None);
                    grantSet.FromXml(PermissionSetXml);
                    return grantSet;
                }
                else
                {
                    return PermissionSetFactoryV4.GetStandardPermissionSet(StandardPermissionSet, SourceUrl);
                }
            }
        }
    }

}
