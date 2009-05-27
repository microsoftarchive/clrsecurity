// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;

namespace Security.Policy
{
    /// <summary>
    ///     ApplicationTrustExtensionMethods provides extension methods for the <see cref="ApplicationTrust" />
    ///     class This type is in the Security.Policy namespace (not the System.Security.Policy namespace), so
    ///     in order to use these extension methods, you will need to make sure you include this namespace as
    ///     well as a reference to Security.dll.
    /// </summary>
    public static class ApplicationTrustExtensionMethods
    {
        /// <summary>
        ///     An ApplicationTrust object contains a default grant set as well as a list of assemblies which
        ///     are fully trusted. The GetFullTrustAssemblies method retrieves the strong names of assemblies
        ///     which the ApplicationTrust object considers to be fully trusted.
        /// </summary>
        public static IList<StrongName> GetFullTrustAssemblies(this ApplicationTrust applicationTrust)
        {
            List<StrongName> fullTrustAssemblies = new List<StrongName>();

            // ApplicationTrust does not expose the full trust list programatically.  To access this
            // information, we need to write out the ApplicationTrust XML and then pull out the strong names
            // from the serialized XML.
            SecurityElement applicationTrustXml = applicationTrust.ToXml();

            // First look for the FullTrustAssemblies node
            SecurityElement fullTrustAssembliesXml = null;
            if (applicationTrustXml.Children != null)
            {
                for (int i = 0; i < applicationTrustXml.Children.Count && fullTrustAssembliesXml == null; ++i)
                {
                    SecurityElement currentChild = applicationTrustXml.Children[i] as SecurityElement;
                    if (String.Equals(currentChild.Tag, "FullTrustAssemblies", StringComparison.Ordinal))
                    {
                        fullTrustAssembliesXml = currentChild;
                    }
                }
            }

            // If we found a FullTrustAssemblies node, each child will represent the strong name of one
            // fully trusted assembly
            if (fullTrustAssembliesXml != null &&
                fullTrustAssembliesXml.Children != null)
            {
                foreach (SecurityElement fullTrustAssemblyXml in fullTrustAssembliesXml.Children)
                {
                    // We only know how to parse v1 StrongName XML
                    if (String.Equals(fullTrustAssemblyXml.Tag, "StrongName", StringComparison.Ordinal) &&
                        String.Equals(fullTrustAssemblyXml.Attribute("version"), "1", StringComparison.Ordinal))
                    {
                        string assemblyName = fullTrustAssemblyXml.Attribute("Name");
                        assemblyName = assemblyName != null ? assemblyName : String.Empty;

                        string assemblyVersionString = fullTrustAssemblyXml.Attribute("Version");
                        Version assemblyVersion = assemblyVersionString != null ? new Version(assemblyVersionString) : new Version();

                        string assemblyKeyString = fullTrustAssemblyXml.Attribute("Key");
                        byte[] assemblyKey = assemblyKeyString != null ? HexToBytes(assemblyKeyString) : new byte[0];

                        StrongName fullTrustAssembly = new StrongName(new StrongNamePublicKeyBlob(assemblyKey),
                                                                      assemblyName,
                                                                      assemblyVersion);

                        fullTrustAssemblies.Add(fullTrustAssembly);
                    }
                }
            }

            return fullTrustAssemblies.AsReadOnly();
        }

        /// <summary>
        ///     Utility method to convert a signle hex digit into a byte
        /// </summary>
        private static byte ConvertHexDigit(char hexDigit)
        {
            if (hexDigit >= '0' && hexDigit <= '9')
            {
                return (byte)(hexDigit - '0');
            }
            else if (hexDigit >= 'a' && hexDigit <= 'f')
            {
                return (byte)((hexDigit - 'a') + 10);
            }
            else if (hexDigit >= 'A' && hexDigit <= 'F')
            {
                return (byte)((hexDigit - 'A') + 10);
            }
            else
            {
                Debug.Assert(false, "Invalid hex digit");
                return 0;
            }
        }

        /// <summary>
        ///     Utility method to convert a hex string into the corresponding byte array
        /// </summary>
        private static byte[] HexToBytes(string assemblyKeyString)
        {
            Debug.Assert(assemblyKeyString != null, "assemblyKeyString != null");
            Debug.Assert(assemblyKeyString.Length % 2 == 0, "assemblyKeyString.Length %2 == 0");

            byte[] key = new byte[assemblyKeyString.Length / 2];

            for (int i = 0; i < assemblyKeyString.Length; i += 2)
            {
                key[i / 2] = (byte)((ConvertHexDigit(assemblyKeyString[i]) << 4) |
                                    (ConvertHexDigit(assemblyKeyString[i + 1])));
            }

            return key;
        }
    }
}
