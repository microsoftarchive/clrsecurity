// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using System.Text;
using Security.Reflection;
using Security.Tools.PartialTrustRunner.Properties;

namespace Security.Tools.PartialTrustRunner
{
    /// <summary>
    ///     This tool will launch an executable in a restricted grant set.
    /// </summary>
    internal static class Program
    {
        private static int? s_consoleWidth;

        /// <summary>
        ///     Get the number of characters of text that can fit in one output line.
        /// </summary>
        internal static int ConsoleWidth
        {
            get
            {
                if (!s_consoleWidth.HasValue)
                {
                    int consoleWidth = Int32.MaxValue;

                    try
                    {
                        consoleWidth = Console.BufferWidth;
                    }
                    catch (IOException)
                    {
                        // BufferWidth throws an IOException if there is no console attached - there's
                        // currently no way to detect this situation, so we just eat the exception.
                    }

                    s_consoleWidth = consoleWidth;
                }

                return s_consoleWidth.Value;
            }
        }

        /// <summary>
        ///     Print the usage of the program
        /// </summary>
        [SecuritySafeCritical]
        private static void Usage()
        {
            string name = Process.GetCurrentProcess().ProcessName;
            string possibleVals = Enum.GetNames(typeof(StandardPermissionSet)).Aggregate((workset, next) => workset + ", " + next);

            WriteOutput(Resources.CommandLine1);
            WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.CommandLine2, name));
            WriteOutput();
            WriteOutput(Resources.CommandLine3);
            WriteOutput(Resources.CommandLine4, "    ");
            WriteOutput();
            WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.CommandLine5, possibleVals), "    ");
            WriteOutput();
            WriteOutput(Resources.CommandLine6, "    ");
            WriteOutput();
            WriteOutput(Resources.CommandLine7, "    ");
            WriteOutput();
            WriteOutput(Resources.CommandLine8, "    ");
            WriteOutput();
            WriteOutput(Resources.CommandLine9);
            WriteOutput();
            WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.CommandLine10, name));
            WriteOutput(Resources.CommandLine11);
            WriteOutput();
            WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.CommandLine12, name));
            WriteOutput();
            WriteOutput(Resources.CommandLine13);
            WriteOutput();
            WriteOutput(Resources.CommandLine14);
            WriteOutput(Resources.CommandLine15);
        }

        /// <summary>
        ///     Command line parser.
        /// </summary>
        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Reflection.Assembly.LoadFrom", Justification = "We need to LoadFrom this assembly in order to get its StrongName")]
        private static CommandLineData ParseCommandLine(string[] args)
        {
            Contract.Requires(args != null);

            try
            {
                int i = 0;

                CommandLineData ret = new CommandLineData();

                // The partial trust runner assembly needs to be in the full trust list in the
                // sandboxed domain in order to correctly function in that domain
                ret.FullTrustAssemblies.Add(Assembly.GetExecutingAssembly());

                // First search for parameters to control PartialTrustRunner itself
                while (i < args.Length && args[i].StartsWith("-", StringComparison.OrdinalIgnoreCase))
                {
                    // Add full trust assembly
                    if (String.Equals(args[i], "-af", StringComparison.OrdinalIgnoreCase))
                    {
                        Assembly asm = Assembly.LoadFrom(args[++i]);
                        ret.FullTrustAssemblies.Add(asm);
                    }
                    // Suppress PartialTrustRunner output
                    else if (String.Equals(args[i], "-nro", StringComparison.OrdinalIgnoreCase))
                    {
                        ret.NoRunnerOutput = true;
                    }
                    // The partial trust PermissionSet
                    else if (String.Equals(args[i], "-ps", StringComparison.OrdinalIgnoreCase))
                    {
                        ret.StandardPermissionSet = (StandardPermissionSet)Enum.Parse(typeof(StandardPermissionSet), args[++i], true);
                    }
                    // URL to provide same-site access to
                    else if (String.Equals(args[i], "-url", StringComparison.OrdinalIgnoreCase))
                    {
                        ret.SourceUrl = new Url(args[++i]);
                    }
                    // Permission set XML file
                    else if (String.Equals(args[i], "-xml", StringComparison.OrdinalIgnoreCase))
                    {
                        using (StreamReader sr = new StreamReader(args[++i]))
                        {
                            SecurityElement elem = SecurityElement.FromString(sr.ReadToEnd());
                        }
                    }
                    else
                    {
                        WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.UnknownOption, args[i]));
                        Usage();
                        return null;
                    }

                    ++i;
                }

                // If we still have parameters left, they should go through to the program that will be run
                if (i < args.Length)
                {
                    // The first parameter is the application itself
                    ret.ProgramName = args[i++];

                    // Any remaining parameters are for the application itself
                    int argsSize = args.Length - i;
                    ret.Arguments = new string[argsSize];
                    if (argsSize > 0)
                    {
                        Array.Copy(args, i, ret.Arguments, 0, argsSize);
                    }

                    // We only want to return success if we found arguments for the program, since
                    // otherwise we don't know what program to run in the sandbox
                    return ret;
                }
            }
            catch (ArgumentException ex)
            {
                WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.ErrorParsingCommandLine, ex.Message));
            }
            catch (InvalidOperationException ex)
            {
                WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.ErrorParsingCommandLine, ex.Message));
            }

            // If we got here, we have an invalid command line
            Usage();
            return null;
        }

        /// <summary>
        ///     The main function of the runner
        /// </summary>
        [SecuritySafeCritical]
        internal static int Main(string[] args)
        {
            try
            {
                // Make sure that we have a strong name signature, otherwise we won't be able
                // to correctly trust this assembly in the sandboxed domain.
                if (Assembly.GetExecutingAssembly().Evidence.GetHostEvidence<StrongName>() == null)
                {
                    WriteOutput(Resources.PartialTrustRunnerUnsigned);
                    return -1;
                }

                // Parse the command line - and make sure it is valid
                CommandLineData commands = ParseCommandLine(args);
                if (commands == null)
                {
                    return -1;
                }

                AppDomainSetup sandboxSetup = new AppDomainSetup();
                
                // We need the AppDomain to have its AppBase be in the same location as the target
                // program.  This allows the application to find all of its dependencies correctly
                sandboxSetup.ApplicationBase = Path.GetDirectoryName(Path.GetFullPath(commands.ProgramName));

                // The application name should match the entry point
                sandboxSetup.ApplicationName = Path.GetFileNameWithoutExtension(commands.ProgramName);

                // We also want the AppDomain to use the .exe.config file that the target has
                // specified for itself (if it exists)
                string configFile = Path.GetFullPath(commands.ProgramName) + ".config";
                if (File.Exists(configFile))
                {
                    sandboxSetup.ConfigurationFile = configFile;
                }

                // Get strong names for the full trust assemblies
                var fullTrustStrongNames = from fullTrustAssembly in commands.FullTrustAssemblies
                                           where fullTrustAssembly.Evidence.GetHostEvidence<StrongName>() != null
                                           select fullTrustAssembly.Evidence.GetHostEvidence<StrongName>();

                // Create the sandboxed domain
                AppDomain sandbox = AppDomain.CreateDomain(Path.GetFileNameWithoutExtension(commands.ProgramName),
                                                           null,
                                                           sandboxSetup,
                                                           commands.PermissionSet,
                                                           fullTrustStrongNames.ToArray());

                // Create an instance of our runner trampoline in the sandbox
                ObjectHandle runnerHandle = Activator.CreateInstanceFrom(sandbox,
                                                                         typeof(AssemblyRunner).Assembly.Location,
                                                                         typeof(AssemblyRunner).FullName);
                AssemblyRunner runner = runnerHandle.Unwrap() as AssemblyRunner;

                // Use the runner to execute the target assembly, and return the result of the assembly's
                // Main method.
                return runner.ExecuteAssembly(commands.ProgramName, commands.Arguments, commands.NoRunnerOutput);
            }
            catch (Exception ex)
            {
                WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.GeneralError, ex.Message));
                return -1;
            }
        }

        /// <summary>
        ///     Write an empty line to the output
        /// </summary>
        internal static void WriteOutput()
        {
            WriteOutput(String.Empty);
        }

        /// <summary>
        ///     Write a message to the output location, splitting long lines for screen size if it is a
        ///     console output.
        /// </summary>
        internal static void WriteOutput(string message)
        {
            WriteOutput(message, String.Empty);
        }

        /// <summary>
        ///     Write a message to the output location, splitting long lines for screen size if it is a
        ///     console output.
        /// </summary>
        internal static void WriteOutput(string message, string linePrefix)
        {
            Contract.Requires(message != null);
            Contract.Requires(linePrefix != null);

            List<string> lines = new List<string>();

            StringBuilder currentLine = new StringBuilder();
            currentLine.Append(linePrefix);

            foreach (string word in message.Split(' '))
            {
                if (currentLine.Length + word.Length + 1 >= ConsoleWidth)
                {
                    Console.WriteLine(currentLine.ToString());
                    lines.Add(currentLine.ToString());
                    currentLine = new StringBuilder();
                    currentLine.Append(linePrefix);
                }

                currentLine.Append(word);
                currentLine.Append(' ');
            }

            if (currentLine.Length > 0)
            {
                Console.WriteLine(currentLine.ToString());
            }
        }
    }
}
