// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Contracts;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using Security.Tools.PartialTrustRunner.Properties;

namespace Security.Tools.PartialTrustRunner
{
    /// <summary>
    ///     The runner. This class will be instantiated in the new sandboxed AppDomain, and is used
    ///     as a trampoline for PartialTrustRunner to start up the client program.
    /// </summary>
    internal class AssemblyRunner : MarshalByRefObject
    {
        /// <summary>
        ///     Execute the client assembly. Arguments are passed to Main
        /// </summary>
        /// <param name="assemblyPath">The path to the assembly</param>
        /// <param name="arguments">Arguments to the Main method</param>
        /// <param name="noRunnerOutput">Stop the runner from printing output before and after running the program</param>
        /// <returns>The return of the application</returns>
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = "This needs to be an instance method so that we can call it from across AppDomain boundaries")]
        [SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes", Justification = "All exceptions must be caught for security purposes - see the comment in the code")]
        internal int ExecuteAssembly(string assemblyPath, string[] arguments, bool noRunnerOutput)
        {
            Contract.Requires(assemblyPath != null);
            Contract.Requires(arguments != null);

            // Get a delegate around Main
            Func<string[], int> main = ConstructMainAdapter(assemblyPath);

            if (!noRunnerOutput)
            {
                PrintStart(assemblyPath, arguments);
            }

            // Run Main.  We need to catch any exception thrown from here, since we don't want them
            // to deserialize in the default app domain which is not sandboxed.
            int ret = 0;
            try
            {
                ret = main(arguments);
            }
            catch (Exception ex)
            {
                Program.WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.ExceptionLeaked, ex.ToString()));
                return -1;
            }

            if (!noRunnerOutput)
            {
                PrintStop(ret);
            }

            return ret;
        }

        /// <summary>
        ///     Print some pretty information about program startup
        /// </summary>
        private static void PrintStart(string assemblyPath, string[] arguments)
        {
            Contract.Requires(assemblyPath != null);
            Contract.Requires(arguments != null);

            string args = String.Empty;
            if (arguments.Length > 0)
            {
                args = " " + arguments.Aggregate((workingSentence, next) => workingSentence + " " + next);
            }

            Program.WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.StartingApplication, assemblyPath, args));
        }

        /// <summary>
        ///     Print some pretty information about program shutdown
        /// </summary>
        private static void PrintStop(int ret)
        {
            Program.WriteOutput(String.Format(CultureInfo.CurrentCulture, Resources.ApplicationExit, ret));
        }

        /// <summary>
        ///     This method is in charge of creating the propper main-delegate adapter. It loads 
        ///     the assembly, gets the entry point and makes a decision about which adapter to create.
        /// <remarks>
        ///     Because there are a total of four possible signatures for main, we need special logic
        ///     to convert all of them to a single, simpler to use signature.
        ///     The reason we are not using dirrectly MethodInfo.Invoke is that we would have to 
        ///     grant a ReflectionPermission and this would "polute" the sandbox with that permission. 
        ///  </remarks>
        /// </summary>
        /// <param name="assemblyPath">The assembly which will be executed</param>
        /// <returns>A simple adapter for the main function</returns>
        [PermissionSet(SecurityAction.Assert, Unrestricted=true)]
        [SecuritySafeCritical]
        private static Func<string[], int> ConstructMainAdapter(string assemblyPath)
        {
            Contract.Requires(assemblyPath != null);
            Contract.Ensures(Contract.Result<Func<string[], int>>() != null);

            Assembly a = Assembly.Load(Path.GetFileNameWithoutExtension(assemblyPath));
            MethodInfo mi = a.EntryPoint;

            // MSDN says there are only void/int return values, and non/string[] for parameter. 
            // That makes a total of 4 possible delegates
            if (mi.ReturnType == typeof(void) && mi.GetParameters().Length == 0)
            {
                return GetAdapterForVoidWithNoArgs(mi);
            }
            else if (mi.ReturnType == typeof(void) && mi.GetParameters().Length > 0)
            {
                return GetAdapterForVoidWithArgs(mi);
            }
            else if (mi.ReturnType == typeof(int) && mi.GetParameters().Length == 0)
            {
                return GetAdapterForIntWithNoArgs(mi);
            }
            else
            {
                Debug.Assert(mi.ReturnType == typeof(int) && mi.GetParameters().Length > 0,
                             "Found entrypoint with not supported signature");
                return GetAdapterForIntWithArgs(mi);
            }
        }

        /// <summary>
        ///     Return a Func<string[], int> delegate type that wraps around mi. 
        ///     This function treats the int Main(string []args) signature
        /// </summary>
        /// <param name="mi">The method to be adapted</param>
        private static Func<string[], int> GetAdapterForIntWithArgs(MethodInfo mi)
        {
            Contract.Requires(mi != null);
            Contract.Ensures(Contract.Result<Func<string[], int>>() != null);

            Func<string[], int> dlg = (Func<string[], int>)Delegate.CreateDelegate(typeof(Func<string[], int>), mi);
            return ((string[] args) => { return dlg(args); });
        }

        /// <summary>
        ///     Return a Func<string[], int> delegate type that wraps around mi. 
        ///     This function treats the void Main(string []args) signature
        /// </summary>
        /// <param name="mi">The method to be adapted</param>
        private static Func<string[], int> GetAdapterForVoidWithArgs(MethodInfo mi)
        {
            Contract.Requires(mi != null);
            Contract.Ensures(Contract.Result<Func<string[], int>>() != null);

            Action<string[]> dlg = (Action<string[]>)Delegate.CreateDelegate(typeof(Action<string[]>), mi);
            return ((string[] args) => { dlg(args); return 0; });
        }

        /// <summary>
        ///     Return a Func<string[], int> delegate type that wraps around mi. 
        ///     This function treats the int Main() signature
        /// </summary>
        /// <param name="mi">The method to be adapted</param>
        private static Func<string[], int> GetAdapterForIntWithNoArgs(MethodInfo mi)
        {
            Contract.Requires(mi != null);
            Contract.Ensures(Contract.Result<Func<string[], int>>() != null);

            Func<int> dlg = (Func<int>)Delegate.CreateDelegate(typeof(Func<int>), mi);
            return ((string[] args) => { return dlg(); });
        }

        /// <summary>
        ///     Return a Func<string[], int> delegate type that wraps around mi. 
        ///     This function treats the void Main() signature
        /// </summary>
        /// <param name="mi">The method to be adapted</param>
        private static Func<string[], int> GetAdapterForVoidWithNoArgs(MethodInfo mi)
        {
            Contract.Requires(mi != null);
            Contract.Ensures(Contract.Result<Func<string[], int>>() != null);

            Action dlg = (Action)Delegate.CreateDelegate(typeof(Action), mi);
            return ((string[] args) => { dlg(); return 0; });
        }
    }
}
