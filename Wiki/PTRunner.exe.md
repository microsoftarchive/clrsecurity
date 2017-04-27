PTRunner is a program designed to run an application in partial trust in an easy and simple way. Under the covers it starts an AppDomain with a permission set and a full trust list and uses this AppDomain to run your application in.

PTRunner is a v4.0 binary, which requires the .NET Framework v4.0 beta 1 to operate.  The source project requires Visual Studio 2010 Beta 1 to build.

Download [release:28359](release_28359)

If you are creating AppDomains or your application uses a host, you might not be able to use this program. This program is designed to offer an easy solution to those that want to run something in partial trust and don't care about the intricacies of this endeavor.

**Example usage:**
PTRunner -af FullTrustAssembly.dll -ps Internet Program.exe

This wil run Program.exe in a sandbox granted the Internet permission set and with FullTrustAssembly.dll as full-trust

**Command Line Parameters:**
Usage:
PTRunner {"["}-nro{"](_}-nro{_)"} {"["}-ps _namedPermissionSet_{"](_}-ps-_namedPermissionSet_{_)|["}-xml _ptrunner.xml_{"](_}-xml-_ptrunner.xml_{_) ["}-af _fullTrustAssembly_{"](_}-af-_fullTrustAssembly_{_) ["}-url _sourceUrl_{"](_}-url-_sourceUrl_{_)"} _programName_ {"{"}_program arguments_{"}"}

Parameters:
| -nro | No runner output. Stops the runner from printing start and stop messages. |
| -ps | _namedPermissionSet_ The standard permission set in which should be used to sandbox the application. This can be any one of: Nothing, Execution, Internet, LocalIntranet, Everything, FullTrust |
| -xml | XmlFile File containing the permission set which should be used to sandbox the application. This permission set takes precedence over the -ps parameter. |
| -af | AddToFullTrust One assembly that you want in the full trust list. Your full trust assembly must have a strong name signature. See []("Strong-Named Assemblies"|http://msdn.microsoft.com/en-us/library/wd40t7ad.aspx) in MSDN for more information.
| -url | source URL to provide same-site access to in the sandbox |
| program arguments | arguments for the sandboxed program. The first parameter which does not begin with a "-" is considered to be the path to the program to sandbox. All subsequent parameters are considered to be parameters for the sandboxed program itself. |

**Building PTRunner**
Note that if you wish to build the PTRunner sources yourself, you must make two updates to the project:
# PTRunner.exe must be signed with a strong name signature in order to correctly operate.  This means you must supply a strong name key pair in the PTRunner project when you build it.
# PTRunner.exe depends upon Security.dll ([release:28364](release_28364)), so you will need to update the project to point at your local copy of that assembly.