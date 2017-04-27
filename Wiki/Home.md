**Introduction**

Welcome to the CLR security team's Codeplex site.  On this site you'll find a set of projects that extend the security APIs shipped with the .NET framework to provide additional functionality.  We also have some tools to help in debugging security related problems in your code.

The latest rollup package of all of the assemblies on this site can be found here: [release:47765](release_47765).  Note that this release will be the final release of the CLR Security CodePlex project which supports Visual Studio 2008 and the .NET Framework v3.5.

**_Did you know?_**

Elements from this project have started making their way into the .NET Framework, and [.NET Core](https://dotnet.github.io/).  Most notably, [RSACng](https://msdn.microsoft.com/en-us/library/system.security.cryptography.rsacng(v=vs.110).aspx) was added in .NET 4.6 and brought with it changes to the RSA base class so that the two implementations can be used polymorphically.

Further improvements are in progress.  If there's functionality that you depend on in Security.Cryptography.dll which has not yet been added to .NET Framework and/or .NET Core, find (or create) an issue at [https://github.com/dotnet/corefx/issues](https://github.com/dotnet/corefx/issues) and let the .NET team know!

**Project Description**: [Security.dll](Security.dll)
Security.dll provides a set of extension methods to ease working with the Code Access Security system in the .NET Framework.  Within this project you will find:
* Methods to create partially trusted instances of objects
* Methods to determine the grant set of an assembly or AppDomain
* Methods to help in creating and examining simple sandbox domains
* Methods to make working with classes like Evidence and SecurityElement easier
Download [release:47763](release_47763)

**Project Description**: [Security.Cryptography.dll](Security.Cryptography.dll)
Security.Cryptography.dll provides a new set of algorithm implementations to augment the built in .NET framework supported algorithms.  It also provides some APIs to extend the existing framework cryptography APIs.  Within this project you will find:
* A CNG implementation of the AES, RSA, HMACSHA2, and TripleDES encryption algorithms
* A CNG implementation of a random number generator
* A CNG implementation of the PBKDF2 key derivation algorithm
* A CNG implementation of authenticated symmetric encryption.
* A class that allows dynamically creating algorithms both from this library as well as all of the algorithms that ship with .NET 3.5
* An enumerator over all of the installed CNG providers on the current machine
* Extension methods that allow access to all of the keys installed in a CNG provider, as well as all of the algorithms the provider supports
* Extension methods to access X509Certificates that store their key with CNG, as well as create self signed X509Certificates.
* Other utility types and methods
_Note:_ Since functionality from Security.Cryptography.dll is migrating into the .NET Framework it may, in the interest of clarity, cease being available from this library in whatever future releases there may be.

Download [release:138352](release_138352)

**Project Description**: [Security.Cryptography.Debug.dll](Security.Cryptography.Debug.dll)
Have you ever run into an indecipherable cryptographic exception complaining about "Padding is invalid and cannot be removed" when using the .NET Framework's symmetric algorithms?  Since nearly all bugs relating to symmetric algorithms tend to result in this same exception, it can be incredibly difficult to track down exactly what went wrong to cause the exception.  Security.Cryptography.Debug.dll is a tool that can be used in these circumstances in order to help you figure out the root cause of your cryptographic exception.

Download [release:24868](release_24868)

**Project Description**: [PTRunner.exe](PTRunner.exe)
PTRunner is a host application which runs programs in a sandbox.  It allows you to choose from a set of standard CLR sandboxes (such as Execution, Internet and LocalIntranet), or provide your own custom permission sets.  Additionally, PTRunner allows you to expose a set of fully trusted assemblies to the code in the sandboxed AppDomain.

PTRunner is a .NET 4.0 application, and requires the .NET Framework v4.0 beta 1 in order to run.

Download [release:28359](release_28359)