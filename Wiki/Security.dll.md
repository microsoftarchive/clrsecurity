# Security.dll

Security.dll provides a set of extension methods to ease working with the Code Access Security system in the .NET Framework.

## Download
[release:28364](release_28364)

## Class Reference

**[Security.PermissionSetFactory](Security.PermissionSetFactory)** - Creates instances of standard permission sets
**[Security.SandboxActivator](Security.SandboxActivator)** - Creates instances of objects with a sandbox grant set
**[Security.SandboxFactory](Security.SandboxFactory)** - Creates homogenous AppDomains
**[Security.StandardPermissionSet](Security.StandardPermissionSet)** - Enumeration of standard runtime permission sets

**[Security.Principal.GroupSecurityIdentifierAttributes](Security.Principal.GroupSecurityIdentifierAttributes)** - Attributes that can be associated with the SID of a group
**[Security.Principal.GroupSecurityIdentifierInformation](Security.Principal.GroupSecurityIdentifierInformation)** - Provides additional information about the SID of a group
**[Security.Principal.LogOnProvider](Security.Principal.LogOnProvider)** - Enumeration over the providers usable for logging a user on
**[Security.Principal.LogOnType](Security.Principal.LogOnType)** - Enumeration of types of logons that can be performed when getting a user token
**[Security.Principal.SafeTokenHandle](Security.Principal.SafeTokenHandle)** - A SafeHandle for the tokens represented by a WindowsIdentity

## Extension Methods

**[System.AppDomain](System.AppDomain)** - A set of extension methods for the AppDomain type

**[System.Reflection.Assembly](System.Reflection.Assembly)** - A set of extension methods for the Assembly type

**[System.Security.SecurityElement](System.Security.SecurityElement)** - A set of extension methods for the SecurityElement type

**[System.Security.Policy.ApplicationTrust](System.Security.Policy.ApplicationTrust)** - A set of extension methods for the ApplicationTrust type
**[System.Security.Policy.Evidence](System.Security.Policy.Evidence)** - A set of extension methods for the Evidence type
**[System.Security.Policy.StrongName](System.Security.Policy.StrongName)** - A set of extension methods for the StrongName type

**[System.Security.Principal.NTAccount](System.Security.Principal.NTAccount)** - A set of extension methods for the NTAccount type
**[System.Security.Principal.WindowsIdentity](System.Security.Principal.WindowsIdentity)** - A set of extension methods for the WindowsIdentity type