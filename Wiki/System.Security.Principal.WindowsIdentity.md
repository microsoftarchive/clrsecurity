# System.Security.Principal.WindowsIdentity

Extension methods for the [System.Security.Principal.WindowsIdentity](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.aspx) class. These extension methods are in the Security.Principal namespace, so in order to use them both the Security.Principal and System.Security.Principal namespaces must be included in your code. 

## APIs

### System.Collections.Generic.IEnumerable<[Security.Principal.GroupSecurityIdentifierInformation](Security.Principal.GroupSecurityIdentifierInformation)> GetAllGroups()

Get the group information for all of the groups that associated with the [System.Security.Principal.WindowsIdentity](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.aspx) . This is different from the standard [System.Security.Principal.WindowsIdentity.Groups](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.groups.aspx) property in that none of the returned groups are filtered out. Before using any of the groups, it is important to ensure that they are enabled and not for deny-only by checking their attributes. 

**Return Value:**
A collection of [Security.Principal.GroupSecurityIdentifierInformation](Security.Principal.GroupSecurityIdentifierInformation) objects containing the group SIDs which are attacked to the WindowsIdentity's token, as well as the associated attributes. 


### [Security.Principal.SafeTokenHandle](Security.Principal.SafeTokenHandle) GetSafeTokenHandle()

Get a SafeHandle for the token that the WindowsIdentity represents. 

**Return Value:**
A [Security.Principal.SafeTokenHandle](Security.Principal.SafeTokenHandle) for the token of the WindowsIdentity. This token handle can be used beyond the lifetime of the originating WindowsIdentity object and must be disposed of seperately. 


### bool IsAdministrator()

Determine if the a WindowsIdentity is in the Administrator role 


