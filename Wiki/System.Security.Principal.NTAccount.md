# System.Security.Principal.NTAccount

{"Extension methods for the"} [System.Security.Principal.NTAccount](http://msdn.microsoft.com/en-us/library/system.security.principal.ntaccount.aspx) {"class. These extension methods are in the Security.Principal namespace, so in order to use them both the Security.Principal and System.Security.Principal namespaces must be included in your code."} 

## APIs

### [System.Security.Principal.WindowsIdentity](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.aspx) LogOnUser([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) password)

{"Log a user on using a clear string password. This method uses the default logon provider and performs an interactive logon."} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"This method demands SecurityPermission/ControlPrincipal"}  |


### [System.Security.Principal.WindowsIdentity](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.aspx) LogOnUser([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) password, [Security.Principal.LogOnType](Security.Principal.LogOnType) logOnType, [Security.Principal.LogOnProvider](Security.Principal.LogOnProvider) logOnProvider)

{"Log a user on using a clear string password, specifying the logon type and provider to use."} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"This method demands SecurityPermission/ControlPrincipal"}  |


### [System.Security.Principal.WindowsIdentity](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.aspx) LogOnUser([System.Security.SecureString](http://msdn.microsoft.com/en-us/library/system.security.securestring.aspx) password)

{"Log a user on using a secure password. This method uses the default logon provider and performs an interactive logon."} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"This method demands SecurityPermission/ControlPrincipal"}  |


### [System.Security.Principal.WindowsIdentity](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.aspx) LogOnUser([System.Security.SecureString](http://msdn.microsoft.com/en-us/library/system.security.securestring.aspx) password, [Security.Principal.LogOnType](Security.Principal.LogOnType) logOnType, [Security.Principal.LogOnProvider](Security.Principal.LogOnProvider) logOnProvider)

{"Log a user on using a secure password, specifying the logon type and provider to use."} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"This method demands SecurityPermission/ControlPrincipal"}  |


