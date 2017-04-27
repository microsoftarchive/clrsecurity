# System.AppDomain

AppDomainExtensionMethods provides several extension methods for the [System.AppDomain](http://msdn.microsoft.com/en-us/library/system.appdomain.aspx) class. This type is in the Security namespace (not the System namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.dll. 

## APIs

### [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) GetPermissionSet()

Get the permission set that the current AppDomain is sandboxed with. This is the permission set which is used if a security demand crosses the AppDomain boundary. 

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | This method requries its immediate caller to be fully trusted  |


### bool IsHomogenous()

Detect if an AppDomain is a simple sandbox style domain, created by passing a PermissionSet to the [System.AppDomain.CreateDomain(System.String,System.Security.Policy.Evidence,System.AppDomainSetup,System.Security.PermissionSet,System.Security.Policy.StrongName(array))](http://msdn.microsoft.com/en-us/library/system.appdomain.createdomain.aspx) call. 

**Return Value:**
True if the domain is a simple sandbox; false if it is a legacy v1.x domain. 


### bool IsSandboxed()

Determine if an AppDomain is sandboxed 

**Return Value:**
True if the AppDomain has a grant set other than FullTrust 
