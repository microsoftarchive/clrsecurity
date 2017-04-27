# Security.SandboxFactory

{"SandboxFactory can be used to wrap the process of making a simple homogenous domain"} 

## APIs

### static [System.AppDomain](http://msdn.microsoft.com/en-us/library/system.appdomain.aspx) CreateSandbox([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) applicationBase, [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) grantSet)

{"Create a homogenous sandboxed AppDomain rooted at the specified AppBase"} 

**Parameters:**
| applicationBase | {"location where the application to be sandboxed lives"}  |
| grantSet | {"permissions to grant the sandbox"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _applicationBase_ {"or"} _grantSet_ {"are null"}  |


### static [System.AppDomain](http://msdn.microsoft.com/en-us/library/system.appdomain.aspx) CreateSandbox([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) applicationBase, [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) grantSet, System.Reflection.Assembly[]() fullTrustAssemblies)

{"Create a homogenous AppDomain rooted at the specified AppBase, which has an optional collection of full trust assemblies"} 

**Parameters:**
| applicationBase | {"location where the application to be sandboxed lives"}  |
| grantSet | {"permissions to grant the sandbox"}  |
| fullTrustAssemblies | {"optional list of assemblies to grant full trust in the sandbox"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _applicationBase_ {"or"} _grantSet_ {"are null"}  |


