# System.Reflection.Assembly

AssemblyExtensionMethods provides several extension methods for the [System.Reflection.Assembly](http://msdn.microsoft.com/en-us/library/system.reflection.assembly.aspx) class. This type is in the Security.Reflection namespace (not the System.Reflection namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.dll. 

## APIs

### [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) GetPermissionSet()

The GetPermissionSet method returns the permission set that an assembly is granted. This method works for assemblies loaded via implicit loads, or explicit calls to [System.Reflection.Assembly.Load(System.String)](http://msdn.microsoft.com/en-us/library/system.reflection.assembly.load.aspx) or [System.Reflection.Assembly.LoadFrom(System.String)](http://msdn.microsoft.com/en-us/library/system.reflection.assembly.loadfrom.aspx) . Results may not be accurate for assemblies loaded via [System.Reflection.Assembly.Load(System.Byte(array))](http://msdn.microsoft.com/en-us/library/system.reflection.assembly.load.aspx) , or dynamic assemblies created with [System.AppDomain.DefineDynamicAssembly(System.Reflection.AssemblyName,System.Reflection.Emit.AssemblyBuilderAccess)](http://msdn.microsoft.com/en-us/library/system.appdomain.definedynamicassembly.aspx) . 

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | This method requries its immediate caller to be fully trusted  |


### [System.Security.Policy.StrongName](http://msdn.microsoft.com/en-us/library/system.security.policy.strongname.aspx) GetStrongName()

Get an assembly's strong name. 
The [System.Security.Policy.StrongName](http://msdn.microsoft.com/en-us/library/system.security.policy.strongname.aspx) object returned may be different from the strong name in the assembly's evidence if a host has chosen to customize the evidence the assembly was loaded with. 

**Exceptions:**
| [System.ArgumentException](http://msdn.microsoft.com/en-us/library/system.argumentexception.aspx) | if the assembly is not strongly named  |


### bool IsFullyTrusted()

Determine if an assembly is granted full trust in the current domain. 
Results may not be accurate for assemblies loaded via [System.Reflection.Assembly.Load(System.Byte(array))](http://msdn.microsoft.com/en-us/library/system.reflection.assembly.load.aspx) , or dynamic assemblies created with [System.AppDomain.DefineDynamicAssembly(System.Reflection.AssemblyName,System.Reflection.Emit.AssemblyBuilderAccess)](http://msdn.microsoft.com/en-us/library/system.appdomain.definedynamicassembly.aspx) 


### bool IsStrongNamed()

Determine if an assembly is strong name signed. This method does not attempt to detect if the assembly is delay signed and loaded because of a skip verification entry on the machine. 
