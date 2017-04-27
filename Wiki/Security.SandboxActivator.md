# Security.SandboxActivator

{""} 
{"SandboxActivator allows you to create a sandboxed instance of an object. It creates sandboxed AppDomains and activates objects in the remote domains, return a reference to the remote sandboxed object. Objects created with the same grant sets will share AppDomains, rather than each object getting its own AppDomain."} 
 {""} 
{"For example, to get an instance of an object which runs in an Internet sandbox:"} {{
PermissionSet internetGrantSet = PermissionSetFactory.GetStandardPermissionSet(StandardPermissionSet.Internet);
SandboxedObject sandboxed = SandboxActivator.CreateSandboxedInstance<SandboxedObject>(internetGrantSet);

}}
 {""} 
 {""} 

## APIs

### static T CreateSandboxedInstance<T>()

{""} 
{"Create an instance of type"} _T_ {"in an Execute only AppDomain."} 
 {""} 
{"This method is thread safe."} 
 {""} 

**Generic Parameters:**
| T | {"Type to create an execution-only instnace of"}  |


### static T CreateSandboxedInstance<T>([System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) grantSet)

{""} 
{"Create an instance of type"} _T_ {"in an AppDomain with the specified grant set."} 
 {""} 

**Generic Parameters:**
| T | {"Type to create a sandboxed instance of"}  |

**Parameters:**
| grantSet | {"Permissions to grant the object"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _grantSet_ {"is null"}  |


### static T CreateSandboxedInstance<T>([System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) grantSet, System.Collections.Generic.IEnumerable<[System.Reflection.Assembly](http://msdn.microsoft.com/en-us/library/system.reflection.assembly.aspx)> fullTrustList)

{""} 
{"Create an instance of type"} _T_ {"in an AppDomain with the specified grant set. Additionally, this domain will allow some extra full trust asemblies to be loaded into it for use by the partial trust code."} 
 {""} 
{"This method is thread safe."} 
 {""} 

**Generic Parameters:**
| T | {"Type to create a sandboxed instance of"}  |

**Parameters:**
| grantSet | {"Permission set to grant the object"}  |
| fullTrustList | {"Optional list of fullly trusted assemblies for the object to work with"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _grantSet_ {"is null"}  |


