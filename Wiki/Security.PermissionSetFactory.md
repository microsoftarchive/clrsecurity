# Security.PermissionSetFactory

{"The PermissionSetFactory class provides methods to easily get copies of common permission sets."} 

## APIs

### static [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) GetStandardSandbox([System.Security.Policy.Evidence](http://msdn.microsoft.com/en-us/library/system.security.policy.evidence.aspx) evidence)

{"Get a sandbox permission set which is safe to use for an assembly that has the given evidence. This is explicitly not a policy API - it instead provides guidance for hosts which can use this set in their decisions as to how to sandbox an assembly best. CAS policy is not consulted when generating this suggested permission set."} 

**Parameters:**
| evidence | {"evidence to get a standard sandbox for"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _evidence_ {"is null"}  |


### static [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) GetStandardPermissionSet([Security.StandardPermissionSet](Security.StandardPermissionSet) permissionSet)

{"Build a copy of a given standard permission set, without including any same site permissions."} 

**Parameters:**
| permissionSet | {"standard permission set to generate"}  |

**Exceptions:**
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if"} _permissionSet_ {"is not one of the standard permission sets"}  |


### static [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) GetStandardPermissionSet([Security.StandardPermissionSet](Security.StandardPermissionSet) permissionSet, [System.Security.Policy.Url](http://msdn.microsoft.com/en-us/library/system.security.policy.url.aspx) sourceUrl)

{"Build a copy of a given standard permission set, optionally extending it with same site permission for the given source URL."} 

**Parameters:**
| permissionSet | {"standard permission set to generate"}  |
| sourceUrl | {"optional source URL to generate same site permission for"}  |

**Exceptions:**
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if"} _permissionSet_ {"is not one of the standard permission sets"}  |


