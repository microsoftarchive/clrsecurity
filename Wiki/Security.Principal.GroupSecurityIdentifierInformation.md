# Security.Principal.GroupSecurityIdentifierInformation

SecurityIdentifierInformation contains a group SID and an associated set of attributes for that group. 

## APIs

### .ctor([System.Security.Principal.SecurityIdentifier](http://msdn.microsoft.com/en-us/library/system.security.principal.securityidentifier.aspx) sid, [Security.Principal.GroupSecurityIdentifierAttributes](Security.Principal.GroupSecurityIdentifierAttributes) attributes)

Create a GroupSecurityIdentifierInformation object for a SID. 

**Parameters:**
| sid | group SID to associate attributes with  |
| attributes | attributes associated with the SID  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | If _sid_ is null.  |


### [Security.Principal.GroupSecurityIdentifierAttributes](Security.Principal.GroupSecurityIdentifierAttributes) Attributes { get; }

Get the attributes associated with a group SID. 

### [System.Security.Principal.SecurityIdentifier](http://msdn.microsoft.com/en-us/library/system.security.principal.securityidentifier.aspx) SecurityIdentifier { get; }

Get the group SID associated with the attributes. 

