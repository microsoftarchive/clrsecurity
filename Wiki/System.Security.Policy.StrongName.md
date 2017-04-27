# System.Security.Policy.StrongName

StrongNameExtensionMethods provides several extension methods for the [System.Security.Policy.StrongName](http://msdn.microsoft.com/en-us/library/system.security.policy.strongname.aspx) class. This type is in the Security.Policy namespace (not the System.Security.Policy namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.dll. 

## APIs

### [System.Security.Policy.StrongNameMembershipCondition](http://msdn.microsoft.com/en-us/library/system.security.policy.strongnamemembershipcondition.aspx) CreateMembershipCondition()

The CreateMembershipCondition method builds a membership condition which exactly matches the strong name (including version). 
