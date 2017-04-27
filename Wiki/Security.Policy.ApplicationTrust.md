# System.Security.Policy.ApplicationTrust

ApplicationTrustExtensionMethods provides extension methods for the [System.Security.Policy.ApplicationTrust](http://msdn.microsoft.com/en-us/library/system.security.policy.applicationtrust.aspx) class This type is in the Security.Policy namespace (not the System.Security.Policy namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.dll. 

## APIs

### System.Collections.Generic.IList<[System.Security.Policy.StrongName](http://msdn.microsoft.com/en-us/library/system.security.policy.strongname.aspx)> GetFullTrustAssemblies()

An ApplicationTrust object contains a default grant set as well as a list of assemblies which are fully trusted. The GetFullTrustAssemblies method retrieves the strong names of assemblies which the ApplicationTrust object considers to be fully trusted. 
