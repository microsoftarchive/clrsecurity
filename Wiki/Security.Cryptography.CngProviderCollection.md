# Security.Cryptography.CngProviderCollection

{""} 
{"The CngProviderCollection class implements an enumerator over the installed CNG providers on the machine. The enumerator specifically lists the NCrypt key storage providers, and does not work with the BCrypt layer of CNG."} 
 {""} 
{"CngProviderCollection uses the NCrypt layer of CNG to do its work, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 

## APIs

### System.Collections.Generic.IEnumerator<[System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx)> GetEnumerator()

{"Get an enumerator containing a"} [System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) {"for each of the installed NCrypt key storage providers on the current machine."} 


