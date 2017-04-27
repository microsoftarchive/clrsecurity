# Security.Cryptography.Oid2

{""} 
{"Oid2 is an enhanced OID type over the"} [System.Security.Cryptography.Oid](http://msdn.microsoft.com/en-us/library/system.security.cryptography.oid.aspx) {"type. Oid2 provides some performance benefits when it is used to lookup OID information since it can do more directed queries than Oid does. It also exposes additional information about the OID, such as group and algortihm mappings for CAPI and CNG."} 
 {""} 
{"One notable difference between Oid2 and Oid is that Oid2 will never query for information about an Oid unless specifically instructed to via a call to EnumerateOidInformation or one of the FindBy methods. Simply constructing an Oid2 type does not trigger a lookup on information not provided."} 
 {""} 

## APIs

### .ctor([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid, [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName)

{"Constructs an Oid2 object with the given value and friendly name. No lookup is done for further information on this OID. It is assigned a group of AllGroups and no algorithm mapping."} 

**Parameters:**
| oid | {"value of this OID"}  |
| friendlyName | {"friendly name for the OID"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _oid_ {"or"} _friendlyName_ {"are null"}  |


### .ctor([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid, [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group)

{"Constructs an Oid2 object with the given value and friendly name belonging to a specific group. No lookup is done for further information on this OID. It has no algorithm mapping."} 

**Parameters:**
| oid | {"value of this OID"}  |
| friendlyName | {"friendly name for the OID"}  |
| group | {"group the OID belongs to"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _oid_ {"or"} _friendlyName_ {"are null"}  |


### .ctor([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid, [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) cngAlgorithm, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) extraCngAlgorithm)

{"Constructs an Oid2 object with the given value and friendly name belonging to a specific group. No lookup is done for further information on this OID. It has no CAPI algorithm mapping, but does have optional CNG algorithm mappings."} 

**Parameters:**
| oid | {"value of this OID"}  |
| friendlyName | {"friendly name for the OID"}  |
| group | {"group the OID belongs to"}  |
| cngAlgorithm | {"CNG algorithm that this OID represents"}  |
| extraCngAlgorithm | {"additional CNG algorithm this OID represents"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _oid_ {"or"} _friendlyName_ {"are null"}  |


### .ctor([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid, [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group, int capiAlgorithm, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) cngAlgorithm, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) extraCngAlgorithm)

{"Constructs an Oid2 object with the given value and friendly name belonging to a specific group. No lookup is done for further information on this OID. It has both a CAPI algorithm mapping and optional CNG algorithm mappings."} 

**Parameters:**
| oid | {"value of this OID"}  |
| friendlyName | {"friendly name for the OID"}  |
| group | {"group the OID belongs to"}  |
| capiAlgorithm | {"CAPI algorithm ID that this OID represents"}  |
| cngAlgorithm | {"CNG algorithm that this OID represents"}  |
| extraCngAlgorithm | {"additional CNG algorithm this OID represents"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _oid_ {"or"} _friendlyName_ {"are null"}  |


### int AlgorithmId { get; }

{"Get the CAPI algorithm ID represented by this OID."} 
**Exceptions:**
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if HasAlgorithmId is false"}  |



### [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) CngAlgorithm { get; }

{"Get the CNG algorithm that this OID represents."} 

### [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) CngExtraAlgorithm { get; }

{"Get an additional CNG algorithm that this OID represents."} 

### [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) FriendlyName { get; }

{"Get the friendly name of the OID."} 

### [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) Group { get; }

{"Get the OID group that this OID belongs to."} 

### bool HasAlgorithmId { get; }

{"Determines if the OID has a CAPI algorithm ID that it maps to, available in the AlgorithmId property. This property does not check to see if the OID has matching CNG algorithms, which can be checked by checking the CngAlgorithm property for null."} 

### [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) Value { get; }

{"Get the string representation of the OID."} 

### static System.Collections.Generic.IEnumerable<[Security.Cryptography.Oid2](Security.Cryptography.Oid2)> EnumerateOidInformation()

{"This overload of EnumerateOidInformation returns an enumerator containing an Oid2 object for every OID registered regardless of group."} 


### static System.Collections.Generic.IEnumerable<[Security.Cryptography.Oid2](Security.Cryptography.Oid2)> EnumerateOidInformation([Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group)

{"This overload of EnumerateOidInformation returns an enumerator containing an Oid2 object for every OID registered as belonging to a specific OID group."} 

**Parameters:**
| group | {"OID group to enumerate, AllGroups to enumerate every OID"}  |


### static [Security.Cryptography.Oid2](Security.Cryptography.Oid2) FindByFriendlyName([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName)

{"This overload of FindByFriendlyName searches for any OID registered on the local machine with the specified friendly name. It looks in all OID groups for an OID matching the name, but does not look in the Active Directory for a matching OID. If no match is found, null is returned."} 

**Parameters:**
| friendlyName | {"name of the OID to search for"}  |


### static [Security.Cryptography.Oid2](Security.Cryptography.Oid2) FindByFriendlyName([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group)

{"This overload of FindByFriendlyName searches for any OID registered on the local machine with the specified friendly name. It looks only in the specified OID groups for an OID matching the name, and does not look in the Active Directory for a matching OID. If no match is found, null is returned."} 

**Parameters:**
| friendlyName | {"name of the OID to search for"}  |
| group | {"OID group to enumerate, AllGroups to enumerate every OID"}  |


### static [Security.Cryptography.Oid2](Security.Cryptography.Oid2) FindByFriendlyName([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) friendlyName, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group, bool useNetworkLookup)

{"This overload of FindByFriendlyName searches for any OID registered on the local machine with the specified friendly name. It looks only in the specified OID groups for an OID matching the name, and can optionally look in the Active Directory for a matching OID. If no match is found, null is returned."} 

**Parameters:**
| friendlyName | {"name of the OID to search for"}  |
| group | {"OID group to enumerate, AllGroups to enumerate every OID"}  |
| useNetworkLookup | {"true to look in the Active Directory for a match, false to skip network lookup"}  |


### static [Security.Cryptography.Oid2](Security.Cryptography.Oid2) FindByValue([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid)

{"This overload of FindByValue searches for any OID registered on the local machine with the specified OID value. It looks in all OID groups for an OID matching the value, but does not look in the Active Directory for a matching OID. If no match is found, null is returned."} 

**Parameters:**
| oid | {"oid to search for"}  |


### static [Security.Cryptography.Oid2](Security.Cryptography.Oid2) FindByValue([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group)

{"This overload of FindByValue searches for any OID registered on the local machine with the specified value. It looks only in the specified OID groups for an OID matching the value, and does not look in the Active Directory for a matching OID. If no match is found, null is returned."} 

**Parameters:**
| oid | {"oid to search for"}  |
| group | {"OID group to enumerate, AllGroups to enumerate every OID"}  |


### static [Security.Cryptography.Oid2](Security.Cryptography.Oid2) FindByValue([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) oid, [Security.Cryptography.OidGroup](Security.Cryptography.OidGroup) group, bool useNetworkLookup)

{"This overload of FindByValue searches for any OID registered on the local machine with the specified value. It looks only in the specified OID groups for an OID matching the value, and can optionally look in the Active Directory for a matching OID. If no match is found, null is returned."} 

**Parameters:**
| oid | {"oid to search for"}  |
| group | {"OID group to enumerate, AllGroups to enumerate every OID"}  |
| useNetworkLookup | {"true to look in the Active Directory for a match, false to skip network lookup"}  |


### void Register()

{"Register the OID on the local machine, so that later processes can query for the OID and include it in enumerations. This method requires that the caller be fully trusted, and that the user context that the calling application be run under be an Administrator on the machine. Updating the registration table may have no effect on the current process, if Windows has already read them. Instead, the process may need to be restarted to reflect the registration changes. This overload of Register places the OID after the built in OIDs."} 

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | {"The immediate caller of this API must be fully trusted"}  |


### void Register([Security.Cryptography.OidRegistrationOptions](Security.Cryptography.OidRegistrationOptions) registrationOptions)

{"Register the OID on the local machine, so that later processes can query for the OID and include it in enumerations. This method requires that the caller be fully trusted, and that the user context that the calling application be run under be an Administrator on the machine. Updating the registration table may have no effect on the current process, if Windows has already read them. Instead, the process may need to be restarted to reflect the registration changes. This overload of Register can places the OID either before or after the built in OIDs depending on the registration options."} 

**Parameters:**
| registrationOptions | {"settings to register the OID with"}  |

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | {"The immediate caller of this API must be fully trusted"}  |


### static void RegisterSha2OidInformationForRsa()

{""} 
{"On Windows 2003, the default OID -> algorithm ID mappings for the SHA2 family of hash algorithms are not setup in a way that the .NET Framework v3.5 SP1 can understand them when creating RSA-SHA2 signatures. This method can be used to update the registrations on Windows 2003 so that RSA-SHA2 signatures work as expected."} 
 {""} 
{"To call this method, the calling code must be fully trusted and running as an Administrator on the machine. If OID tables have already been read for the process, then the process may need to be restarted for the registration to take effect. Therefore, it is recommended to use this method in a setup program or as the first line of code in your application."} 
 {""} 
{"While not required, this method will work on other versions of Windows and the .NET Framework."} 
 {""} 

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | {"This API requires that its immediate caller be fully trusted"}  |


### [System.Security.Cryptography.Oid](http://msdn.microsoft.com/en-us/library/system.security.cryptography.oid.aspx) ToOid()

{"Convert the Oid2 object into an Oid object that is usable by APIs in the .NET Framework which expect an Oid rather than an Oid2. This method only transfers the OID value and friendly name to the new Oid object. Group and algorithm mappings are lost."} 


### void Unregister()

{"Revert the registration of this OID, which may have been registered with one of the Register overloads. As with OID registration, this method requires that the caller be fully trusted, and that the user context that the calling application be run under be an Administrator on the machine. Updating the registration table may have no effect on the current process, if Windows has already read them. Instead, the process may need to be restarted to reflect the registration changes."} 

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | {"This API requires that its immediate caller be fully trusted"}  |


