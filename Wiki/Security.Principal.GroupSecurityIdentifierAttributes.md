# Security.Principal.GroupSecurityIdentifierAttributes


Attributes that can be associated with a group's SecurityIdentifier. 
 
These values map to the group attributes documented on [http://msdn.microsoft.com/en-us/library/aa379624.aspx](http://msdn.microsoft.com/en-us/library/aa379624.aspx) 
 

| None | No attributes are set on the group SID.  |
| Mandatory | The group cannot have its Enabled bit removed. This maps to the SE_GROUP_MANDATORY attribute.  |
| EnabledByDefault | The group is enabled by default. This maps to the SE_GROUP_ENABLED_BY_DEFAULT attribute.  |
| Enabled | The group is enabled for use in access checks. This maps to the SE_GROUP_ENABLED attribute.  |
| Owner | The token that the group is pulled from is the owner of the group. This maps to the SE_GROUP_OWNER attribute.  |
| DenyOnly | The group can only be used to match deny ACEs, and will not match allow ACEs. This maps to the SE_GROUP_USE_FOR_DENY_ONLY attribute.  |
| Integrity | The group is used to set the integrity level of the token. This maps to the SE_GROUP_INTEGRITY attribute.  |
| IntegrityEnabled | The group is used to set the integrity level of the token. This maps to the SE_GROUP_INTEGRITY_ENABLED attribute.  |
| Resource | The group is domain-local. This maps to the SE_GROUP_RESOURCE attribute.  |
| LogOnIdentifier | The group identifies the logon session of the token. This maps to the SE_GROUP_LOGON_ID attribute.  |
