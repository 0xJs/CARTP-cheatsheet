# CARTP-cheatsheet
Azure AD cheatsheet for the CARTP course

## General information
### Terminology
- Tenant - An instance of Azure AD and represents a single organization.
- Azure AD Directory - Each tenant has a dedicated Directory. This is used 
to perform identity and access management functions for resources. 
- Subscriptions - It is used to pay for services. There can be multiple 
subscriptions in a Directory.
- Core Domain - The initial domain name <tenant>.onmicrosoft.com is 
the core domain. it is possible to define custom domain names too.
- Azure resourced are divided into four levels:
  - Management groups
    - Management groups are used to manage multiple subscriptions. 
    - All subscriptions inherit the conditions applied to the management group. 
    - All subscriptions within a single management group belong to the same Azure tenant.
    - A management group can be placed in a lower hierarchy of another management group.
    - There is a single top-level management group - Root management group - for each directory in Azure.
  - Subscriptions
    - An Azure subscription is a logical unit of Azure services that links to an Azure account. 
    - An Azure subscription is a billing and/or access control boundary in an Azure AD Directory. 
    - An Azure AD Directory may have multiple subscriptions but each subscription can only trust a single directory.
    - An Azure role applied at the subscription level applies to all the resources within the subscription.
  - Resource groups
    - A resource group acts as a container for resources. 
    - In Azure, all the resources must be inside a resource group and can belong only to a group. 
    - If a resource group is deleted, all the resources inside it are also deleted. 
    - A resource group has its own Identity and Access Management settings for providing role based access. An Azure role applied to the resource group applied to all the resources in the group.
  - Resources
    - A resource is a deployable item in Azure like VMs, App Services, Storage Accounts etc. 

# Enumeration
#### Command title
```
test
```

# Initial access attacks

# Authenticated enumeration

# Privilege escalation

# Lateral movement

# Persistent techniques

# Data mining

# Defenses

# Bypassing defenses

# Example title
## Second title
#### Command title
```

```

