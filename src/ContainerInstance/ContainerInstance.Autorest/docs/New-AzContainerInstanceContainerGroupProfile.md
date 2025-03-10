---
external help file:
Module Name: Az.ContainerInstance
online version: https://learn.microsoft.com/powershell/module/az.containerinstance/new-azcontainerinstancecontainergroupprofile
schema: 2.0.0
---

# New-AzContainerInstanceContainerGroupProfile

## SYNOPSIS
Create or update container group profiles with specified configurations.

## SYNTAX

```
New-AzContainerInstanceContainerGroupProfile -Name <String> -ResourceGroupName <String>
 -Container <IContainer[]> -OSType <OperatingSystemTypes> [-SubscriptionId <String>]
 [-ConfidentialComputePropertyCcePolicy <String>] [-EncryptionPropertyIdentity <String>]
 [-EncryptionPropertyKeyName <String>] [-EncryptionPropertyKeyVersion <String>]
 [-EncryptionPropertyVaultBaseUrl <String>] [-Extension <IDeploymentExtensionSpec[]>]
 [-ImageRegistryCredential <IImageRegistryCredential[]>] [-InitContainer <IInitContainerDefinition[]>]
 [-IPAddressAutoGeneratedDomainNameLabelScope <DnsNameLabelReusePolicy>] [-IPAddressDnsNameLabel <String>]
 [-IPAddressIP <String>] [-IPAddressPort <IPort[]>] [-IPAddressType <ContainerGroupIPAddressType>]
 [-Location <String>] [-LogAnalyticLogType <LogAnalyticsLogType>] [-LogAnalyticMetadata <Hashtable>]
 [-LogAnalyticWorkspaceId <String>] [-LogAnalyticWorkspaceKey <String>]
 [-LogAnalyticWorkspaceResourceId <String>] [-Priority <ContainerGroupPriority>]
 [-RestartPolicy <ContainerGroupRestartPolicy>] [-Sku <ContainerGroupSku>] [-Tag <Hashtable>]
 [-Volume <IVolume[]>] [-Zone <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

## DESCRIPTION
Create or update container group profiles with specified configurations.

## EXAMPLES

### Example 1: Create a container group profile with a container instance and request a public IP address with opening ports
```powershell
$port1 = New-AzContainerInstancePortObject -Port 8000 -Protocol TCP
$port2 = New-AzContainerInstancePortObject -Port 8001 -Protocol TCP
$container = New-AzContainerInstanceObject -Name test-container -Image nginx -RequestCpu 1 -RequestMemoryInGb 1.5 -Port @($port1, $port2)
$containerGroupProfile = New-AzContainerInstanceContainerGroupProfile -ResourceGroupName test-rg -Name test-cgp -Location eastus -Container $container -OsType Linux -RestartPolicy "Never" -IpAddressType Public
```

```output
Location Name    Zone ResourceGroupName
-------- ----    ---- -----------------
eastus   test-cgp      test-rg
```

This commands creates a container group profile with a container instance, whose image is latest nginx, and requests a public IP address with opening port 8000 and 8001.

### Example 2: Create container group profile and runs a custom script inside the container.
```powershell
$pwd = ConvertTo-SecureString -String "****" -AsPlainText -Force
$env1 = New-AzContainerInstanceEnvironmentVariableObject -Name "env1" -Value "value1"
$env2 = New-AzContainerInstanceEnvironmentVariableObject -Name "env2" -SecureValue $pwd
$container = New-AzContainerInstanceObject -Name test-container -Image alpine -Command "/bin/sh -c myscript.sh" -EnvironmentVariable @($env1, $env2) -RequestCpu 1 -RequestMemoryInGb 1.5
$containerGroupProfile = New-AzContainerInstanceContainerGroupProfile -ResourceGroupName test-rg -Name test-cgp -Location eastus -Container $container -OsType Linux
```

```output
Location Name    Zone ResourceGroupName
-------- ----    ---- -----------------
eastus   test-cgp      test-rg
```

This commands creates a container group profile and runs a custom script inside the container.

### Example 3: Create a container group profile with a container instance using image nginx in Azure Container Registry
```powershell
$pwd = ConvertTo-SecureString -String "****" -AsPlainText -Force
$container = New-AzContainerInstanceObject -Name test-container -Image myacr.azurecr.io/nginx:latest -RequestCpu 1 -RequestMemoryInGb 1.5
$imageRegistryCredential = New-AzContainerGroupImageRegistryCredentialObject -Server "myacr.azurecr.io" -Username "username" -Password $pwd
$containerGroupProfile = New-AzContainerInstanceContainerGroupProfile -ResourceGroupName test-rg -Name test-cgp -Location eastus -Container $container -ImageRegistryCredential $imageRegistryCredential -OsType Linux
```

```output
Location Name    Zone ResourceGroupName
-------- ----    ---- -----------------
eastus   test-cgp      test-rg
```

This commands creates a container group profile with a container instance, whose image is nginx in Azure Container Registry.

### Example 4: Create a container group profile with Spot priority and a container instance using nginx image 
```powershell
$container = New-AzContainerInstanceObject -Name test-container -Image nginx -RequestCpu 1 -RequestMemoryInGb 1.5
$containerGroupProfile = New-AzContainerInstanceContainerGroupProfile -ResourceGroupName test-rg -Name test-cgp -Location eastus -Container $container -OsType Linux -RestartPolicy Never -Priority Spot
```

```output
Location Name    Zone ResourceGroupName
-------- ----    ---- -----------------
eastus   test-cgp      test-rg
```

This commands creates a container group profile with spot priority and a container instance, whose image is nginx.

## PARAMETERS

### -ConfidentialComputePropertyCcePolicy
The base64 encoded confidential compute enforcement policy

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Container
The containers within the container group.
To construct, see NOTES section for CONTAINER properties and create a hash table.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IContainer[]
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DefaultProfile
The DefaultProfile parameter is not functional.
Use the SubscriptionId parameter when available if executing the cmdlet against a different subscription.

```yaml
Type: System.Management.Automation.PSObject
Parameter Sets: (All)
Aliases: AzureRMContext, AzureCredential

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncryptionPropertyIdentity
The keyvault managed identity.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncryptionPropertyKeyName
The encryption key name.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncryptionPropertyKeyVersion
The encryption key version.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncryptionPropertyVaultBaseUrl
The keyvault base url.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Extension
extensions used by virtual kubelet
To construct, see NOTES section for EXTENSION properties and create a hash table.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IDeploymentExtensionSpec[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ImageRegistryCredential
The image registry credentials by which the container group is created from.
To construct, see NOTES section for IMAGEREGISTRYCREDENTIAL properties and create a hash table.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IImageRegistryCredential[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InitContainer
The init containers for a container group.
To construct, see NOTES section for INITCONTAINER properties and create a hash table.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IInitContainerDefinition[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPAddressAutoGeneratedDomainNameLabelScope
The value representing the security enum.
The 'Unsecure' value is the default value if not selected and means the object's domain name label is not secured against subdomain takeover.
The 'TenantReuse' value is the default value if selected and means the object's domain name label can be reused within the same tenant.
The 'SubscriptionReuse' value means the object's domain name label can be reused within the same subscription.
The 'ResourceGroupReuse' value means the object's domain name label can be reused within the same resource group.
The 'NoReuse' value means the object's domain name label cannot be reused within the same resource group, subscription, or tenant.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.DnsNameLabelReusePolicy
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPAddressDnsNameLabel
The Dns name label for the IP.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPAddressIP
The IP exposed to the public internet.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPAddressPort
The list of ports exposed on the container group.
To construct, see NOTES section for IPADDRESSPORT properties and create a hash table.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IPort[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPAddressType
Specifies if the IP is exposed to the public internet or private VNET.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupIPAddressType
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Location
The resource location.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogAnalyticLogType
The log type to be used.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.LogAnalyticsLogType
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogAnalyticMetadata
Metadata for log analytics.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogAnalyticWorkspaceId
The workspace id for log analytics

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogAnalyticWorkspaceKey
The workspace key for log analytics

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogAnalyticWorkspaceResourceId
The workspace resource id for log analytics

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name
The name of the container group profile.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: ContainerGroupProfileName

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OSType
The operating system type required by the containers in the container group.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.OperatingSystemTypes
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Priority
The priority of the container group.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupPriority
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResourceGroupName
The name of the resource group.
The name is case insensitive.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RestartPolicy
Restart policy for all containers within the container group.
- `Always` Always restart- `OnFailure` Restart on failure- `Never` Never restart

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupRestartPolicy
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Sku
The SKU for a container group.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupSku
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SubscriptionId
The ID of the target subscription.
The value must be an UUID.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: (Get-AzContext).Subscription.Id
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tag
The resource tags.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Volume
The list of volumes that can be mounted by containers in this container group.
To construct, see NOTES section for VOLUME properties and create a hash table.

```yaml
Type: Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IVolume[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Zone
The zones for the container group.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20240501Preview.IContainerGroupProfile

## NOTES

## RELATED LINKS

