
$defaultValue='rgHsmKey'
$rg=Read-Host "Resource Group Name: [$($defaultValue)]"
if ($rg -eq "") {$rg = $defaultValue}
$rg
$defaultvalue='South Central US'
$location=Read-Host "Location: [$($defaultValue)]"
if ($location -eq "") {$location = $defaultValue}
$location
$vaultName=Read-Host "Vault Name"
$keyName=Read-Host "KeyName"

Login-AzureRmAccount 
$Subscription = Get-AzureRmSubscription
Set-AzureRmContext -SubscriptionId $Subscription.SubscriptionId
New-AzureRmResourceGroup –Name $rg –Location $location
$Vault= New-AzureRmKeyVault -VaultName $vaultName -ResourceGroupName $rg -Location $location -SKU 'Premium'
Write-Host "---------- VAULT --------------"
$Vault
$key = Add-AzureKeyVaultKey -VaultName $vaultName -Name $keyName -Destination 'HSM'
Write-Host "---------- KEY --------------"
$key

Write-Host "-----------COPY THIS VALUES TO PROGRAM.CS-------------"
Write-Host "var keyName = `"$($key.Name)`";"
Write-Host "var keyVaultAddress = `"$($Vault.VaultUri)`";"
Write-Host "var keyVersion = `"$($key.Version)`";"
Write-Host "------------------------"




