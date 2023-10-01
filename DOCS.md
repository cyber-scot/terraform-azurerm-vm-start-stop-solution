# Information

All credit for this solution goes to Microsoft and documentation on the solution specifically can be found at [Microsoft's GitHub repo ](https://github.com/microsoft/startstopv2-deployments)and the [documentation on Microsoft Docs](https://learn.microsoft.com/en-us/azure/azure-functions/start-stop-vms/overview)

This module also utilised the use of [aztfexport](https://github.com/Azure/aztfexport), so again, full credit to Microsoft :smile:

The code in this repo is purely for deploying the Microsoft solution using terraform, rather than the default ARM template deployment

For any specific issues with the terraform deployment, you can raise issues and improvements [here](https://github.com/cyber-scot/terraform-azurerm-vm-start-stop-solution/issues), [with the azurerm provider](https://github.com/hashicorp/terraform-provider-azurerm) or [with terraform itself](https://github.com/hashicorp/terraform)

## Potential Infrastructure Improvements for v1.1.0 (PRs welcome)

These are some known issues in the infrastructure for the v1.0.0 deployment.  PRs are welcome on these suggestions for a v1.1.0 release.  These issues should also exist in the Microsoft ARM template deployment as the v1.0.0 build aims to be a like-for-like replacement with some extra utilities on naming and configuration options

- Enabling the Storage Account firewall causes logic app deployment issues. It is disabled by default in the Microsoft deployment and by default in v1.0.0
- Disable storage account keys and use managed identities
  - Switch to optional user-assigned managed identity for all resources (e.g. `id-start-stop-solution`)
- Private endpoint support and VNet integration for function app
- HTTPS only mode fails
- Sometimes, when first creating start/stop, alerts may not be created properly due to app insights instance calls failures.  Running apply for a second time seems to resolve this.
