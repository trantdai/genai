# Terraform Configuration
This is a Terraform configuration file used for writing your Terraform code. Use this template below to manage infrastructure using the Cloudflare provider.
 
## Provider Configuration
This section is used to configure the Cloudflare provider. The email and token are used to authenticate with the Cloudflare API. Replace "example@hotmail.com" and "your-api-key" with your actual Cloudflare email and API token.
 
## Variable Declaration
 
This section declares a variable named domain with a default value of "example.com". This variable can be used in other parts of the Terraform configuration.
 
## Resource Configuration:
 
This section defines a Cloudflare DNS record. The domain is set to the value of the domain variable declared earlier. The name is the subdomain for the DNS record. The value is the IP address that the DNS record points to. The type is the type of DNS record, in this case, an "A" record. The proxied option, when set to true, enables Cloudflare's proxy.
 
### Template Configuration
This file is .tf file
```
provider "cloudflare" {
  email = "example@hotmail.com"
  token = "your-api-key"
}
 
variable "domain" {
  default = "example.com"
}
 
resource "cloudflare_record" "www" {
  domain  = "${var.domain}"
  name    = "www"
  value   = "203.0.113.10"
  type    = "A"
  proxied = true
}