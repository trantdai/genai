# Write Detailed User Guide on How to Write Terraform Code to Create Cloudflare Configurations with Example Snippets
 
Sure, here's a basic guide on how to use Terraform to manage Cloudflare configurations.
 
Sure, here's a detailed guide in Markdown format on how to use Terraform to manage various Cloudflare configurations.
 
Prerequisites
Install Terraform on your machine. You can download it from the official Terraform website.
You need a Cloudflare account. If you don't have one, you can create it on the Cloudflare website.
Get your Cloudflare API token. You can generate it in your Cloudflare dashboard.
Step-by-step guide
1. Set up your Terraform provider
Create a new file named main.tf and add the following code:
 
terraform {
  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      version = "~> 2.0"
    }
  }
}
 
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
 
This code sets up the Cloudflare provider for Terraform. Replace 2.0 with the latest version of the Cloudflare provider.
 
2. Define your Cloudflare API token
Create a new file named variables.tf and add the following code:
 
variable "cloudflare_api_token" {
  description = "API token for Cloudflare"
  type        = string
}
 
This code defines a variable for your Cloudflare API token.
 
3. Create a DNS record
Add the following code to your main.tf file:
 
resource "cloudflare_record" "example" {
  zone_id = var.cloudflare_zone_id
  name    = "example"
  value   = "192.0.2.1"
  type    = "A"
  ttl     = 3600
}
 
This code creates a new A record in your DNS zone. Replace example with the name of your record, 192.0.2.1 with the IP address you want to point to, and 3600 with the TTL you want to set.
 
4. Define your Cloudflare zone ID
Add the following code to your variables.tf file:
 
variable "cloudflare_zone_id" {
  description = "Zone ID for Cloudflare"
  type        = string
}
 
This code defines a variable for your Cloudflare zone ID.
 
5. Apply your configuration
Run the following command in your terminal:
 
terraform init
terraform apply -var="cloudflare_api_token=YOUR_API_TOKEN" -var="cloudflare_zone_id=YOUR_ZONE_ID"
 
Replace YOUR_API_TOKEN with your Cloudflare API token and YOUR_ZONE_ID with your Cloudflare zone ID.
 
6. cloudflare_firewall_rule (Resource)
Define Firewall rules using filter expressions for more control over how traffic is matched to the rule. A filter expression permits selecting traffic by multiple criteria allowing greater freedom in rule creation.
 
Filter expressions needs to be created first before using Firewall Rule.
 
Note
cloudflare_firewall_rule is in a deprecation phase that will last for 14 months (July 1st, 2024). During this time period, this resource is still fully supported but you are strongly advised to move to the cloudflare_ruleset resource. Full details can be found in the developer documentation.
 
Example Usage
 
resource "cloudflare_filter" "wordpress" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  description = "Wordpress break-in attempts that are outside of the office"
  expression  = "(http.request.uri.path ~ \".*wp-login.php\" or http.request.uri.path ~ \".*xmlrpc.php\") and ip.src ne 192.0.2.1"
}
 
resource "cloudflare_firewall_rule" "wordpress" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  description = "Block wordpress break-in attempts"
  filter_id   = cloudflare_filter.wordpress.id
  action      = "block"
}
 
7. cloudflare_record (Resource)
Provides a Cloudflare record resource.
 
Example Usage
 
# Add a record to the domain
resource "cloudflare_record" "example" {
  zone_id = var.cloudflare_zone_id
  name    = "terraform"
  value   = "192.0.2.1"
  type    = "A"
  ttl     = 3600
}
 
# Add a record requiring a data map
resource "cloudflare_record" "_sip_tls" {
  zone_id = var.cloudflare_zone_id
  name    = "_sip._tls"
  type    = "SRV"
 
  data {
    service  = "_sip"
    proto    = "_tls"
    name     = "terraform-srv"
    priority = 0
    weight   = 0
    port     = 443
    target   = "example.com"
  }
}
 
8. cloudflare_list (Resource)
Provides Lists (IPs, Redirects, Hostname, ASNs) to be used in Edge Rules Engine across all zones within the same account.
 
Note
The cloudflare_list resource supports defining list items in line with the item attribute. The provider also has a cloudflare_list_item resource for managing items as independent resources. Using both in line item definitions and cloudflare_list_items on the same list is not supported and will cause Terraform into an irreconcilable state.
 
Example Usage
# IP list
resource "cloudflare_list" "example" {
  account_id  = "f037e56e89293a057740de681ac9abbe"
  name        = "example_list"
  description = "example IPs for a list"
  kind        = "ip"
 
  item {
    value {
      ip = "192.0.2.0"
    }
    comment = "one"
  }
 
  item {
    value {
      ip = "192.0.2.1"
    }
    comment = "two"
  }
}
 
# Redirect list
resource "cloudflare_list" "example" {
  account_id  = "f037e56e89293a057740de681ac9abbe"
  name        = "example_list"
  description = "example redirects for a list"
  kind        = "redirect"
 
  item {
    value {
      redirect {
        source_url = "example.com/blog"
        target_url = "https://blog.example.com"
      }
    }
    comment = "one"
  }
 
  item {
    value {
      redirect {
        source_url            = "example.com/foo"
        target_url            = "https://foo.example.com"
        include_subdomains    = "enabled"
        subpath_matching      = "enabled"
        status_code           = 301
        preserve_query_string = "enabled"
        preserve_path_suffix  = "disabled"
      }
    }
    comment = "two"
  }
}
 
# ASN list
resource "cloudflare_list" "example" {
  account_id  = "f037e56e89293a057740de681ac9abbe"
  name        = "example_list"
  description = "example ASNs for a list"
  kind        = "asn"
 
  item {
    value {
      asn = 677
    }
    comment = "one"
  }
 
  item {
    value {
     asn = 989
    }
    comment = "two"
  }
}
 
 
# Hostname list
resource "cloudflare_list" "example" {
  account_id  = "f037e56e89293a057740de681ac9abbe"
  name        = "example_list"
  description = "example hostnames for a list"
  kind        = "hostname"
 
  item {
    value {
      hostname {
        url_hostname = "example.com"
      }
    }
    comment = "one"
  }
 
  item {
    value {
      hostname {
        url_hostname = "*.example.com"
      }
    }
    comment = "two"
  }
}
Schema
Required
account_id (String) The account identifier to target for the resource.
kind (String) The type of items the list will contain. Available values: ip, redirect, hostname, asn. Modifying this attribute will force creation of a new resource.
name (String) The name of the list. Modifying this attribute will force creation of a new resource.
Optional
description (String) An optional description of the list.
item (Block Set) (see below for nested schema)
Read-Only
id (String) The ID of this resource.
 
Nested Schema for item
Required:
 
value (Block List, Min: 1, Max: 1) (see below for nested schema)
Optional:
 
comment (String) An optional comment for the item.
 
Nested Schema for item.value
Optional:
 
asn (Number)
hostname (Block List) (see below for nested schema)
ip (String)
redirect (Block List) (see below for nested schema)
 
Nested Schema for item.value.hostname
Required:
 
url_hostname (String) The FQDN to match on. Wildcard sub-domain matching is allowed. Eg. *.abc.com.
 
Nested Schema for item.value.redirect
Required:
 
source_url (String) The source url of the redirect.
target_url (String) The target url of the redirect.
Optional:
 
include_subdomains (String) Whether the redirect also matches subdomains of the source url. Available values: disabled, enabled.
preserve_path_suffix (String) Whether to preserve the path suffix when doing subpath matching. Available values: disabled, enabled.
preserve_query_string (String) Whether the redirect target url should keep the query string of the request's url. Available values: disabled, enabled.
status_code (Number) The status code to be used when redirecting a request.
subpath_matching (String) Whether the redirect also matches subpaths of the source url. Available values: disabled, enabled.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_list.example <account_id>/<list_id>
 
9. cloudflare_ruleset (Resource)
The Cloudflare Ruleset Engine allows you to create and deploy rules and rulesets.
 
The engine syntax, inspired by the Wireshark Display Filter language, is the same syntax used in custom Firewall Rules. Cloudflare uses the Ruleset Engine in different products, allowing you to configure several products using the same basic syntax.
 
Example Usage
# Magic Transit
resource "cloudflare_ruleset" "magic_transit_example" {
  account_id  = "f037e56e89293a057740de681ac9abbe"
  name        = "account magic transit"
  description = "example magic transit ruleset description"
  kind        = "root"
  phase       = "magic_transit"
 
  rules {
    action      = "allow"
    expression  = "tcp.dstport in { 32768..65535 }"
    description = "Allow TCP Ephemeral Ports"
  }
}
 
# Zone-level WAF Managed Ruleset
resource "cloudflare_ruleset" "zone_level_managed_waf" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "managed WAF"
  description = "managed WAF ruleset description"
  kind        = "zone"
  phase       = "http_request_firewall_managed"
 
  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee"
    }
    expression  = "(http.host eq \"example.host.com\")"
    description = "Execute Cloudflare Managed Ruleset on my zone-level phase entry point ruleset"
    enabled     = true
  }
}
 
# Zone-level WAF with tag-based overrides
resource "cloudflare_ruleset" "zone_level_managed_waf_with_category_based_overrides" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "managed WAF with tag-based overrides"
  description = "managed WAF with tag-based overrides ruleset description"
  kind        = "zone"
  phase       = "http_request_firewall_managed"
 
  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee"
      overrides {
        categories {
          category = "wordpress"
          action   = "block"
          enabled  = true
        }
 
        categories {
          category = "joomla"
          action   = "block"
          enabled  = true
        }
      }
    }
 
    expression  = "(http.host eq \"example.host.com\")"
    description = "overrides to only enable wordpress rules to block"
    enabled     = false
  }
}
 
# Rewrite the URI path component to a static path
resource "cloudflare_ruleset" "transform_uri_rule_path" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "transform rule for URI path"
  description = "change the URI path to a new static path"
  kind        = "zone"
  phase       = "http_request_transform"
 
  rules {
    action = "rewrite"
    action_parameters {
      uri {
        path {
          value = "/my-new-route"
        }
      }
    }
 
    expression  = "(http.host eq \"example.com\" and http.request.uri.path eq \"/old-path\")"
    description = "example URI path transform rule"
    enabled     = true
  }
}
 
# Rewrite the URI query component to a static query
resource "cloudflare_ruleset" "transform_uri_rule_query" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "transform rule for URI query parameter"
  description = "change the URI query to a new static query"
  kind        = "zone"
  phase       = "http_request_transform"
 
  rules {
    action = "rewrite"
    action_parameters {
      uri {
        query {
          value = "old=new_again"
        }
      }
    }
 
    expression  = "(http.host eq \"example.host.com\")"
    description = "URI transformation query example"
    enabled     = true
  }
}
 
# Rewrite HTTP headers to a modified values
resource "cloudflare_ruleset" "transform_uri_http_headers" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "transform rule for HTTP headers"
  description = "modify HTTP headers before reaching origin"
  kind        = "zone"
  phase       = "http_request_late_transform"
 
  rules {
    action = "rewrite"
    action_parameters {
      headers {
        name      = "example-http-header-1"
        operation = "set"
        value     = "my-http-header-value-1"
      }
 
      headers {
        name       = "example-http-header-2"
        operation  = "set"
        expression = "cf.zone.name"
      }
 
      headers {
        name      = "example-http-header-3-to-remove"
        operation = "remove"
      }
    }
 
    expression  = "(http.host eq \"example.host.com\")"
    description = "example request header transform rule"
    enabled     = false
  }
}
 
# HTTP rate limit for an API route
resource "cloudflare_ruleset" "rate_limiting_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "restrict API requests count"
  description = "apply HTTP rate limiting for a route"
  kind        = "zone"
  phase       = "http_ratelimit"
 
  rules {
    action = "block"
    ratelimit {
      characteristics = [
        "cf.colo.id",
        "ip.src"
      ]
      period              = 60
      requests_per_period = 100
      mitigation_timeout  = 600
    }
 
    expression  = "(http.request.uri.path matches \"^/api/\")"
    description = "rate limit for API"
    enabled     = true
  }
}
 
# Change origin for an API route
resource "cloudflare_ruleset" "http_origin_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "Change to some origin"
  description = "Change origin for a route"
  kind        = "zone"
  phase       = "http_request_origin"
 
  rules {
    action = "route"
    action_parameters {
      host_header = "some.host"
      origin {
        host = "some.host"
        port = 80
      }
    }
    expression  = "(http.request.uri.path matches \"^/api/\")"
    description = "change origin to some.host"
    enabled     = true
  }
}
 
# Custom fields logging
resource "cloudflare_ruleset" "custom_fields_logging_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "log custom fields"
  description = "add custom fields to logging"
  kind        = "zone"
  phase       = "http_log_custom_fields"
 
  rules {
    action = "log_custom_field"
    action_parameters {
      request_fields = [
        "content-type",
        "x-forwarded-for",
        "host"
      ]
      response_fields = [
        "server",
        "content-type",
        "allow"
      ]
      cookie_fields = [
        "__ga",
        "accountNumber",
        "__cfruid"
      ]
    }
 
    expression  = "(http.host eq \"example.host.com\")"
    description = "log custom fields rule"
    enabled     = true
  }
}
 
# Custom cache keys + settings
resource "cloudflare_ruleset" "cache_settings_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "set cache settings"
  description = "set cache settings for the request"
  kind        = "zone"
  phase       = "http_request_cache_settings"
 
  rules {
    action = "set_cache_settings"
    action_parameters {
      edge_ttl {
        mode    = "override_origin"
        default = 60
        status_code_ttl {
          status_code = 200
          value       = 50
        }
        status_code_ttl {
          status_code_range {
            from = 201
            to   = 300
          }
          value = 30
        }
      }
      browser_ttl {
        mode = "respect_origin"
      }
      serve_stale {
        disable_stale_while_updating = true
      }
      respect_strong_etags = true
      cache_key {
        ignore_query_strings_order = false
        cache_deception_armor      = true
        custom_key {
          query_string {
            exclude = ["*"]
          }
          header {
            include        = ["habc", "hdef"]
            check_presence = ["habc_t", "hdef_t"]
            exclude_origin = true
          }
          cookie {
            include        = ["cabc", "cdef"]
            check_presence = ["cabc_t", "cdef_t"]
          }
          user {
            device_type = true
            geo         = false
          }
          host {
            resolved = true
          }
        }
      }
      origin_error_page_passthru = false
    }
    expression  = "(http.host eq \"example.host.com\")"
    description = "set cache settings rule"
    enabled     = true
  }
}
 
# Redirects based on a List resource
resource "cloudflare_ruleset" "redirect_from_list_example" {
  account_id  = "f037e56e89293a057740de681ac9abbe"
  name        = "redirects"
  description = "Redirect ruleset"
  kind        = "root"
  phase       = "http_request_redirect"
 
  rules {
    action = "redirect"
    action_parameters {
      from_list {
        name = "redirect_list"
        key  = "http.request.full_uri"
      }
    }
    expression  = "http.request.full_uri in $redirect_list"
    description = "Apply redirects from redirect_list"
    enabled     = true
  }
}
 
# Dynamic Redirects from value resource
resource "cloudflare_ruleset" "redirect_from_value_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "redirects"
  description = "Redirect ruleset"
  kind        = "zone"
  phase       = "http_request_dynamic_redirect"
 
  rules {
    action = "redirect"
    action_parameters {
      from_value {
        status_code = 301
        target_url {
          value = "some_host.com"
        }
        preserve_query_string = true
      }
    }
    expression  = "(http.request.uri.path matches \"^/api/\")"
    description = "Apply redirect from value"
    enabled     = true
  }
}
 
# Serve some custom error response
resource "cloudflare_ruleset" "http_custom_error_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "Serve some error response"
  description = "Serve some error response"
  kind        = "zone"
  phase       = "http_custom_errors"
  rules {
    action = "serve_error"
    action_parameters {
      content      = "some error html"
      content_type = "text/html"
      status_code  = "530"
    }
    expression  = "(http.request.uri.path matches \"^/api/\")"
    description = "serve some error response"
    enabled     = true
  }
}
 
# Set Configuration Rules for an API route
resource "cloudflare_ruleset" "http_config_rules_example" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "set config rules"
  description = "set config rules for request"
  kind        = "zone"
  phase       = "http_config_settings"
 
  rules {
    action = "set_config"
    action_parameters {
      email_obfuscation = true
      bic               = true
    }
    expression  = "(http.request.uri.path matches \"^/api/\")"
    description = "set config rules for matching request"
    enabled     = true
  }
}
 
# Set compress algorithm for response.
resource "cloudflare_ruleset" "response_compress_brotli_html" {
  zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
  name        = "Brotli response compression for HTML"
  description = "Response compression ruleset"
  kind        = "zone"
  phase       = "http_response_compression"
 
  rules {
    action = "compress_response"
    action_parameters {
      algorithms {
        name = "brotli"
      }
      algorithms {
        name = "auto"
      }
    }
    expression  = "http.response.content_type.media_type == \"text/html\""
    description = "Prefer brotli compression for HTML"
    enabled     = true
  }
}
Schema
Required
kind (String) Type of Ruleset to create. Available values: custom, managed, root, zone.
name (String) Name of the ruleset.
phase (String) Point in the request/response lifecycle where the ruleset will be created. Available values: ddos_l4, ddos_l7, http_config_settings, http_custom_errors, http_log_custom_fields, http_ratelimit, http_request_cache_settings, http_request_dynamic_redirect, http_request_firewall_custom, http_request_firewall_managed, http_request_late_transform, http_request_origin, http_request_redirect, http_request_sanitize, http_request_sbfm, http_request_transform, http_response_compression, http_response_firewall_managed, http_response_headers_transform, magic_transit.
Optional
account_id (String) The account identifier to target for the resource.
description (String) Brief summary of the ruleset and its intended use.
rules (Block List) List of rules to apply to the ruleset. (see below for nested schema)
zone_id (String) The zone identifier to target for the resource.
Read-Only
id (String) The identifier of this resource.
 
Nested Schema for rules
Required:
 
expression (String) Criteria for an HTTP request to trigger the ruleset rule action. Uses the Firewall Rules expression language based on Wireshark display filters. Refer to the Firewall Rules language documentation for all available fields, operators, and functions.
Optional:
 
action (String) Action to perform in the ruleset rule. Available values: block, challenge, compress_response, ddos_dynamic, ddos_mitigation, execute, force_connection_close, js_challenge, log, log_custom_field, managed_challenge, redirect, rewrite, route, score, serve_error, set_cache_settings, set_config, skip.
action_parameters (Block List) List of parameters that configure the behavior of the ruleset rule action. (see below for nested schema)
description (String) Brief summary of the ruleset rule and its intended use.
enabled (Boolean) Whether the rule is active.
exposed_credential_check (Block List) List of parameters that configure exposed credential checks. (see below for nested schema)
logging (Block List) List parameters to configure how the rule generates logs. Only valid for skip action. (see below for nested schema)
ratelimit (Block List) List of parameters that configure HTTP rate limiting behaviour. (see below for nested schema)
ref (String) Rule reference.
Read-Only:
 
id (String) Unique rule identifier.
last_updated (String) The most recent update to this rule.
version (String) Version of the ruleset to deploy.
 
Nested Schema for rules.action_parameters
Optional:
 
additional_cacheable_ports (Set of Number) Specifies uncommon ports to allow cacheable assets to be served from.
algorithms (Block List) Compression algorithms to use in order of preference. (see below for nested schema)
automatic_https_rewrites (Boolean) Turn on or off Cloudflare Automatic HTTPS rewrites.
autominify (Block List) Indicate which file extensions to minify automatically. (see below for nested schema)
bic (Boolean) Inspect the visitor's browser for headers commonly associated with spammers and certain bots.
browser_ttl (Block List) List of browser TTL parameters to apply to the request. (see below for nested schema)
cache (Boolean) Whether to cache if expression matches.
cache_key (Block List) List of cache key parameters to apply to the request. (see below for nested schema)
content (String) Content of the custom error response.
content_type (String) Content-Type of the custom error response.
cookie_fields (Set of String) List of cookie values to include as part of custom fields logging.
disable_apps (Boolean) Turn off all active Cloudflare Apps.
disable_railgun (Boolean) Turn off railgun feature of the Cloudflare Speed app.
disable_rum (Boolean) Turn off RUM feature.
disable_zaraz (Boolean) Turn off zaraz feature.
edge_ttl (Block List) List of edge TTL parameters to apply to the request. (see below for nested schema)
email_obfuscation (Boolean) Turn on or off the Cloudflare Email Obfuscation feature of the Cloudflare Scrape Shield app.
fonts (Boolean) Toggle fonts.
from_list (Block List) Use a list to lookup information for the action. (see below for nested schema)
from_value (Block List) Use a value to lookup information for the action. (see below for nested schema)
headers (Block List) List of HTTP header modifications to perform in the ruleset rule. Note: Headers are order dependent and must be provided sorted alphabetically ascending based on the name value. (see below for nested schema)
host_header (String) Host Header that request origin receives.
hotlink_protection (Boolean) Turn on or off the hotlink protection feature.
id (String) Identifier of the action parameter to modify.
increment (Number)
matched_data (Block List) List of properties to configure WAF payload logging. (see below for nested schema)
mirage (Boolean) Turn on or off Cloudflare Mirage of the Cloudflare Speed app.
opportunistic_encryption (Boolean) Turn on or off the Cloudflare Opportunistic Encryption feature of the Edge Certificates tab in the Cloudflare SSL/TLS app.
origin (Block List) List of properties to change request origin. (see below for nested schema)
origin_cache_control (Boolean) Enable or disable the use of a more compliant Cache Control parsing mechanism, enabled by default for most zones.
origin_error_page_passthru (Boolean) Pass-through error page for origin.
overrides (Block List) List of override configurations to apply to the ruleset. (see below for nested schema)
phases (Set of String) Point in the request/response lifecycle where the ruleset will be created. Available values: ddos_l4, ddos_l7, http_config_settings, http_custom_errors, http_log_custom_fields, http_ratelimit, http_request_cache_settings, http_request_dynamic_redirect, http_request_firewall_custom, http_request_firewall_managed, http_request_late_transform, http_request_origin, http_request_redirect, http_request_sanitize, http_request_sbfm, http_request_transform, http_response_compression, http_response_firewall_managed, http_response_headers_transform, magic_transit.
polish (String) Apply options from the Polish feature of the Cloudflare Speed app.
products (Set of String) Products to target with the actions. Available values: bic, hot, ratelimit, securityLevel, uablock, waf, zonelockdown.
read_timeout (Number) Specifies a maximum timeout for reading content from an origin server.
request_fields (Set of String) List of request headers to include as part of custom fields logging, in lowercase.
respect_strong_etags (Boolean) Respect strong ETags.
response (Block List) List of parameters that configure the response given to end users. (see below for nested schema)
response_fields (Set of String) List of response headers to include as part of custom fields logging, in lowercase.
rocket_loader (Boolean) Turn on or off Cloudflare Rocket Loader in the Cloudflare Speed app.
rules (Map of String) Map of managed WAF rule ID to comma-delimited string of ruleset rule IDs. Example: rules = { "efb7b8c949ac4650a09736fc376e9aee" = "5de7edfa648c4d6891dc3e7f84534ffa,e3a567afc347477d9702d9047e97d760" }.
ruleset (String) Which ruleset ID to target.
rulesets (Set of String) List of managed WAF rule IDs to target. Only valid when the "action" is set to skip.
security_level (String) Control options for the Security Level feature from the Security app.
serve_stale (Block List) List of serve stale parameters to apply to the request. (see below for nested schema)
server_side_excludes (Boolean) Turn on or off the Server Side Excludes feature of the Cloudflare Scrape Shield app.
sni (Block List) List of properties to manange Server Name Indication. (see below for nested schema)
ssl (String) Control options for the SSL feature of the Edge Certificates tab in the Cloudflare SSL/TLS app.
status_code (Number) HTTP status code of the custom error response.
sxg (Boolean) Turn on or off the SXG feature.
uri (Block List) List of URI properties to configure for the ruleset rule when performing URL rewrite transformations. (see below for nested schema)
version (String) Version of the ruleset to deploy.
 
Nested Schema for rules.action_parameters.algorithms
Required:
 
name (String) Name of the compression algorithm to use. Available values: gzip, brotli, auto, default, none
 
Nested Schema for rules.action_parameters.autominify
Optional:
 
css (Boolean) CSS minification.
html (Boolean) HTML minification.
js (Boolean) JS minification.
 
Nested Schema for rules.action_parameters.browser_ttl
Required:
 
mode (String) Mode of the browser TTL. Available values: override_origin, respect_origin, bypass
Optional:
 
default (Number) Default browser TTL. This value is required when override_origin is set
 
Nested Schema for rules.action_parameters.cache_key
Optional:
 
cache_by_device_type (Boolean) Cache by device type.
cache_deception_armor (Boolean) Cache deception armor.
custom_key (Block List) Custom key parameters for the request. (see below for nested schema)
ignore_query_strings_order (Boolean) Ignore query strings order.
 
Nested Schema for rules.action_parameters.cache_key.custom_key
Optional:
 
cookie (Block List) Cookie parameters for the custom key. (see below for nested schema)
header (Block List) Header parameters for the custom key. (see below for nested schema)
host (Block List) Host parameters for the custom key. (see below for nested schema)
query_string (Block List) Query string parameters for the custom key. (see below for nested schema)
user (Block List) User parameters for the custom key. (see below for nested schema)
 
Nested Schema for rules.action_parameters.cache_key.custom_key.cookie
Optional:
 
check_presence (Set of String) List of cookies to check for presence in the custom key.
include (Set of String) List of cookies to include in the custom key.
 
Nested Schema for rules.action_parameters.cache_key.custom_key.header
Optional:
 
check_presence (Set of String) List of headers to check for presence in the custom key.
exclude_origin (Boolean) Exclude the origin header from the custom key.
include (Set of String) List of headers to include in the custom key.
 
Nested Schema for rules.action_parameters.cache_key.custom_key.host
Optional:
 
resolved (Boolean) Resolve hostname to IP address.
 
Nested Schema for rules.action_parameters.cache_key.custom_key.query_string
Optional:
 
exclude (Set of String) List of query string parameters to exclude from the custom key.
include (Set of String) List of query string parameters to include in the custom key.
 
Nested Schema for rules.action_parameters.cache_key.custom_key.user
Optional:
 
device_type (Boolean) Add device type to the custom key.
geo (Boolean) Add geo data to the custom key.
lang (Boolean) Add language data to the custom key.
 
Nested Schema for rules.action_parameters.edge_ttl
Required:
 
mode (String) Mode of the edge TTL. Available values: override_origin, respect_origin, bypass_by_default
Optional:
 
default (Number) Default edge TTL.
status_code_ttl (Block List) Edge TTL for the status codes. (see below for nested schema)
 
Nested Schema for rules.action_parameters.edge_ttl.status_code_ttl
Optional:
 
status_code (Number) Status code for which the edge TTL is applied.
status_code_range (Block List) Status code range for which the edge TTL is applied. (see below for nested schema)
value (Number) Status code edge TTL value.
 
Nested Schema for rules.action_parameters.edge_ttl.status_code_ttl.status_code_range
Optional:
 
from (Number) From status code.
to (Number) To status code.
 
Nested Schema for rules.action_parameters.from_list
Optional:
 
key (String) Expression to use for the list lookup.
name (String) Name of the list.
 
Nested Schema for rules.action_parameters.from_value
Optional:
 
preserve_query_string (Boolean) Preserve query string for redirect URL.
status_code (Number) Status code for redirect.
target_url (Block List) Target URL for redirect. (see below for nested schema)
 
Nested Schema for rules.action_parameters.from_value.target_url
Optional:
 
expression (String) Use a value dynamically determined by the Firewall Rules expression language based on Wireshark display filters. Refer to the Firewall Rules language documentation for all available fields, operators, and functions.
value (String) Static value to provide as the HTTP request header value.
 
Nested Schema for rules.action_parameters.headers
Optional:
 
expression (String) Use a value dynamically determined by the Firewall Rules expression language based on Wireshark display filters. Refer to the Firewall Rules language documentation for all available fields, operators, and functions.
name (String) Name of the HTTP request header to target.
operation (String) Action to perform on the HTTP request header. Available values: remove, set, add.
value (String) Static value to provide as the HTTP request header value.
 
Nested Schema for rules.action_parameters.matched_data
Optional:
 
public_key (String) Public key to use within WAF Ruleset payload logging to view the HTTP request parameters. You can generate a public key using the matched-data-cli command-line tool or in the Cloudflare dashboard.
 
Nested Schema for rules.action_parameters.origin
Optional:
 
host (String) Origin Hostname where request is sent.
port (Number) Origin Port where request is sent.
 
Nested Schema for rules.action_parameters.overrides
Optional:
 
action (String) Action to perform in the rule-level override. Available values: block, challenge, compress_response, ddos_dynamic, ddos_mitigation, execute, force_connection_close, js_challenge, log, log_custom_field, managed_challenge, redirect, rewrite, route, score, serve_error, set_cache_settings, set_config, skip.
categories (Block List) List of tag-based overrides. (see below for nested schema)
enabled (Boolean) Defines if the current ruleset-level override enables or disables the ruleset.
rules (Block List) List of rule-based overrides. (see below for nested schema)
sensitivity_level (String) Sensitivity level to override for all ruleset rules. Available values: default, medium, low, eoff.
 
Nested Schema for rules.action_parameters.overrides.categories
Optional:
 
action (String) Action to perform in the tag-level override. Available values: block, challenge, compress_response, ddos_dynamic, ddos_mitigation, execute, force_connection_close, js_challenge, log, log_custom_field, managed_challenge, redirect, rewrite, route, score, serve_error, set_cache_settings, set_config, skip.
category (String) Tag name to apply the ruleset rule override to.
enabled (Boolean) Defines if the current tag-level override enables or disables the ruleset rules with the specified tag.
 
Nested Schema for rules.action_parameters.overrides.rules
Optional:
 
action (String) Action to perform in the rule-level override. Available values: block, challenge, compress_response, ddos_dynamic, ddos_mitigation, execute, force_connection_close, js_challenge, log, log_custom_field, managed_challenge, redirect, rewrite, route, score, serve_error, set_cache_settings, set_config, skip.
enabled (Boolean) Defines if the current rule-level override enables or disables the rule.
id (String) Rule ID to apply the override to.
score_threshold (Number) Anomaly score threshold to apply in the ruleset rule override. Only applicable to modsecurity-based rulesets.
sensitivity_level (String) Sensitivity level for a ruleset rule override.
 
Nested Schema for rules.action_parameters.response
Optional:
 
content (String) Body content to include in the response.
content_type (String) HTTP content type to send in the response.
status_code (Number) HTTP status code to send in the response.
 
Nested Schema for rules.action_parameters.serve_stale
Optional:
 
disable_stale_while_updating (Boolean) Disable stale while updating.
 
Nested Schema for rules.action_parameters.sni
Optional:
 
value (String) Value to define for SNI.
 
Nested Schema for rules.action_parameters.uri
Optional:
 
origin (Boolean)
path (Block List) URI path configuration when performing a URL rewrite. (see below for nested schema)
query (Block List) Query string configuration when performing a URL rewrite. (see below for nested schema)
 
Nested Schema for rules.action_parameters.uri.path
Optional:
 
expression (String) Expression that defines the updated (dynamic) value of the URI path or query string component. Uses the Firewall Rules expression language based on Wireshark display filters. Refer to the Firewall Rules language documentation for all available fields, operators, and functions.
value (String) Static string value of the updated URI path or query string component.
 
Nested Schema for rules.action_parameters.uri.query
Optional:
 
expression (String) Expression that defines the updated (dynamic) value of the URI path or query string component. Uses the Firewall Rules expression language based on Wireshark display filters. Refer to the Firewall Rules language documentation for all available fields, operators, and functions.
value (String) Static string value of the updated URI path or query string component.
 
Nested Schema for rules.exposed_credential_check
Optional:
 
password_expression (String) Firewall Rules expression language based on Wireshark display filters for where to check for the "password" value. Refer to the Firewall Rules language.
username_expression (String) Firewall Rules expression language based on Wireshark display filters for where to check for the "username" value. Refer to the Firewall Rules language.
 
Nested Schema for rules.logging
Optional:
 
enabled (Boolean) Override the default logging behavior when a rule is matched.
 
Nested Schema for rules.ratelimit
Optional:
 
characteristics (Set of String) List of parameters that define how Cloudflare tracks the request rate for this rule.
counting_expression (String) Criteria for counting HTTP requests to trigger the Rate Limiting action. Uses the Firewall Rules expression language based on Wireshark display filters. Refer to the Firewall Rules language documentation for all available fields, operators, and functions.
mitigation_timeout (Number) Once the request rate is reached, the Rate Limiting rule blocks further requests for the period of time defined in this field.
period (Number) The period of time to consider (in seconds) when evaluating the request rate.
requests_per_period (Number) The number of requests over the period of time that will trigger the Rate Limiting rule.
requests_to_origin (Boolean) Whether to include requests to origin within the Rate Limiting count.
score_per_period (Number) The maximum aggregate score over the period of time that will trigger Rate Limiting rule.
score_response_header_name (String) Name of HTTP header in the response, set by the origin server, with the score for the current request.
Import
Import is supported using the following syntax:
 
# Import an account scoped Ruleset configuration.
$ terraform import cloudflare_ruleset.example account/<account_id>/<ruleset_id>
 
# Import a zone scoped Ruleset configuration.
$ terraform import cloudflare_ruleset.example zone/<zone_id>/<ruleset_id>
 
10. cloudflare_zone (Resource)
Provides a Cloudflare Zone resource. Zone is the basic resource for working with Cloudflare and is roughly equivalent to a domain name that the user purchases.
 
Note
If you are attempting to sign up a subdomain of a zone you must first have Subdomain Support entitlement for your account.
 
Example Usage
resource "cloudflare_zone" "example" {
  account_id = "f037e56e89293a057740de681ac9abbe"
  zone       = "example.com"
}
Schema
Required
account_id (String) Account ID to manage the zone resource in.
zone (String) The DNS zone name which will be added. Modifying this attribute will force creation of a new resource.
Optional
jump_start (Boolean) Whether to scan for DNS records on creation. Ignored after zone is created.
paused (Boolean) Whether this zone is paused (traffic bypasses Cloudflare). Defaults to false.
plan (String) The name of the commercial plan to apply to the zone. Available values: free, lite, pro, pro_plus, business, enterprise, partners_free, partners_pro, partners_business, partners_enterprise.
type (String) A full zone implies that DNS is hosted with Cloudflare. A partial zone is typically a partner-hosted zone or a CNAME setup. Available values: full, partial, secondary. Defaults to full.
Read-Only
id (String) The ID of this resource.
meta (Map of Boolean)
name_servers (List of String) Cloudflare-assigned name servers. This is only populated for zones that use Cloudflare DNS.
status (String) Status of the zone. Available values: active, pending, initializing, moved, deleted, deactivated.
vanity_name_servers (List of String) List of Vanity Nameservers (if set).
verification_key (String) Contains the TXT record value to validate domain ownership. This is only populated for zones of type partial.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_zone.example <zone_id>
 
11. cloudflare_custom_ssl (Resource)
Provides a Cloudflare custom SSL resource.
 
Example Usage
resource "cloudflare_custom_ssl" "example" {
  zone_id = "0da42c8d2132a9ddaf714f9e7c920711"
  custom_ssl_options {
    certificate      = "-----INSERT CERTIFICATE-----"
    private_key      = "-----INSERT PRIVATE KEY-----"
    bundle_method    = "ubiquitous"
    geo_restrictions = "us"
    type             = "legacy_custom"
  }
}
Schema
Required
zone_id (String) The zone identifier to target for the resource.
Optional
custom_ssl_options (Block List, Max: 1) The certificate associated parameters. Modifying this attribute will force creation of a new resource. (see below for nested schema)
custom_ssl_priority (Block List) (see below for nested schema)
Read-Only
expires_on (String)
hosts (List of String)
id (String) The ID of this resource.
issuer (String)
modified_on (String)
priority (Number)
signature (String)
status (String)
uploaded_on (String)
 
Nested Schema for custom_ssl_options
Optional:
 
bundle_method (String) Method of building intermediate certificate chain. A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it. Available values: ubiquitous, optimal, force.
certificate (String) Certificate certificate and the intermediate(s).
geo_restrictions (String) Specifies the region where your private key can be held locally. Available values: us, eu, highest_security.
private_key (String, Sensitive) Certificate's private key.
type (String) Whether to enable support for legacy clients which do not include SNI in the TLS handshake. Available values: legacy_custom, sni_custom.
 
Nested Schema for custom_ssl_priority
Optional:
 
priority (Number)
Read-Only:
 
id (String) The ID of this resource.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_custom_ssl.example <zone_id>/<certificate_id>
 
12. cloudflare_custom_ssl (Resource)
Provides a Cloudflare custom SSL resource.
 
Example Usage
resource "cloudflare_custom_ssl" "example" {
  zone_id = "0da42c8d2132a9ddaf714f9e7c920711"
  custom_ssl_options {
    certificate      = "-----INSERT CERTIFICATE-----"
    private_key      = "-----INSERT PRIVATE KEY-----"
    bundle_method    = "ubiquitous"
    geo_restrictions = "us"
    type             = "legacy_custom"
  }
}
Schema
Required
zone_id (String) The zone identifier to target for the resource.
Optional
custom_ssl_options (Block List, Max: 1) The certificate associated parameters. Modifying this attribute will force creation of a new resource. (see below for nested schema)
custom_ssl_priority (Block List) (see below for nested schema)
Read-Only
expires_on (String)
hosts (List of String)
id (String) The ID of this resource.
issuer (String)
modified_on (String)
priority (Number)
signature (String)
status (String)
uploaded_on (String)
 
Nested Schema for custom_ssl_options
Optional:
 
bundle_method (String) Method of building intermediate certificate chain. A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it. Available values: ubiquitous, optimal, force.
certificate (String) Certificate certificate and the intermediate(s).
geo_restrictions (String) Specifies the region where your private key can be held locally. Available values: us, eu, highest_security.
private_key (String, Sensitive) Certificate's private key.
type (String) Whether to enable support for legacy clients which do not include SNI in the TLS handshake. Available values: legacy_custom, sni_custom.
 
Nested Schema for custom_ssl_priority
Optional:
 
priority (Number)
Read-Only:
 
id (String) The ID of this resource.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_custom_ssl.example <zone_id>/<certificate_id>
 
13. cloudflare_bot_management (Resource)
Provides a resource to configure Bot Management.
 
Specifically, this resource can be used to manage:
 
Bot Fight Mode
Super Bot Fight Mode
Bot Management for Enterprise
Example Usage
resource "cloudflare_bot_management" "example" {
  zone_id                         = "0da42c8d2132a9ddaf714f9e7c920711"
  enable_js                       = true
  sbfm_definitely_automated       = "block"
  sbfm_likely_automated           = "managed_challenge"
  sbfm_verified_bots              = "allow"
  sbfm_static_resource_protection = false
  optimize_wordpress              = true
}
Schema
Required
zone_id (String) The zone identifier to target for the resource. Modifying this attribute will force creation of a new resource.
Optional
auto_update_model (Boolean) Automatically update to the newest bot detection models created by Cloudflare as they are released. Learn more..
enable_js (Boolean) Use lightweight, invisible JavaScript detections to improve Bot Management. Learn more about JavaScript Detections.
fight_mode (Boolean) Whether to enable Bot Fight Mode.
optimize_wordpress (Boolean) Whether to optimize Super Bot Fight Mode protections for Wordpress.
sbfm_definitely_automated (String) Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
sbfm_likely_automated (String) Super Bot Fight Mode (SBFM) action to take on likely automated requests.
sbfm_static_resource_protection (Boolean) Super Bot Fight Mode (SBFM) to enable static resource protection. Enable if static resources on your application need bot protection. Note: Static resource protection can also result in legitimate traffic being blocked.
sbfm_verified_bots (String) Super Bot Fight Mode (SBFM) action to take on verified bots requests.
suppress_session_score (Boolean) Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
Read-Only
id (String) The ID of this resource.
using_latest_model (Boolean) A read-only field that indicates whether the zone currently is running the latest ML model.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_bot_management.example <zone_id>
 
14. cloudflare_mtls_certificate (Resource)
Provides a Cloudflare mTLS certificate resource. These certificates may be used with mTLS enabled Cloudflare services.
 
Example Usage
resource "cloudflare_mtls_certificate" "example" {
  account_id   = "f037e56e89293a057740de681ac9abbe"
  name         = "example"
  certificates = "-----BEGIN CERTIFICATE-----\nMIIDmDCCAoCgAwIBAgIUKTOAZNj...i4JhqeoTewsxndhDDE\n-----END CERTIFICATE-----"
  private_key  = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE...1IS3EnQRrz6WMYA=\n-----END PRIVATE KEY-----"
  ca           = true
}
Schema
Required
account_id (String) The account identifier to target for the resource. Modifying this attribute will force creation of a new resource.
ca (Boolean) Whether this is a CA or leaf certificate. Modifying this attribute will force creation of a new resource.
certificates (String) Certificate you intend to use with mTLS-enabled services. Modifying this attribute will force creation of a new resource.
Optional
name (String) Optional unique name for the certificate. Modifying this attribute will force creation of a new resource.
private_key (String) The certificate's private key. Modifying this attribute will force creation of a new resource.
Read-Only
expires_on (String) Modifying this attribute will force creation of a new resource.
id (String) The ID of this resource.
issuer (String) Modifying this attribute will force creation of a new resource.
serial_number (String) Modifying this attribute will force creation of a new resource.
signature (String) Modifying this attribute will force creation of a new resource.
uploaded_on (String) Modifying this attribute will force creation of a new resource.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_mtls_certificate.example <account_id>/<mtls_certificate_id>
 
15.  cloudflare_rate_limit (Resource)
Provides a Cloudflare rate limit resource for a given zone. This can be used to limit the traffic you receive zone-wide, or matching more specific types of requests/responses.
 
Note
cloudflare_rate_limit is in a deprecation phase that will last for 14 months (July 1st, 2024). During this time period, this resource is still fully supported but you are strongly advised to move to the cloudflare_ruleset resource. Full details can be found in the developer documentation.
 
Example Usage
resource "cloudflare_rate_limit" "example" {
  zone_id   = "0da42c8d2132a9ddaf714f9e7c920711"
  threshold = 2000
  period    = 2
  match {
    request {
      url_pattern = "${var.cloudflare_zone}/*"
      schemes     = ["HTTP", "HTTPS"]
      methods     = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
    }
    response {
      statuses       = [200, 201, 202, 301, 429]
      origin_traffic = false
      headers = [
        {
          name  = "Host"
          op    = "eq"
          value = "localhost"
        },
        {
          name  = "X-Example"
          op    = "ne"
          value = "my-example"
        }
      ]
    }
  }
  action {
    mode    = "simulate"
    timeout = 43200
    response {
      content_type = "text/plain"
      body         = "custom response body"
    }
  }
  correlate {
    by = "nat"
  }
  disabled            = false
  description         = "example rate limit for a zone"
  bypass_url_patterns = ["example.com/bypass1", "example.com/bypass2"]
}
Schema
Required
action (Block List, Min: 1, Max: 1) The action to be performed when the threshold of matched traffic within the period defined is exceeded. (see below for nested schema)
period (Number) The time in seconds to count matching traffic. If the count exceeds threshold within this period the action will be performed.
threshold (Number) The threshold that triggers the rate limit mitigations, combine with period.
zone_id (String) The zone identifier to target for the resource. Modifying this attribute will force creation of a new resource.
Optional
bypass_url_patterns (Set of String)
correlate (Block List, Max: 1) Determines how rate limiting is applied. By default if not specified, rate limiting applies to the clients IP address. (see below for nested schema)
description (String) A note that you can use to describe the reason for a rate limit. This value is sanitized and all tags are removed.
disabled (Boolean) Whether this ratelimit is currently disabled. Defaults to false.
match (Block List, Max: 1) Determines which traffic the rate limit counts towards the threshold. By default matches all traffic in the zone. (see below for nested schema)
Read-Only
id (String) The ID of this resource.
 
Nested Schema for action
Required:
 
mode (String) The type of action to perform. Available values: simulate, ban, challenge, js_challenge, managed_challenge.
Optional:
 
response (Block List, Max: 1) Custom content-type and body to return, this overrides the custom error for the zone. This field is not required. Omission will result in default HTML error page. (see below for nested schema)
timeout (Number) The time in seconds as an integer to perform the mitigation action. This field is required if the mode is either simulate or ban. Must be the same or greater than the period.
 
Nested Schema for action.response
Required:
 
body (String) The body to return, the content here should conform to the content_type.
content_type (String) The content-type of the body. Available values: text/plain, text/xml, application/json.
 
Nested Schema for correlate
Optional:
 
by (String) If set to 'nat', NAT support will be enabled for rate limiting. Available values: nat.
 
Nested Schema for match
Optional:
 
request (Block List, Max: 1) Matches HTTP requests (from the client to Cloudflare). (see below for nested schema)
response (Block List, Max: 1) Matches HTTP responses before they are returned to the client from Cloudflare. If this is defined, then the entire counting of traffic occurs at this stage. (see below for nested schema)
 
Nested Schema for match.request
Optional:
 
methods (Set of String) HTTP Methods to match traffic on. Available values: GET, POST, PUT, DELETE, PATCH, HEAD, _ALL_.
schemes (Set of String) HTTP schemes to match traffic on. Available values: HTTP, HTTPS, _ALL_.
url_pattern (String) The URL pattern to match comprised of the host and path, i.e. example.org/path. Wildcard are expanded to match applicable traffic, query strings are not matched. Use _ for all traffic to your zone.
 
Nested Schema for match.response
Optional:
 
headers (List of Map of String) List of HTTP headers maps to match the origin response on.
origin_traffic (Boolean) Only count traffic that has come from your origin servers. If true, cached items that Cloudflare serve will not count towards rate limiting.
statuses (Set of Number) HTTP Status codes, can be one, many or indicate all by not providing this value.
Import
Import is supported using the following syntax:
 
$ terraform import cloudflare_rate_limit.example <zone_id>/<rate_limit_id>
 
This is a basic example of how to use Terraform with Cloudflare. You can do much more with Terraform and Cloudflare, such as managing page rules, firewall rules, and more. For more information, check out the official Terraform Cloudflare provider documentation.