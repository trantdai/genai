## Self-service Security Chatbot Usage Guide

Security consumers or requesters should follow the following guide or workflow to get trained on security technologies in questions, learn how to prompt the chatbot correctly to get sample suggested requests and request the chatbot to create pull requests with the content derived from the suggested requests.

1. Security consumers ask the chatbot security domain questions like `What does Cloudflare web application firewall do?` and `What does Cloudflare rate limit do?` to understand about the security technlogies in question
2. Security consumers ask the chatbot about how to create and manage the security configuration using an IaC tool like `Terraform` to get the suggested sample code. Some examples of the questions are `Tell me how to create Cloudflare WAF managed ruleset in Terraform` and `Show me Terraform code to create a Cloudflare HTTP rate limit resource`
3. Security consumers compose their security self-service requests based on the suggested sample code and ask the chatbot to create a GitHub pull request on their behalf like this prompt ```createpr->resource "cloudflare_rate_limit" "example" { zone_id = "your_zone_id" name = "example-rate-limit" description = "Example rate limit" disabled = false match { request { methods = ["GET", "POST"] schemes = ["HTTP", "HTTPS"] path { values = ["/example/*"] } } } threshold = 10 period = 1 action { mode = "simulate" } }```
4. The chatbot creates a PR
5. Process owners (security engineers) review and merge the PR that triggers the configuration management pipeline