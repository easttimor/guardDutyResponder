# GuardDuty Responder
## Automated responses to GuardDuty findings
Author: Timothy Orr @easttim0r

This initial capability handles the following GuardDuty finding types:
* Recon:EC2/PortProbeUnprotectedPort
* UnauthorizedAccess:EC2/SSHBruteForce
* UnauthorizedAccess:EC2/RDPBruteForce

CloudWatch Events filters for GuardDuty findings, and targets the Lambda. Lambda parses the event, looks for these finding types, and enriches with the applicable NACL ID.

The Lambda looks up the instanceId-remoteIp pair in DynamoDB and:
* adds an entry if not found
* updates the TTL if found

For new instanceId-remoteIp pairs, the Lambda will then check DynamoDB to determine the next available rule number for the associated NACL ID. These rule numbers are initialized with an input parameter (environment variable). With the naclId and rule number both determined, the Lambda writes a NACL entry to DENY the remoteIp from the finding.

*I will soon add an open source license to this.*

![GuardDuty Responder](/images/responderNACLblock.png)

Current capabilities:
* fully provisioned with Terraform (.12 required)
* cross account role assumption
* writes ingress NACL rules to DENY remoteIp (/32 CIDR)
* (untested) accomodates a white list for exempt IPs
* tracks instanceId-remoteIp pairing in DynamoDB
* initializes the starting rule number for each naclId in DynamoDB
* tracks the current rule number to use for each naclId in DynamoDB

Future capabilities:
* support for additional finding types
* sns integration to annouce blocks
* better logic and error handling
* better logic for setting a rule range, potentially with a max, and ability to avoid the default allow all rule (100)
* logic to remove rules from the NACL based on TTL
* logic for exponental increase in block time similar to fail2ban
* configurable ability to write blocks to WAF in addition to NACL
* considering adding an outboud rule to the NACL; this may be useful for other finding types