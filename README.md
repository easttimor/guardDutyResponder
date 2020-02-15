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

![GuardDuty Responder](/images/responderNACLblock.png)
