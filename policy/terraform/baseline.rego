package terraform.baseline

# Organization baseline for Terraform in infra/.
# Input: HCL converted to JSON by python-hcl2, merged as {"resource": [ {<type>: {<name>: {...}}}, ... ]}.
# Extend with org-specific rules (tagging, encryption defaults, network boundaries).

import rego.v1

resources contains r if {
	some block in input.resource
	some rtype, instances in block
	some name, body in instances
	r := {"type": rtype, "name": name, "body": body}
}

is_true(v) if v == true

is_true(v) if v == "true"

admin_ports := {22, 3389}

open_admin_port(rule) if {
	"0.0.0.0/0" in rule.cidr_blocks
	some port in admin_ports
	to_number(rule.from_port) <= port
	port <= to_number(rule.to_port)
}

deny contains msg if {
	some r in resources
	r.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
	r.body.acl in {"public-read", "public-read-write"}
	msg := sprintf("%s.%s: S3 ACL %q makes the bucket public", [r.type, r.name, r.body.acl])
}

deny contains msg if {
	some r in resources
	r.type == "aws_security_group"
	some rule in r.body.ingress
	open_admin_port(rule)
	msg := sprintf("%s.%s: SSH/RDP ingress open to 0.0.0.0/0", [r.type, r.name])
}

deny contains msg if {
	some r in resources
	r.type == "aws_security_group_rule"
	r.body.type == "ingress"
	open_admin_port(r.body)
	msg := sprintf("%s.%s: SSH/RDP ingress open to 0.0.0.0/0", [r.type, r.name])
}

deny contains msg if {
	some r in resources
	r.type in {"aws_db_instance", "aws_rds_cluster"}
	is_true(object.get(r.body, "publicly_accessible", false))
	msg := sprintf("%s.%s: database must not be publicly accessible", [r.type, r.name])
}

deny contains msg if {
	some r in resources
	r.type in {"aws_db_instance", "aws_rds_cluster"}
	not is_true(object.get(r.body, "storage_encrypted", false))
	msg := sprintf("%s.%s: storage_encrypted must be true", [r.type, r.name])
}
