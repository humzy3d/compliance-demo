package terraform.baseline

import rego.v1

# Input: Terraform HCL parsed by `conftest --parser hcl2`, e.g.
#   input.resource[<type>][<name>] = [ { <attributes> } ]

resources contains r if {
	some type, name
	blocks := input.resource[type][name]
	some body in blocks
	r := {"type": type, "name": name, "body": body}
}

public_cidrs := {"0.0.0.0/0", "::/0"}

admin_ports := {22, 3389}

deny contains msg if {
	some r in resources
	r.type == "aws_s3_bucket_acl"
	r.body.acl in {"public-read", "public-read-write", "authenticated-read"}
	msg := sprintf("%s.%s: public S3 ACL '%s' is not allowed", [r.type, r.name, r.body.acl])
}

deny contains msg if {
	some r in resources
	r.type == "aws_security_group_rule"
	r.body.type == "ingress"
	some cidr in r.body.cidr_blocks
	cidr in public_cidrs
	some port in admin_ports
	r.body.from_port <= port
	r.body.to_port >= port
	msg := sprintf("%s.%s: port %d open to %s", [r.type, r.name, port, cidr])
}

deny contains msg if {
	some r in resources
	r.type == "aws_vpc_security_group_ingress_rule"
	r.body.cidr_ipv4 in public_cidrs
	some port in admin_ports
	r.body.from_port <= port
	r.body.to_port >= port
	msg := sprintf("%s.%s: port %d open to the internet", [r.type, r.name, port])
}

deny contains msg if {
	some r in resources
	r.type == "aws_security_group"
	some ing in r.body.ingress
	some cidr in ing.cidr_blocks
	cidr in public_cidrs
	some port in admin_ports
	ing.from_port <= port
	ing.to_port >= port
	msg := sprintf("%s.%s: inline ingress opens port %d to %s", [r.type, r.name, port, cidr])
}

deny contains msg if {
	some r in resources
	r.type in {"aws_db_instance", "aws_rds_cluster"}
	not r.body.storage_encrypted == true
	msg := sprintf("%s.%s: storage_encrypted must be true", [r.type, r.name])
}

deny contains msg if {
	some r in resources
	r.type == "aws_db_instance"
	r.body.publicly_accessible == true
	msg := sprintf("%s.%s: publicly_accessible must not be true", [r.type, r.name])
}

deny contains msg if {
	some r in resources
	r.type == "aws_ebs_volume"
	not r.body.encrypted == true
	msg := sprintf("%s.%s: encrypted must be true", [r.type, r.name])
}

taggable := {"aws_instance", "aws_s3_bucket", "aws_db_instance", "aws_rds_cluster", "aws_ebs_volume", "aws_vpc", "aws_lb"}

warn contains msg if {
	some r in resources
	r.type in taggable
	not r.body.tags
	msg := sprintf("%s.%s: no tags (add owner/data-classification tags or use provider default_tags)", [r.type, r.name])
}
