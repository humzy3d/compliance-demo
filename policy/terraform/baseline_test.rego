package terraform.baseline_test

import rego.v1

import data.terraform.baseline

test_private_bucket_allowed if {
	count(baseline.deny) == 0 with input as {"resource": [{"aws_s3_bucket": {"b": {"acl": "private"}}}]}
}

test_public_bucket_denied if {
	count(baseline.deny) == 1 with input as {"resource": [{"aws_s3_bucket": {"b": {"acl": "public-read"}}}]}
}

test_open_ssh_denied if {
	count(baseline.deny) == 1 with input as {"resource": [{"aws_security_group": {"sg": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}}}]}
}

test_restricted_ssh_allowed if {
	count(baseline.deny) == 0 with input as {"resource": [{"aws_security_group": {"sg": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]}}}]}
}

test_unencrypted_db_denied if {
	count(baseline.deny) == 1 with input as {"resource": [{"aws_db_instance": {"db": {"storage_encrypted": false}}}]}
}

test_encrypted_private_db_allowed if {
	count(baseline.deny) == 0 with input as {"resource": [{"aws_db_instance": {"db": {"storage_encrypted": true, "publicly_accessible": false}}}]}
}
