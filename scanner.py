import boto3
import json
import botocore


def check_public_s3_buckets(session):
    s3 = session.client("s3")
    findings = []
    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            bucket_name = bucket["Name"]
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                if "AllUsers" in grant.get("Grantee", {}).get("URI", ""):
                    findings.append(f"❗ Bucket '{bucket_name}' is publicly accessible.")
    except Exception as e:
        findings.append(f"⚠️ Error checking S3 buckets: {e}")
    return findings


def check_all_s3_buckets(session):
    s3 = session.client("s3")
    result = []

    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_info = {
                "bucket": bucket_name,
                "status": "Private",
                "public_access": False,
                "policy": None,
                "acl_grants": [],
                "issues": []
            }

            # Check ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        bucket_info["public_access"] = True
                        bucket_info["status"] = "Public via ACL"
                        bucket_info["acl_grants"].append(grant)
                        bucket_info["issues"].append("ACL allows public access")
            except botocore.exceptions.ClientError as e:
                bucket_info["issues"].append(f"ACL check error: {str(e)}")

            # Check Bucket Policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_statements = json.loads(policy["Policy"]).get("Statement", [])
                bucket_info["policy"] = policy_statements

                for statement in policy_statements:
                    principal = statement.get("Principal")
                    effect = statement.get("Effect")
                    condition = statement.get("Condition", {})

                    if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                        if not condition:
                            bucket_info["public_access"] = True
                            bucket_info["status"] = "Public via Policy"
                            bucket_info["issues"].append("Bucket policy allows public access")
                        else:
                            bucket_info["status"] = "Conditionally Public"
                            bucket_info["issues"].append("Policy allows access with conditions")
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    bucket_info["issues"].append(f"Policy check error: {str(e)}")

            result.append(bucket_info)

    except Exception as e:
        return [f"❌ Error checking buckets: {str(e)}"]

    return result


def check_wildcard_iam_policies(session):
    iam = session.client("iam")
    findings = []
    try:
        roles = iam.list_roles()["Roles"]
        for role in roles:
            role_name = role["RoleName"]
            policies = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for policy in policies:
                policy_version = iam.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"]
                )
                statements = policy_version["PolicyVersion"]["Document"].get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Action") == "*" or stmt.get("Resource") == "*":
                        findings.append(f"❗ Role '{role_name}' uses wildcard in policy '{policy['PolicyName']}'.")
    except Exception as e:
        findings.append(f"⚠️ Error checking IAM policies: {e}")
    return findings


def check_open_security_groups(session):
    ec2 = session.client("ec2")
    findings = []
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            sg_id = sg["GroupId"]
            for permission in sg["IpPermissions"]:
                from_port = permission.get("FromPort", "All")
                to_port = permission.get("ToPort", "All")
                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        findings.append(f"❗ Security Group '{sg_id}' allows 0.0.0.0/0 on ports {from_port}-{to_port}.")
    except Exception as e:
        findings.append(f"⚠️ Error checking security groups: {e}")
    return findings


def check_unencrypted_rds_instances(session):
    rds = session.client("rds")
    findings = []
    try:
        instances = rds.describe_db_instances()["DBInstances"]
        for db in instances:
            if not db.get("StorageEncrypted"):
                findings.append(f"❗ RDS instance '{db['DBInstanceIdentifier']}' is not encrypted.")
    except Exception as e:
        findings.append(f"⚠️ Error checking RDS encryption: {e}")
    return findings


def check_unencrypted_ebs_volumes(session):
    ec2 = session.client("ec2")
    findings = []
    try:
        volumes = ec2.describe_volumes()["Volumes"]
        for vol in volumes:
            if not vol.get("Encrypted"):
                findings.append(f"❗ EBS volume '{vol['VolumeId']}' is not encrypted.")
    except Exception as e:
        findings.append(f"⚠️ Failed to check EBS encryption: {e}")
    return findings


def check_cloudtrail_logging(session):
    ct = session.client("cloudtrail")
    findings = []
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            findings.append("❗ No CloudTrail trails configured.")
        else:
            for trail in trails:
                name = trail["Name"]
                status = ct.get_trail_status(Name=name)
                if not status.get("IsLogging"):
                    findings.append(f"❗ CloudTrail '{name}' is not logging.")
    except Exception as e:
        findings.append(f"⚠️ Error checking CloudTrail: {e}")
    return findings


def run_all_checks(session):
    report = {}

    report["public_s3_buckets"] = check_public_s3_buckets(session)
    report["s3_bucket_audit"] = check_all_s3_buckets(session)
    report["wildcard_iam_policies"] = check_wildcard_iam_policies(session)
    report["open_security_groups"] = check_open_security_groups(session)
    report["unencrypted_rds_instances"] = check_unencrypted_rds_instances(session)
    report["unencrypted_ebs_volumes"] = check_unencrypted_ebs_volumes(session)
    report["cloudtrail_logging"] = check_cloudtrail_logging(session)

    with open("report.json", "w") as f:
        json.dump(report, f, indent=2)

    return report
