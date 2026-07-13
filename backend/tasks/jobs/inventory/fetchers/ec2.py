from ..throttle import with_backoff


@with_backoff()
def fetch_ec2_config(session, arn: str, region: str) -> dict:
    instance_id = arn.split("/")[-1]
    ec2 = session.client("ec2", region_name=region)

    r = ec2.describe_instances(InstanceIds=[instance_id])
    instance = r["Reservations"][0]["Instances"][0]

    return {
        "instance_id": instance_id,
        "instance_type": instance.get("InstanceType"),
        "state": instance["State"]["Name"],
        "vpc_id": instance.get("VpcId"),
        "subnet_id": instance.get("SubnetId"),
        "public_ip": instance.get("PublicIpAddress"),
        "public_dns": instance.get("PublicDnsName"),
        "iam_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
        "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
        "monitoring": instance.get("Monitoring", {}).get("State"),
        "ebs_optimized": instance.get("EbsOptimized"),
        "metadata_options": instance.get("MetadataOptions", {}),
    }
