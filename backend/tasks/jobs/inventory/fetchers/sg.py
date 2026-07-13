from ..throttle import with_backoff


@with_backoff()
def fetch_sg_config(session, arn: str, region: str) -> dict:
    sg_id = arn.split("/")[-1]
    ec2 = session.client("ec2", region_name=region)

    r = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = r["SecurityGroups"][0]

    def normalise_rule(rule):
        return {
            "protocol": rule.get("IpProtocol"),
            "from_port": rule.get("FromPort"),
            "to_port": rule.get("ToPort"),
            "ipv4_ranges": [r["CidrIp"] for r in rule.get("IpRanges", [])],
            "ipv6_ranges": [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])],
        }

    return {
        "group_id": sg_id,
        "group_name": sg.get("GroupName"),
        "vpc_id": sg.get("VpcId"),
        "inbound_rules": [normalise_rule(r) for r in sg.get("IpPermissions", [])],
        "outbound_rules": [normalise_rule(r) for r in sg.get("IpPermissionsEgress", [])],
        "description": sg.get("Description"),
    }
