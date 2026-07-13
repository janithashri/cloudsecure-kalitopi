from ..throttle import with_backoff


@with_backoff()
def fetch_iam_config(session, arn: str, region: str) -> dict:
    iam = session.client("iam", region_name="us-east-1")

    arn_parts = arn.split(":")
    entity_path = arn_parts[-1]
    entity_type = entity_path.split("/")[0]
    entity_name = "/".join(entity_path.split("/")[1:])

    config = {"arn": arn, "entity_type": entity_type, "name": entity_name}

    if entity_type == "role":
        r = iam.get_role(RoleName=entity_name)
        config["assume_role_policy"] = r["Role"]["AssumeRolePolicyDocument"]
        config["max_session_duration"] = r["Role"].get("MaxSessionDuration")
        policy_names = iam.list_role_policies(RoleName=entity_name)["PolicyNames"]
        config["inline_policies"] = {
            p: iam.get_role_policy(RoleName=entity_name, PolicyName=p)["PolicyDocument"]
            for p in policy_names
        }
    elif entity_type == "user":
        r = iam.get_user(UserName=entity_name)
        config["password_last_used"] = str(r["User"].get("PasswordLastUsed", "Never"))
        policy_names = iam.list_user_policies(UserName=entity_name)["PolicyNames"]
        config["inline_policies"] = {
            p: iam.get_user_policy(UserName=entity_name, PolicyName=p)["PolicyDocument"]
            for p in policy_names
        }
        mfa = iam.list_mfa_devices(UserName=entity_name)["MFADevices"]
        config["mfa_enabled"] = len(mfa) > 0

    return config
