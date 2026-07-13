from .cloudtrail import fetch_cloudtrail_config
from .ec2 import fetch_ec2_config
from .iam import fetch_iam_config
from .kms import fetch_kms_config
from .rds import fetch_rds_config
from .s3 import fetch_s3_config
from .sg import fetch_sg_config

FETCHER_MAP = {
    "AWS::S3::Bucket": fetch_s3_config,
    "AWS::EC2::Instance": fetch_ec2_config,
    "AWS::EC2::SecurityGroup": fetch_sg_config,
    "AWS::IAM::Role": fetch_iam_config,
    "AWS::IAM::User": fetch_iam_config,
    "AWS::RDS::DBInstance": fetch_rds_config,
    "AWS::KMS::Key": fetch_kms_config,
    "AWS::CloudTrail::Trail": fetch_cloudtrail_config,
}
