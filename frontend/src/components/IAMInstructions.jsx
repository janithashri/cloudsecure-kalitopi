import { useState } from "react";

const TRUST_POLICY = (cloudSecureAccountId) => `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${cloudSecureAccountId}:root"
    },
    "Action": "sts:AssumeRole"
  }]
}`;

const PERMISSION_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "resource-explorer-2:Search",
        "resource-explorer-2:GetIndex",
        "resource-explorer-2:GetDefaultView",
        "resource-explorer-2:ListViews",
        "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketEncryption",
        "s3:GetBucketVersioning", "s3:GetBucketLogging", "s3:GetPublicAccessBlock",
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
        "iam:GetRole", "iam:GetUser", "iam:ListRolePolicies",
        "iam:GetRolePolicy", "iam:ListUserPolicies", "iam:GetUserPolicy",
        "iam:ListMFADevices",
        "rds:DescribeDBInstances",
        "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}`;

const RE_CMD = `aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1`;

function CopyBlock({ text, label }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded bg-slate-800 p-4 pr-24 text-sm text-slate-100">
        {text}
      </pre>
      <button
        type="button"
        onClick={copy}
        className="absolute right-2 top-2 rounded bg-slate-600 px-2 py-1 text-xs text-white hover:bg-slate-500"
      >
        {copied ? "Copied" : "Copy"}
      </button>
      {label && <p className="mt-1 text-xs text-slate-500">{label}</p>}
    </div>
  );
}

export default function IAMInstructions({ cloudSecureAccountId }) {
  const [open, setOpen] = useState(false);
  const trustPolicy = TRUST_POLICY(cloudSecureAccountId);
  return (
    <div className="mt-8 border-t border-slate-200 pt-6">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-slate-600 hover:text-slate-800 underline"
      >
        {open ? "Hide" : "Show"} IAM setup instructions
      </button>
      {open && (
        <div className="mt-4 space-y-6 text-sm">
          <div>
            <h3 className="font-medium text-slate-800">Step 1 — Create the IAM Role with this trust policy</h3>
            <CopyBlock text={trustPolicy} label="Substitute your CloudSecure account ID in Principal.AWS" />
          </div>
          <div>
            <h3 className="font-medium text-slate-800">Step 2 — Attach this inline permission policy to the role</h3>
            <CopyBlock text={PERMISSION_POLICY} />
          </div>
          <div>
            <h3 className="font-medium text-slate-800">Step 3 — Enable Resource Explorer in your AWS account</h3>
            <CopyBlock text={RE_CMD} label="Run in AWS CLI" />
          </div>
        </div>
      )}
    </div>
  );
}
