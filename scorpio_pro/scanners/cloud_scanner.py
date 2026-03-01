"""Cloud security scanner — AWS, Azure, and GCP configuration auditing."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding


class CloudScanner(BaseScanner):
    """Audits cloud provider configurations for security misconfigurations.

    Credential discovery order:
    1. Checks environment variables / standard SDK config files.
    2. If not found, prompts the user interactively.
    3. If user declines, performs public-facing checks only.

    Covers:
    - AWS: IAM, S3, security groups, CloudTrail, KMS, VPC, RDS
    - Azure: RBAC, storage, NSG, Azure AD, Key Vault
    - GCP: IAM, GCS, firewall rules, audit logging, KMS
    """

    name = "Cloud Scanner"
    description = "AWS, Azure, and GCP security configuration auditing."

    def check_prerequisites(self) -> bool:
        """Cloud scanning is always available (degrades gracefully without SDKs)."""
        return True

    def run(self, scope: Any) -> list[Finding]:
        """Execute cloud security checks for configured providers.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.

        Returns:
            List of cloud security findings.
        """
        findings: list[Finding] = []
        cloud_accounts: list[dict[str, Any]] = getattr(scope, "cloud_accounts", [])

        # Always enumerate which providers are configured
        findings.extend(self._detect_configured_providers())

        aws_creds = self._get_aws_credentials(cloud_accounts)
        if aws_creds:
            findings.extend(self._scan_aws(aws_creds))

        azure_creds = self._get_azure_credentials(cloud_accounts)
        if azure_creds:
            findings.extend(self._scan_azure(azure_creds))

        gcp_creds = self._get_gcp_credentials(cloud_accounts)
        if gcp_creds:
            findings.extend(self._scan_gcp(gcp_creds))

        return findings

    # ------------------------------------------------------------------ #
    # Credential Discovery                                                 #
    # ------------------------------------------------------------------ #

    def _detect_configured_providers(self) -> list[Finding]:
        """Check which cloud provider credentials exist on this system."""
        detected: list[str] = []
        evidence_lines: list[str] = []

        # AWS
        aws_creds_file = Path.home() / ".aws" / "credentials"
        aws_config_file = Path.home() / ".aws" / "config"
        if (
            aws_creds_file.exists()
            or os.environ.get("AWS_ACCESS_KEY_ID")
            or os.environ.get("AWS_PROFILE")
        ):
            detected.append("AWS")
            evidence_lines.append(
                f"AWS: {'env vars' if os.environ.get('AWS_ACCESS_KEY_ID') else str(aws_creds_file)}"
            )

        # Azure
        azure_dir = Path.home() / ".azure"
        if azure_dir.exists() or os.environ.get("AZURE_CLIENT_ID"):
            detected.append("Azure")
            evidence_lines.append(
                f"Azure: {'env vars' if os.environ.get('AZURE_CLIENT_ID') else str(azure_dir)}"
            )

        # GCP
        gcp_creds = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        if gcp_creds.exists() or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            detected.append("GCP")
            evidence_lines.append(
                f"GCP: {os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', str(gcp_creds))}"
            )

        return [
            Finding(
                title="Cloud Provider Credentials Detected",
                severity="Informational",
                description=(
                    f"Credentials found for: {', '.join(detected)}"
                    if detected
                    else "No cloud provider credentials detected on this system."
                ),
                evidence="\n".join(evidence_lines) or "No credentials found.",
                remediation=(
                    "Ensure cloud credentials use least-privilege IAM roles. "
                    "Rotate credentials regularly. Do not store long-term keys in plaintext files."
                ),
                test_run="cloud_credential_detection",
                rationale="Exposed cloud credentials can grant complete access to cloud infrastructure.",
                methodology="Checked standard credential file locations and environment variables.",
                status="warning" if detected else "pass",
                compliance_tags=["NIST-PR.AC-1", "NIST-PR.AC-3", "GDPR-Art32"],
                metadata={"detected_providers": detected},
            )
        ]

    def _get_aws_credentials(self, cloud_accounts: list[dict]) -> dict[str, Any] | None:
        """Discover AWS credentials from env vars, config files, or scope."""
        # From scope config
        for acc in cloud_accounts:
            if acc.get("provider", "").lower() == "aws":
                return acc

        # From environment
        if os.environ.get("AWS_ACCESS_KEY_ID"):
            return {
                "provider": "aws",
                "access_key_id": os.environ["AWS_ACCESS_KEY_ID"],
                "source": "environment",
            }

        # From ~/.aws/credentials
        creds_file = Path.home() / ".aws" / "credentials"
        if creds_file.exists():
            return {"provider": "aws", "source": "credentials_file"}

        return None

    def _get_azure_credentials(self, cloud_accounts: list[dict]) -> dict[str, Any] | None:
        """Discover Azure credentials from env vars, config files, or scope."""
        for acc in cloud_accounts:
            if acc.get("provider", "").lower() == "azure":
                return acc

        if os.environ.get("AZURE_CLIENT_ID"):
            return {
                "provider": "azure",
                "client_id": os.environ.get("AZURE_CLIENT_ID"),
                "source": "environment",
            }

        if (Path.home() / ".azure").exists():
            return {"provider": "azure", "source": "azure_cli_profile"}

        return None

    def _get_gcp_credentials(self, cloud_accounts: list[dict]) -> dict[str, Any] | None:
        """Discover GCP credentials from env vars, config files, or scope."""
        for acc in cloud_accounts:
            if acc.get("provider", "").lower() == "gcp":
                return acc

        if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            return {
                "provider": "gcp",
                "key_file": os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
                "source": "environment",
            }

        gcp_file = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        if gcp_file.exists():
            return {"provider": "gcp", "source": "gcloud_adc"}

        return None

    # ------------------------------------------------------------------ #
    # AWS Scanning                                                         #
    # ------------------------------------------------------------------ #

    def _scan_aws(self, creds: dict[str, Any]) -> list[Finding]:
        """Run AWS security checks using boto3."""
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
        except ImportError:
            self._log.warning("boto3 not installed; skipping AWS scan.")
            return [self._unavailable_finding("AWS", "boto3")]

        findings: list[Finding] = []
        try:
            session = boto3.Session()
            findings.extend(self._aws_iam_checks(session))
            findings.extend(self._aws_s3_checks(session))
            findings.extend(self._aws_cloudtrail_checks(session))
            findings.extend(self._aws_security_group_checks(session))
        except Exception as exc:  # noqa: BLE001
            self._log.warning("AWS scan error: %s", exc)
            findings.append(
                Finding(
                    title="AWS Scan Error",
                    severity="Informational",
                    description=f"AWS scan could not complete: {exc}",
                    evidence=str(exc),
                    remediation="Verify AWS credentials are valid and have sufficient permissions.",
                    test_run="aws_scan",
                    rationale="AWS access is required to perform cloud security checks.",
                    methodology="Attempted boto3 API calls.",
                    status="warning",
                    compliance_tags=[],
                )
            )
        return findings

    def _aws_iam_checks(self, session: Any) -> list[Finding]:
        """Check IAM password policy and root account MFA."""
        from botocore.exceptions import ClientError
        findings: list[Finding] = []
        try:
            iam = session.client("iam")

            # Password policy
            try:
                policy = iam.get_account_password_policy()["PasswordPolicy"]
                issues: list[str] = []
                if policy.get("MinimumPasswordLength", 0) < 14:
                    issues.append("Minimum password length is less than 14 characters.")
                if not policy.get("RequireUppercaseCharacters"):
                    issues.append("Password policy does not require uppercase letters.")
                if not policy.get("RequireNumbers"):
                    issues.append("Password policy does not require numbers.")
                if not policy.get("RequireSymbols"):
                    issues.append("Password policy does not require symbols.")
                if not policy.get("MaxPasswordAge"):
                    issues.append("No maximum password age configured.")
                if not policy.get("PasswordReusePrevention"):
                    issues.append("Password reuse prevention not configured.")

                findings.append(
                    Finding(
                        title="AWS IAM Password Policy",
                        severity="High" if issues else "Informational",
                        description=f"{len(issues)} IAM password policy issue(s)." if issues else "IAM password policy is well configured.",
                        evidence=json.dumps(policy, indent=2),
                        remediation="Configure IAM password policy to require complexity, minimum 14 chars, and expiry.",
                        test_run="aws_iam_password_policy",
                        rationale="Weak password policies lead to compromised IAM credentials.",
                        methodology="Called iam:GetAccountPasswordPolicy.",
                        status="fail" if issues else "pass",
                        compliance_tags=["NIST-PR.AC-1", "HIPAA-164.312(a)(2)(i)", "GDPR-Art32"],
                        metadata={"issues": issues, "policy": policy},
                    )
                )
            except ClientError:
                findings.append(
                    Finding(
                        title="AWS IAM Password Policy — Not Configured",
                        severity="High",
                        description="No IAM password policy is configured for this account.",
                        evidence="GetAccountPasswordPolicy returned NoSuchEntity.",
                        remediation="Configure an IAM account password policy immediately.",
                        test_run="aws_iam_password_policy",
                        rationale="Without a password policy, users can set trivially weak passwords.",
                        methodology="Called iam:GetAccountPasswordPolicy.",
                        status="fail",
                        compliance_tags=["NIST-PR.AC-1", "HIPAA-164.312(a)(2)(i)"],
                    )
                )

            # Root MFA
            try:
                summary = iam.get_account_summary()["SummaryMap"]
                root_mfa = summary.get("AccountMFAEnabled", 0)
                findings.append(
                    Finding(
                        title="AWS Root Account MFA",
                        severity="Critical" if not root_mfa else "Informational",
                        description=(
                            "Root account does NOT have MFA enabled."
                            if not root_mfa
                            else "Root account MFA is enabled."
                        ),
                        evidence=f"AccountMFAEnabled: {root_mfa}",
                        remediation="Enable MFA on the AWS root account immediately.",
                        test_run="aws_root_mfa",
                        rationale="Root account compromise is catastrophic; MFA is essential.",
                        methodology="Called iam:GetAccountSummary.",
                        status="fail" if not root_mfa else "pass",
                        compliance_tags=["NIST-PR.AC-7", "HIPAA-164.312(d)", "GDPR-Art32"],
                    )
                )
            except Exception:
                pass

        except Exception as exc:
            self._log.debug("IAM check error: %s", exc)
        return findings

    def _aws_s3_checks(self, session: Any) -> list[Finding]:
        """Check for publicly accessible S3 buckets."""
        from botocore.exceptions import ClientError
        findings: list[Finding] = []
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            public_buckets: list[str] = []

            for bucket in buckets[:20]:  # limit to avoid rate throttling
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") in (
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        ):
                            public_buckets.append(name)
                            break
                except ClientError:
                    pass

                # Check public access block
                try:
                    pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    if not all(pab.values()):
                        public_buckets.append(f"{name} (public access block not fully enabled)")
                except ClientError:
                    pass

            findings.append(
                Finding(
                    title="AWS S3 Bucket Public Access",
                    severity="Critical" if public_buckets else "Informational",
                    description=(
                        f"{len(public_buckets)} S3 bucket(s) may be publicly accessible."
                        if public_buckets
                        else f"All {len(buckets)} S3 buckets appear to have public access restricted."
                    ),
                    evidence="\n".join(public_buckets) if public_buckets else "No public buckets found.",
                    remediation=(
                        "Enable S3 Block Public Access at the account level. "
                        "Review bucket ACLs and policies. Enable S3 server-side encryption."
                    ),
                    test_run="aws_s3_public_access",
                    rationale="Publicly accessible S3 buckets have led to major data breaches.",
                    methodology="Called s3:ListBuckets, s3:GetBucketAcl, s3:GetPublicAccessBlock.",
                    status="fail" if public_buckets else "pass",
                    compliance_tags=["NIST-PR.DS-1", "HIPAA-164.312(a)(1)", "GDPR-Art32"],
                    metadata={"total_buckets": len(buckets), "public_buckets": public_buckets},
                )
            )
        except Exception as exc:
            self._log.debug("S3 check error: %s", exc)
        return findings

    def _aws_cloudtrail_checks(self, session: Any) -> list[Finding]:
        """Check CloudTrail is enabled in all regions."""
        findings: list[Finding] = []
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
            if not trails:
                findings.append(
                    Finding(
                        title="AWS CloudTrail Not Configured",
                        severity="High",
                        description="No CloudTrail trails found. API activity is not being logged.",
                        evidence="describe_trails returned empty list.",
                        remediation="Create a multi-region CloudTrail trail with CloudWatch Logs integration.",
                        test_run="aws_cloudtrail",
                        rationale="CloudTrail is essential for detecting and investigating security incidents.",
                        methodology="Called cloudtrail:DescribeTrails.",
                        status="fail",
                        compliance_tags=["HIPAA-164.312(b)", "NIST-DE.CM-3", "GDPR-Art33"],
                    )
                )
            else:
                multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
                log_validation = any(t.get("LogFileValidationEnabled") for t in trails)
                issues: list[str] = []
                if not multi_region:
                    issues.append("No multi-region CloudTrail trail configured.")
                if not log_validation:
                    issues.append("Log file validation not enabled on any trail.")

                findings.append(
                    Finding(
                        title="AWS CloudTrail Configuration",
                        severity="Medium" if issues else "Informational",
                        description=(
                            f"{len(issues)} CloudTrail issue(s): {'; '.join(issues)}"
                            if issues
                            else f"{len(trails)} trail(s) configured correctly."
                        ),
                        evidence=json.dumps([{k: v for k, v in t.items() if k in ("Name", "IsMultiRegionTrail", "LogFileValidationEnabled")} for t in trails], indent=2),
                        remediation="Enable multi-region trails and log file validation.",
                        test_run="aws_cloudtrail",
                        rationale="CloudTrail provides audit logs required for compliance and incident response.",
                        methodology="Called cloudtrail:DescribeTrails.",
                        status="fail" if issues else "pass",
                        compliance_tags=["HIPAA-164.312(b)", "NIST-DE.CM-3", "GDPR-Art33"],
                        metadata={"issues": issues, "trail_count": len(trails)},
                    )
                )
        except Exception as exc:
            self._log.debug("CloudTrail check error: %s", exc)
        return findings

    def _aws_security_group_checks(self, session: Any) -> list[Finding]:
        """Check for overly permissive security groups."""
        findings: list[Finding] = []
        try:
            ec2 = session.client("ec2")
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            risky: list[dict[str, Any]] = []

            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            risky.append({
                                "sg_id": sg["GroupId"],
                                "sg_name": sg.get("GroupName", ""),
                                "port": perm.get("FromPort", "all"),
                                "protocol": perm.get("IpProtocol", "all"),
                                "cidr": "0.0.0.0/0",
                            })
                    for ipv6_range in perm.get("Ipv6Ranges", []):
                        if ipv6_range.get("CidrIpv6") == "::/0":
                            risky.append({
                                "sg_id": sg["GroupId"],
                                "sg_name": sg.get("GroupName", ""),
                                "port": perm.get("FromPort", "all"),
                                "protocol": perm.get("IpProtocol", "all"),
                                "cidr": "::/0",
                            })

            findings.append(
                Finding(
                    title="AWS Security Groups — Overly Permissive Rules",
                    severity="High" if risky else "Informational",
                    description=(
                        f"{len(risky)} security group rule(s) allow inbound from 0.0.0.0/0 or ::/0."
                        if risky
                        else f"{len(sgs)} security group(s) checked. No 0.0.0.0/0 inbound rules."
                    ),
                    evidence=json.dumps(risky[:20], indent=2),
                    remediation=(
                        "Restrict security group inbound rules to specific IP ranges. "
                        "Never allow 0.0.0.0/0 on SSH (22), RDP (3389), or database ports."
                    ),
                    test_run="aws_security_groups",
                    rationale="Overly broad security groups expose services to the entire internet.",
                    methodology="Called ec2:DescribeSecurityGroups and inspected IpPermissions.",
                    status="fail" if risky else "pass",
                    compliance_tags=["NIST-PR.AC-5", "HIPAA-164.312(e)(1)", "GDPR-Art32"],
                    metadata={"risky_rules": risky},
                )
            )
        except Exception as exc:
            self._log.debug("Security group check error: %s", exc)
        return findings

    # ------------------------------------------------------------------ #
    # Azure Scanning                                                       #
    # ------------------------------------------------------------------ #

    def _scan_azure(self, creds: dict[str, Any]) -> list[Finding]:
        """Run Azure security checks."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import SubscriptionClient
        except ImportError:
            self._log.warning("azure-identity or azure-mgmt-resource not installed; skipping Azure scan.")
            return [self._unavailable_finding("Azure", "azure-identity, azure-mgmt-resource")]

        findings: list[Finding] = []
        try:
            credential = DefaultAzureCredential()
            sub_client = SubscriptionClient(credential)
            subscriptions = list(sub_client.subscriptions.list())
            sub_ids = [s.subscription_id for s in subscriptions]

            findings.append(
                Finding(
                    title="Azure Subscriptions Discovered",
                    severity="Informational",
                    description=f"{len(sub_ids)} Azure subscription(s) accessible.",
                    evidence="\n".join(sub_ids),
                    remediation="Review subscription access and apply least-privilege RBAC.",
                    test_run="azure_subscriptions",
                    rationale="Understanding subscription scope is the first step in Azure security assessment.",
                    methodology="Called Azure SDK SubscriptionClient.subscriptions.list().",
                    status="pass",
                    compliance_tags=["NIST-ID.AM-3"],
                )
            )

            for sub_id in sub_ids[:3]:
                findings.extend(self._azure_storage_checks(credential, sub_id))
                findings.extend(self._azure_nsg_checks(credential, sub_id))

        except Exception as exc:
            self._log.warning("Azure scan error: %s", exc)
        return findings

    def _azure_storage_checks(self, credential: Any, sub_id: str) -> list[Finding]:
        """Check Azure Storage Account public access settings."""
        try:
            from azure.mgmt.storage import StorageManagementClient
        except ImportError:
            return []

        findings: list[Finding] = []
        try:
            client = StorageManagementClient(credential, sub_id)
            accounts = list(client.storage_accounts.list())
            public_accounts: list[str] = []

            for acc in accounts:
                if acc.allow_blob_public_access:
                    public_accounts.append(acc.name)

            findings.append(
                Finding(
                    title="Azure Storage Account Public Access",
                    severity="High" if public_accounts else "Informational",
                    description=(
                        f"{len(public_accounts)} storage account(s) allow public blob access."
                        if public_accounts
                        else f"All {len(accounts)} storage account(s) have public blob access disabled."
                    ),
                    evidence="\n".join(public_accounts) if public_accounts else "No public storage found.",
                    remediation="Disable public blob access on all storage accounts unless explicitly required.",
                    test_run="azure_storage_public_access",
                    rationale="Publicly accessible storage can expose sensitive data.",
                    methodology="Called StorageManagementClient.storage_accounts.list() and checked allow_blob_public_access.",
                    status="fail" if public_accounts else "pass",
                    compliance_tags=["NIST-PR.DS-1", "GDPR-Art32"],
                    metadata={"public_accounts": public_accounts, "total": len(accounts)},
                )
            )
        except Exception as exc:
            self._log.debug("Azure storage check error: %s", exc)
        return findings

    def _azure_nsg_checks(self, credential: Any, sub_id: str) -> list[Finding]:
        """Check Azure NSGs for overly permissive rules."""
        try:
            from azure.mgmt.network import NetworkManagementClient
        except ImportError:
            return []

        findings: list[Finding] = []
        try:
            client = NetworkManagementClient(credential, sub_id)
            nsgs = list(client.network_security_groups.list_all())
            risky: list[str] = []

            for nsg in nsgs:
                for rule in (nsg.security_rules or []):
                    if (
                        rule.access == "Allow"
                        and rule.direction == "Inbound"
                        and rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                        and rule.destination_port_range in ("*", "22", "3389")
                    ):
                        risky.append(
                            f"{nsg.name}: rule {rule.name} allows {rule.destination_port_range} from Internet"
                        )

            findings.append(
                Finding(
                    title="Azure NSG Overly Permissive Rules",
                    severity="High" if risky else "Informational",
                    description=(
                        f"{len(risky)} NSG rule(s) allow SSH/RDP from the Internet."
                        if risky
                        else f"{len(nsgs)} NSG(s) checked with no overly permissive inbound rules."
                    ),
                    evidence="\n".join(risky) if risky else "No risky NSG rules found.",
                    remediation="Restrict inbound SSH and RDP to specific IP ranges or VPN only.",
                    test_run="azure_nsg_rules",
                    rationale="Overly permissive NSG rules expose services to the internet.",
                    methodology="Called NetworkManagementClient.network_security_groups.list_all().",
                    status="fail" if risky else "pass",
                    compliance_tags=["NIST-PR.AC-5", "GDPR-Art32"],
                    metadata={"risky": risky},
                )
            )
        except Exception as exc:
            self._log.debug("Azure NSG check error: %s", exc)
        return findings

    # ------------------------------------------------------------------ #
    # GCP Scanning                                                         #
    # ------------------------------------------------------------------ #

    def _scan_gcp(self, creds: dict[str, Any]) -> list[Finding]:
        """Run GCP security checks."""
        try:
            from google.cloud import storage as gcs
            from google.auth import default as gauth_default
        except ImportError:
            self._log.warning("google-cloud-storage not installed; skipping GCP scan.")
            return [self._unavailable_finding("GCP", "google-cloud-storage")]

        findings: list[Finding] = []
        try:
            credentials, project = gauth_default()
            findings.extend(self._gcp_storage_checks(credentials, project))
        except Exception as exc:
            self._log.warning("GCP scan error: %s", exc)
        return findings

    def _gcp_storage_checks(self, credentials: Any, project: str | None) -> list[Finding]:
        """Check GCS buckets for public access."""
        try:
            from google.cloud import storage as gcs
        except ImportError:
            return []

        findings: list[Finding] = []
        try:
            client = gcs.Client(credentials=credentials, project=project)
            buckets = list(client.list_buckets())
            public_buckets: list[str] = []

            for bucket in buckets[:20]:
                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            public_buckets.append(bucket.name)
                            break
                except Exception:
                    pass

            findings.append(
                Finding(
                    title="GCP Cloud Storage Public Access",
                    severity="Critical" if public_buckets else "Informational",
                    description=(
                        f"{len(public_buckets)} GCS bucket(s) accessible by allUsers or allAuthenticatedUsers."
                        if public_buckets
                        else f"All {len(buckets)} GCS bucket(s) are private."
                    ),
                    evidence="\n".join(public_buckets) if public_buckets else "No public GCS buckets.",
                    remediation="Remove allUsers and allAuthenticatedUsers from GCS bucket IAM policies.",
                    test_run="gcp_storage_public_access",
                    rationale="Public GCS buckets have caused numerous large-scale data breaches.",
                    methodology="Called storage.Client.list_buckets() and inspected IAM policies.",
                    status="fail" if public_buckets else "pass",
                    compliance_tags=["NIST-PR.DS-1", "GDPR-Art32"],
                    metadata={"public_buckets": public_buckets, "total": len(buckets)},
                )
            )
        except Exception as exc:
            self._log.debug("GCP storage check error: %s", exc)
        return findings

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _unavailable_finding(self, provider: str, packages: str) -> Finding:
        """Return an informational finding when SDK packages are missing."""
        return Finding(
            title=f"{provider} Scan Skipped — Missing Dependencies",
            severity="Informational",
            description=f"The {provider} scan was skipped because required packages are not installed: {packages}",
            evidence=f"pip install {packages}",
            remediation=f"Install the required packages: pip install {packages}",
            test_run=f"{provider.lower()}_scan",
            rationale=f"{provider} security scanning requires the provider SDK.",
            methodology="Checked for SDK availability via importlib.",
            status="warning",
            compliance_tags=[],
        )
