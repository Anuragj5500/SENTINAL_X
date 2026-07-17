"""
Cloud Security Module — Simulated cloud log collectors for AWS, Azure, and GCP.
Provides realistic demo data for cloud security monitoring.
"""
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any


# ─────────────────────────── Cloud Event Templates ────────────────────────────

AWS_EVENTS = [
    {"event_type": "ConsoleLogin", "source": "aws_cloudtrail", "severity": "info", "service": "IAM", "description": "AWS Console login"},
    {"event_type": "UnauthorizedAccess", "source": "aws_guardduty", "severity": "critical", "service": "GuardDuty", "description": "Unauthorized API call from unusual IP"},
    {"event_type": "S3BucketPolicyChange", "source": "aws_cloudtrail", "severity": "high", "service": "S3", "description": "S3 bucket policy modified to allow public access"},
    {"event_type": "SecurityGroupModified", "source": "aws_cloudtrail", "severity": "high", "service": "EC2", "description": "Security group ingress rule added: 0.0.0.0/0:22"},
    {"event_type": "RootAccountUsed", "source": "aws_cloudtrail", "severity": "critical", "service": "IAM", "description": "Root account used for API call"},
    {"event_type": "IAMPolicyAttached", "source": "aws_cloudtrail", "severity": "medium", "service": "IAM", "description": "AdministratorAccess policy attached to user"},
    {"event_type": "KMSKeyDisabled", "source": "aws_cloudtrail", "severity": "high", "service": "KMS", "description": "Customer-managed KMS key disabled"},
    {"event_type": "EC2InstanceLaunched", "source": "aws_cloudtrail", "severity": "info", "service": "EC2", "description": "New EC2 instance launched in us-east-1"},
    {"event_type": "MFADisabled", "source": "aws_cloudtrail", "severity": "high", "service": "IAM", "description": "MFA device deactivated for IAM user"},
    {"event_type": "AccessKeyCreated", "source": "aws_cloudtrail", "severity": "medium", "service": "IAM", "description": "New access key created for IAM user"},
]

AZURE_EVENTS = [
    {"event_type": "SignInAttempt", "source": "azure_ad", "severity": "info", "service": "Azure AD", "description": "Interactive sign-in from new location"},
    {"event_type": "RiskySignIn", "source": "azure_ad", "severity": "high", "service": "Azure AD", "description": "Sign-in from anonymous IP address"},
    {"event_type": "RoleAssignment", "source": "azure_activity", "severity": "high", "service": "RBAC", "description": "Owner role assigned to user at subscription scope"},
    {"event_type": "NSGRuleModified", "source": "azure_activity", "severity": "high", "service": "Network", "description": "NSG rule modified to allow inbound RDP from any"},
    {"event_type": "KeyVaultAccess", "source": "azure_keyvault", "severity": "medium", "service": "Key Vault", "description": "Secret accessed from unusual IP"},
    {"event_type": "StorageBlobPublic", "source": "azure_activity", "severity": "critical", "service": "Storage", "description": "Blob container access level changed to public"},
    {"event_type": "VMDeleted", "source": "azure_activity", "severity": "medium", "service": "Compute", "description": "Virtual machine deleted from production resource group"},
    {"event_type": "ConditionalAccessPolicyChanged", "source": "azure_ad", "severity": "high", "service": "Azure AD", "description": "Conditional access policy disabled"},
]

GCP_EVENTS = [
    {"event_type": "SetIAMPolicy", "source": "gcp_audit", "severity": "high", "service": "IAM", "description": "IAM policy binding added with roles/owner"},
    {"event_type": "CreateServiceAccount", "source": "gcp_audit", "severity": "medium", "service": "IAM", "description": "New service account created with editor role"},
    {"event_type": "FirewallRuleCreated", "source": "gcp_audit", "severity": "high", "service": "VPC", "description": "Firewall rule allowing ingress on all ports from 0.0.0.0/0"},
    {"event_type": "BucketIAMUpdated", "source": "gcp_audit", "severity": "critical", "service": "GCS", "description": "Cloud Storage bucket made publicly accessible"},
    {"event_type": "ServiceAccountKeyCreated", "source": "gcp_audit", "severity": "medium", "service": "IAM", "description": "User-managed service account key created"},
    {"event_type": "InstanceCreated", "source": "gcp_audit", "severity": "info", "service": "Compute", "description": "New compute instance created in us-central1"},
    {"event_type": "AuditLogDisabled", "source": "gcp_audit", "severity": "critical", "service": "Logging", "description": "Data access audit logging disabled for project"},
    {"event_type": "ExternalIPAssigned", "source": "gcp_audit", "severity": "medium", "service": "Compute", "description": "External IP assigned to compute instance"},
]

CLOUD_USERS = [
    "admin@company.com", "devops@company.com", "developer1@company.com",
    "sre-team@company.com", "security@company.com", "ci-cd-pipeline",
    "terraform-sa", "deploy-bot", "root", "system"
]

CLOUD_REGIONS = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
    "azure": ["eastus", "westeurope", "southeastasia", "westus2"],
    "gcp": ["us-central1", "europe-west1", "asia-east1", "us-east4"],
}


# ─────────────────────────── Collectors ───────────────────────────────────────

def _generate_cloud_event(template: dict, provider: str) -> Dict[str, Any]:
    """Generate a simulated cloud event from a template."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(
        hours=random.randint(0, 72),
        minutes=random.randint(0, 59),
    )
    regions = CLOUD_REGIONS.get(provider, ["unknown"])

    return {
        "timestamp": ts.isoformat(),
        "event_type": template["event_type"],
        "source": template["source"],
        "severity": template["severity"],
        "service": template["service"],
        "description": template["description"],
        "provider": provider,
        "region": random.choice(regions),
        "user": random.choice(CLOUD_USERS),
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "resource_id": f"arn:{provider}:{template['service'].lower()}:{''.join(random.choices('abcdef0123456789', k=12))}",
        "risk_score": {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 5}.get(template["severity"], 10),
    }


def collect_aws_events(count: int = 10) -> List[Dict[str, Any]]:
    """Generate simulated AWS CloudTrail / GuardDuty events."""
    return [_generate_cloud_event(random.choice(AWS_EVENTS), "aws") for _ in range(count)]


def collect_azure_events(count: int = 10) -> List[Dict[str, Any]]:
    """Generate simulated Azure AD / Activity Log events."""
    return [_generate_cloud_event(random.choice(AZURE_EVENTS), "azure") for _ in range(count)]


def collect_gcp_events(count: int = 10) -> List[Dict[str, Any]]:
    """Generate simulated GCP Audit Log events."""
    return [_generate_cloud_event(random.choice(GCP_EVENTS), "gcp") for _ in range(count)]


def collect_all_cloud_events(count_per_provider: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    """Collect events from all cloud providers."""
    return {
        "aws": collect_aws_events(count_per_provider),
        "azure": collect_azure_events(count_per_provider),
        "gcp": collect_gcp_events(count_per_provider),
    }


def get_cloud_posture() -> Dict[str, Any]:
    """Get simulated cloud security posture summary."""
    return {
        "providers": {
            "aws": {
                "status": "monitored",
                "regions": CLOUD_REGIONS["aws"],
                "services_monitored": ["CloudTrail", "GuardDuty", "IAM", "S3", "EC2", "KMS"],
                "findings": {
                    "critical": random.randint(1, 5),
                    "high": random.randint(3, 12),
                    "medium": random.randint(10, 30),
                    "low": random.randint(20, 50),
                },
                "compliance_score": round(random.uniform(65, 95), 1),
            },
            "azure": {
                "status": "monitored",
                "regions": CLOUD_REGIONS["azure"],
                "services_monitored": ["Azure AD", "Activity Log", "Key Vault", "NSG", "Storage"],
                "findings": {
                    "critical": random.randint(0, 3),
                    "high": random.randint(2, 8),
                    "medium": random.randint(8, 25),
                    "low": random.randint(15, 40),
                },
                "compliance_score": round(random.uniform(70, 95), 1),
            },
            "gcp": {
                "status": "monitored",
                "regions": CLOUD_REGIONS["gcp"],
                "services_monitored": ["Audit Logs", "IAM", "VPC", "GCS", "Compute"],
                "findings": {
                    "critical": random.randint(0, 2),
                    "high": random.randint(1, 6),
                    "medium": random.randint(5, 20),
                    "low": random.randint(10, 35),
                },
                "compliance_score": round(random.uniform(72, 98), 1),
            },
        },
        "total_findings": {
            "critical": random.randint(2, 10),
            "high": random.randint(6, 26),
            "medium": random.randint(23, 75),
            "low": random.randint(45, 125),
        },
        "last_scan": datetime.now(timezone.utc).isoformat(),
    }
