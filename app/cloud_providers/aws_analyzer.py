import boto3
from typing import List, Dict
from models.security_findings import SecurityFinding
from models.compliance import ComplianceCheck

class AWSSecurityAnalyzer:
    def __init__(self, account_id: str):
        self.account_id = account_id
        self.iam_client = boto3.client('iam')
        self.ec2_client = boto3.client('ec2')
        self.s3_client = boto3.client('s3')

    async def analyze_iam_policies(self) -> List[SecurityFinding]:
        findings = []
        try:
            policies = self.iam_client.list_policies(Scope='Local')
            for policy in policies['Policies']:
                policy_version = self.iam_client.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )
                
                # Check for overly permissive policies
                if self._is_policy_overly_permissive(policy_version['PolicyVersion']['Document']):
                    findings.append(
                        SecurityFinding(
                            resource_id=policy['Arn'],
                            severity="HIGH",
                            finding_type="IAM_POLICY_TOO_PERMISSIVE",
                            description="IAM policy contains overly permissive actions",
                            remediation="Review and restrict IAM policy permissions"
                        )
                    )
        except Exception as e:
            findings.append(
                SecurityFinding(
                    resource_id=self.account_id,
                    severity="ERROR",
                    finding_type="IAM_ANALYSIS_ERROR",
                    description=f"Error analyzing IAM policies: {str(e)}",
                    remediation="Check AWS credentials and permissions"
                )
            )
        return findings

    async def analyze_security_groups(self) -> List[SecurityFinding]:
        findings = []
        try:
            security_groups = self.ec2_client.describe_security_groups()
            for sg in security_groups['SecurityGroups']:
                # Check for open ports
                for permission in sg['IpPermissions']:
                    if self._is_security_group_too_permissive(permission):
                        findings.append(
                            SecurityFinding(
                                resource_id=sg['GroupId'],
                                severity="HIGH",
                                finding_type="SECURITY_GROUP_TOO_PERMISSIVE",
                                description=f"Security group {sg['GroupId']} has overly permissive rules",
                                remediation="Restrict security group rules to specific IP ranges and ports"
                            )
                        )
        except Exception as e:
            findings.append(
                SecurityFinding(
                    resource_id=self.account_id,
                    severity="ERROR",
                    finding_type="SECURITY_GROUP_ANALYSIS_ERROR",
                    description=f"Error analyzing security groups: {str(e)}",
                    remediation="Check AWS credentials and permissions"
                )
            )
        return findings

    def _is_policy_overly_permissive(self, policy_doc: Dict) -> bool:
        for statement in policy_doc['Statement']:
            if statement['Effect'] == 'Allow' and '*' in statement.get('Action', []):
                return True
        return False

    def _is_security_group_too_permissive(self, permission: Dict) -> bool:
        for ip_range in permission.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
        return False

    async def run_security_assessment(self) -> Dict:
        iam_findings = await self.analyze_iam_policies()
        sg_findings = await self.analyze_security_groups()
        
        return {
            "account_id": self.account_id,
            "findings": iam_findings + sg_findings,
            "summary": {
                "total_findings": len(iam_findings) + len(sg_findings),
                "high_severity": len([f for f in iam_findings + sg_findings if f.severity == "HIGH"]),
                "medium_severity": len([f for f in iam_findings + sg_findings if f.severity == "MEDIUM"]),
                "low_severity": len([f for f in iam_findings + sg_findings if f.severity == "LOW"])
            }
        }
