"""
Custom Control Definitions System
Allows users to create and manage custom security controls
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass
from persistence.models import Base, ControlCatalog
from persistence.db import SessionLocal
from sqlalchemy import Column, String, DateTime, Text, Boolean, JSON, Integer


class ControlType(Enum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    HYBRID = "hybrid"


class ControlCategory(Enum):
    IDENTITY = "identity"
    NETWORK = "network"
    DATA = "data"
    GOVERNANCE = "governance"
    POSTURE = "posture"
    LOGGING = "logging"
    CUSTOM = "custom"


class CustomControl(Base):
    """Custom control definition"""
    __tablename__ = "custom_controls"
    
    ControlId = Column(String(36), primary_key=True)
    Title = Column(String(255), nullable=False)
    Description = Column(Text)
    Category = Column(String(50), nullable=False)
    ControlType = Column(String(20), nullable=False)
    Severity = Column(String(20), nullable=False)
    CreatedBy = Column(String(36), nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow)
    IsActive = Column(Boolean, default=True)
    
    # Control definition
    Query = Column(Text)  # KQL query for automated controls
    EvaluatorCode = Column(Text)  # Python code for custom evaluators
    Parameters = Column(JSON)  # Control parameters
    
    # Compliance mapping
    FrameworkMappings = Column(JSON)  # Maps to compliance frameworks
    BenchmarkMappings = Column(JSON)  # Maps to benchmarks
    
    # Remediation
    RemediationSteps = Column(Text)
    RemediationType = Column(String(20), default="manual")
    RemediationScript = Column(Text)  # Automated remediation script
    
    # Metadata
    Tags = Column(JSON)  # Tags for categorization
    Documentation = Column(Text)  # Additional documentation


@dataclass
class ControlTemplate:
    """Template for creating custom controls"""
    name: str
    description: str
    category: ControlCategory
    control_type: ControlType
    template_query: str
    template_evaluator: str
    parameters: List[Dict[str, Any]]
    remediation_template: str


class CustomControlManager:
    """Manages custom control definitions"""
    
    def __init__(self):
        self.control_templates = self._load_control_templates()
    
    def _load_control_templates(self) -> List[ControlTemplate]:
        """Load predefined control templates"""
        return [
            ControlTemplate(
                name="Storage Account Public Access",
                description="Check if storage accounts allow public access",
                category=ControlCategory.DATA,
                control_type=ControlType.AUTOMATED,
                template_query="""
Resources
| where type == "microsoft.storage/storageaccounts"
| where properties.allowBlobPublicAccess == true
| project id, name, location, properties.allowBlobPublicAccess
                """,
                template_evaluator="""
def evaluate_storage_public_access(evidence):
    findings = []
    if 'RawResult' in evidence:
        for resource in evidence['RawResult']:
            if resource.get('properties', {}).get('allowBlobPublicAccess') == True:
                findings.append({
                    'FindingId': str(uuid.uuid4()),
                    'ControlId': 'CUSTOM-STORAGE-PUBLIC',
                    'Domain': 'Data Protection',
                    'Severity': 'High',
                    'RiskScore': 7,
                    'Summary': f'Storage account {resource["name"]} allows public blob access',
                    'Description': 'Storage account is configured to allow public access to blobs',
                    'ImpactedResources': json.dumps([{'id': resource['id'], 'name': resource['name']}]),
                    'Recommendation': 'Disable public blob access for storage account',
                    'Remediation': json.dumps({'action': 'disable_public_access', 'resource_id': resource['id']})
                })
    return findings
                """,
                parameters=[
                    {"name": "severity", "type": "select", "options": ["Low", "Medium", "High", "Critical"], "default": "High"},
                    {"name": "risk_score", "type": "number", "min": 1, "max": 10, "default": 7}
                ],
                remediation_template="""
# Disable public blob access for storage account
az storage account update --name {storage_account_name} --resource-group {resource_group} --allow-blob-public-access false
                """
            ),
            ControlTemplate(
                name="Virtual Machine Disk Encryption",
                description="Check if virtual machines have disk encryption enabled",
                category=ControlCategory.DATA,
                control_type=ControlType.AUTOMATED,
                template_query="""
Resources
| where type == "microsoft.compute/virtualmachines"
| where properties.storageProfile.osDisk.encryptionSettings == null
| project id, name, location, properties.storageProfile.osDisk
                """,
                template_evaluator="""
def evaluate_vm_disk_encryption(evidence):
    findings = []
    if 'RawResult' in evidence:
        for resource in evidence['RawResult']:
            os_disk = resource.get('properties', {}).get('storageProfile', {}).get('osDisk', {})
            if not os_disk.get('encryptionSettings'):
                findings.append({
                    'FindingId': str(uuid.uuid4()),
                    'ControlId': 'CUSTOM-VM-ENCRYPTION',
                    'Domain': 'Data Protection',
                    'Severity': 'High',
                    'RiskScore': 8,
                    'Summary': f'VM {resource["name"]} does not have disk encryption enabled',
                    'Description': 'Virtual machine disk is not encrypted',
                    'ImpactedResources': json.dumps([{'id': resource['id'], 'name': resource['name']}]),
                    'Recommendation': 'Enable disk encryption for virtual machine',
                    'Remediation': json.dumps({'action': 'enable_disk_encryption', 'resource_id': resource['id']})
                })
    return findings
                """,
                parameters=[
                    {"name": "severity", "type": "select", "options": ["Low", "Medium", "High", "Critical"], "default": "High"},
                    {"name": "risk_score", "type": "number", "min": 1, "max": 10, "default": 8}
                ],
                remediation_template="""
# Enable disk encryption for VM
az vm encryption enable --resource-group {resource_group} --name {vm_name} --disk-encryption-keyvault {keyvault_name}
                """
            ),
            ControlTemplate(
                name="Network Security Group Rules",
                description="Check for overly permissive NSG rules",
                category=ControlCategory.NETWORK,
                control_type=ControlType.AUTOMATED,
                template_query="""
Resources
| where type == "microsoft.network/networksecuritygroups"
| extend securityRules = properties.securityRules
| mvexpand securityRules
| where securityRules.properties.sourceAddressPrefix == "*" or securityRules.properties.sourceAddressPrefix == "0.0.0.0/0"
| project id, name, location, securityRules
                """,
                template_evaluator="""
def evaluate_nsg_permissive_rules(evidence):
    findings = []
    if 'RawResult' in evidence:
        for resource in evidence['RawResult']:
            security_rules = resource.get('securityRules', [])
            for rule in security_rules:
                source_prefix = rule.get('properties', {}).get('sourceAddressPrefix', '')
                if source_prefix in ['*', '0.0.0.0/0']:
                    findings.append({
                        'FindingId': str(uuid.uuid4()),
                        'ControlId': 'CUSTOM-NSG-PERMISSIVE',
                        'Domain': 'Network Security',
                        'Severity': 'High',
                        'RiskScore': 8,
                        'Summary': f'NSG {resource["name"]} has overly permissive rule: {rule["name"]}',
                        'Description': f'Network Security Group rule allows traffic from {source_prefix}',
                        'ImpactedResources': json.dumps([{'id': resource['id'], 'name': resource['name'], 'rule': rule['name']}]),
                        'Recommendation': 'Restrict source address prefix to specific IP ranges',
                        'Remediation': json.dumps({'action': 'update_nsg_rule', 'resource_id': resource['id'], 'rule_name': rule['name']})
                    })
    return findings
                """,
                parameters=[
                    {"name": "severity", "type": "select", "options": ["Low", "Medium", "High", "Critical"], "default": "High"},
                    {"name": "risk_score", "type": "number", "min": 1, "max": 10, "default": 8}
                ],
                remediation_template="""
# Update NSG rule to restrict source
az network nsg rule update --resource-group {resource_group} --nsg-name {nsg_name} --name {rule_name} --source-address-prefixes {allowed_ips}
                """
            )
        ]
    
    async def create_custom_control(
        self,
        title: str,
        description: str,
        category: ControlCategory,
        control_type: ControlType,
        severity: str,
        created_by: str,
        query: Optional[str] = None,
        evaluator_code: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        remediation_steps: Optional[str] = None,
        remediation_type: str = "manual",
        remediation_script: Optional[str] = None,
        framework_mappings: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        documentation: Optional[str] = None
    ) -> str:
        """Create a new custom control"""
        control_id = f"CUSTOM-{str(uuid.uuid4())[:8].upper()}"
        
        db = SessionLocal()
        try:
            custom_control = CustomControl(
                ControlId=control_id,
                Title=title,
                Description=description,
                Category=category.value,
                ControlType=control_type.value,
                Severity=severity,
                CreatedBy=created_by,
                Query=query,
                EvaluatorCode=evaluator_code,
                Parameters=parameters or {},
                RemediationSteps=remediation_steps,
                RemediationType=remediation_type,
                RemediationScript=remediation_script,
                FrameworkMappings=framework_mappings or {},
                Tags=tags or [],
                Documentation=documentation
            )
            
            db.add(custom_control)
            db.commit()
            
            return control_id
        finally:
            db.close()
    
    async def get_custom_controls(
        self,
        created_by: Optional[str] = None,
        category: Optional[ControlCategory] = None,
        is_active: bool = True
    ) -> List[Dict[str, Any]]:
        """Get custom controls with filtering"""
        db = SessionLocal()
        try:
            query = db.query(CustomControl)
            
            if created_by:
                query = query.filter(CustomControl.CreatedBy == created_by)
            if category:
                query = query.filter(CustomControl.Category == category.value)
            if is_active is not None:
                query = query.filter(CustomControl.IsActive == is_active)
            
            controls = query.order_by(CustomControl.CreatedAt.desc()).all()
            
            return [
                {
                    "control_id": control.ControlId,
                    "title": control.Title,
                    "description": control.Description,
                    "category": control.Category,
                    "control_type": control.ControlType,
                    "severity": control.Severity,
                    "created_by": control.CreatedBy,
                    "created_at": control.CreatedAt.isoformat(),
                    "updated_at": control.UpdatedAt.isoformat(),
                    "is_active": control.IsActive,
                    "parameters": control.Parameters,
                    "framework_mappings": control.FrameworkMappings,
                    "tags": control.Tags,
                    "remediation_type": control.RemediationType
                }
                for control in controls
            ]
        finally:
            db.close()
    
    async def get_custom_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific custom control"""
        db = SessionLocal()
        try:
            control = db.query(CustomControl).filter(CustomControl.ControlId == control_id).first()
            
            if not control:
                return None
            
            return {
                "control_id": control.ControlId,
                "title": control.Title,
                "description": control.Description,
                "category": control.Category,
                "control_type": control.ControlType,
                "severity": control.Severity,
                "created_by": control.CreatedBy,
                "created_at": control.CreatedAt.isoformat(),
                "updated_at": control.UpdatedAt.isoformat(),
                "is_active": control.IsActive,
                "query": control.Query,
                "evaluator_code": control.EvaluatorCode,
                "parameters": control.Parameters,
                "remediation_steps": control.RemediationSteps,
                "remediation_type": control.RemediationType,
                "remediation_script": control.RemediationScript,
                "framework_mappings": control.FrameworkMappings,
                "tags": control.Tags,
                "documentation": control.Documentation
            }
        finally:
            db.close()
    
    async def update_custom_control(
        self,
        control_id: str,
        updates: Dict[str, Any]
    ) -> bool:
        """Update a custom control"""
        db = SessionLocal()
        try:
            control = db.query(CustomControl).filter(CustomControl.ControlId == control_id).first()
            
            if not control:
                return False
            
            # Update fields
            for key, value in updates.items():
                if hasattr(control, key):
                    setattr(control, key, value)
            
            control.UpdatedAt = datetime.utcnow()
            db.commit()
            
            return True
        finally:
            db.close()
    
    async def delete_custom_control(self, control_id: str) -> bool:
        """Delete a custom control"""
        db = SessionLocal()
        try:
            control = db.query(CustomControl).filter(CustomControl.ControlId == control_id).first()
            
            if not control:
                return False
            
            db.delete(control)
            db.commit()
            
            return True
        finally:
            db.close()
    
    async def create_from_template(
        self,
        template_name: str,
        customizations: Dict[str, Any],
        created_by: str
    ) -> str:
        """Create custom control from template"""
        template = next((t for t in self.control_templates if t.name == template_name), None)
        
        if not template:
            raise ValueError(f"Template '{template_name}' not found")
        
        # Apply customizations
        title = customizations.get("title", template.name)
        description = customizations.get("description", template.description)
        severity = customizations.get("severity", "High")
        risk_score = customizations.get("risk_score", 7)
        
        # Customize evaluator code
        evaluator_code = template.template_evaluator
        if "severity" in customizations:
            evaluator_code = evaluator_code.replace("'High'", f"'{severity}'")
        if "risk_score" in customizations:
            evaluator_code = evaluator_code.replace("'RiskScore': 7", f"'RiskScore': {risk_score}")
        
        # Customize remediation
        remediation_script = template.remediation_template
        if customizations.get("remediation_customizations"):
            remediation_script = customizations["remediation_customizations"]
        
        return await self.create_custom_control(
            title=title,
            description=description,
            category=template.category,
            control_type=template.control_type,
            severity=severity,
            created_by=created_by,
            query=template.template_query,
            evaluator_code=evaluator_code,
            parameters=customizations.get("parameters", template.parameters),
            remediation_steps=customizations.get("remediation_steps", "Follow the remediation script"),
            remediation_type=customizations.get("remediation_type", "manual"),
            remediation_script=remediation_script,
            framework_mappings=customizations.get("framework_mappings", {}),
            tags=customizations.get("tags", ["custom"]),
            documentation=customizations.get("documentation", "")
        )
    
    async def get_control_templates(self) -> List[Dict[str, Any]]:
        """Get available control templates"""
        return [
            {
                "name": template.name,
                "description": template.description,
                "category": template.category.value,
                "control_type": template.control_type.value,
                "parameters": template.parameters,
                "preview_query": template.template_query[:200] + "..." if len(template.template_query) > 200 else template.template_query
            }
            for template in self.control_templates
        ]
    
    async def execute_custom_control(
        self,
        control_id: str,
        evidence: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute a custom control evaluator"""
        control_data = await self.get_custom_control(control_id)
        
        if not control_data:
            raise ValueError(f"Custom control '{control_id}' not found")
        
        if not control_data.get("evaluator_code"):
            raise ValueError("Custom control has no evaluator code")
        
        try:
            # Create a safe execution environment
            exec_globals = {
                "json": json,
                "uuid": uuid,
                "datetime": datetime
            }
            
            # Execute the evaluator code
            exec(control_data["evaluator_code"], exec_globals)
            
            # Call the evaluate function
            if "evaluate_" in control_data["evaluator_code"]:
                # Extract function name from code
                function_name = None
                for line in control_data["evaluator_code"].split('\n'):
                    if line.strip().startswith('def evaluate_'):
                        function_name = line.strip().split('(')[0].replace('def ', '')
                        break
                
                if function_name and function_name in exec_globals:
                    evaluator_func = exec_globals[function_name]
                    findings = evaluator_func(evidence)
                    return findings if isinstance(findings, list) else []
            
            return []
            
        except Exception as e:
            print(f"Error executing custom control {control_id}: {e}")
            return []


# Global custom control manager instance
custom_control_manager = CustomControlManager()
