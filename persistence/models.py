"""SQLAlchemy models for persistence layer (MVP).

Note: This is a starter module. For production, split models, migrations, and sessions.
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, Enum, JSON
from sqlalchemy.ext.declarative import declarative_base
import enum
import datetime

Base = declarative_base()

class SeverityEnum(enum.Enum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"

class FindingStatusEnum(enum.Enum):
    Open = "Open"
    InProgress = "InProgress"
    Resolved = "Resolved"
    Suppressed = "Suppressed"

class Evidence(Base):
    __tablename__ = "evidence"
    EvidenceId = Column(String, primary_key=True)
    Source = Column(String)
    QueryOrRequest = Column(Text)
    Timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    RawResult = Column(JSON)
    Hash = Column(String)

class Finding(Base):
    __tablename__ = "finding"
    FindingId = Column(String, primary_key=True)
    ControlId = Column(String, index=True)
    Domain = Column(String)
    Severity = Column(Enum(SeverityEnum))
    RiskScore = Column(Integer)
    Summary = Column(String, nullable=False)
    Description = Column(Text)
    ImpactedResources = Column(JSON)
    EvidenceRefs = Column(JSON)
    Recommendation = Column(Text)
    Remediation = Column(JSON)
    Status = Column(Enum(FindingStatusEnum), default=FindingStatusEnum.Open)
    GeneratedAt = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))

class Report(Base):
    __tablename__ = "report"
    ReportId = Column(String, primary_key=True)
    Scope = Column(JSON)
    BenchmarksApplied = Column(JSON)
    Metrics = Column(JSON)
    FindingsSnapshot = Column(JSON)
    GeneratedAt = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    IntegritySignature = Column(String)

class AuditRun(Base):
    __tablename__ = "auditrun"
    RunId = Column(String, primary_key=True)
    TriggerType = Column(String)
    Scope = Column(JSON)
    StartTime = Column(DateTime)
    EndTime = Column(DateTime)
    Status = Column(String)
    FindingsCount = Column(Integer)
    ReportId = Column(String)

class ControlCatalog(Base):
    __tablename__ = "controlcatalog"
    ControlId = Column(String, primary_key=True)
    Title = Column(String)
    Domain = Column(String)
    BenchmarkMappings = Column(JSON)
    Evaluator = Column(String)
    SeverityRules = Column(JSON)
    Recommendation = Column(Text)
    RemediationType = Column(String)
