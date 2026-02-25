from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import JSON as JSONB
from sqlalchemy import Uuid as UUID
import uuid
import datetime

Base = declarative_base()


def utc_now_naive() -> datetime.datetime:
    """UTC timestamp without tzinfo for compatibility with naive DB columns."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False)
    
    # Relationships
    scans = relationship("Scan", back_populates="target")

class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    status = Column(String, nullable=False, default="open", index=True)
    priority = Column(String, nullable=False, default="normal")
    tags = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=utc_now_naive)
    updated_at = Column(DateTime, default=utc_now_naive)

    # Relationships
    scans = relationship("Scan", back_populates="case")
    tracked_targets = relationship("CaseTarget", back_populates="case")
    notes = relationship("CaseNote", back_populates="case")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    status = Column(String, nullable=False, default="pending")  # pending, running, complete, error
    modules_total = Column(Integer, nullable=False, default=0)
    correlated_intel = Column(JSONB, nullable=True)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now_naive)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    case = relationship("Case", back_populates="scans")
    results = relationship("Result", back_populates="scan")
    reports = relationship("Report", back_populates="scan")

class Result(Base):
    __tablename__ = "results"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    module_name = Column(String, nullable=False)
    data = Column(JSONB, nullable=False)
    timestamp = Column(DateTime, default=utc_now_naive)
    
    # Relationships
    scan = relationship("Scan", back_populates="results")

class ModuleRegistry(Base):
    __tablename__ = "modules"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    version = Column(String, nullable=False)
    target_types = Column(JSONB, nullable=False)
    enabled = Column(Boolean, default=True)

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    format = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=utc_now_naive)
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=utc_now_naive, index=True)
    request_id = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False)
    path = Column(String, nullable=False, index=True)
    status_code = Column(Integer, nullable=False)
    client_ip = Column(String, nullable=True, index=True)
    user_agent = Column(String, nullable=True)
    duration_ms = Column(Integer, nullable=False, default=0)
    api_key_used = Column(Boolean, nullable=False, default=False)
    note = Column(String, nullable=True)


class CaseTarget(Base):
    __tablename__ = "case_targets"
    __table_args__ = (
        UniqueConstraint("case_id", "target_value", "target_type", name="uq_case_targets_case_value_type"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    target_value = Column(String, nullable=False)
    target_type = Column(String, nullable=False)
    first_seen_at = Column(DateTime, default=utc_now_naive)
    last_seen_at = Column(DateTime, default=utc_now_naive)

    case = relationship("Case", back_populates="tracked_targets")


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    content = Column(String, nullable=False)
    author = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now_naive)

    case = relationship("Case", back_populates="notes")
