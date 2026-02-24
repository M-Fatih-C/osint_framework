from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
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

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    status = Column(String, nullable=False, default="pending")  # pending, running, complete, error
    modules_total = Column(Integer, nullable=False, default=0)
    correlated_intel = Column(JSONB, nullable=True)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now_naive)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
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
