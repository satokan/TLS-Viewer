from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Float, DECIMAL, func
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()

class Domain(Base):
    __tablename__ = 'domains'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    tld = Column(String(50), nullable=False, index=True)
    global_rank = Column(Integer, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    scan_results = relationship("ScanResult", back_populates="domain")

class ScanResult(Base):
    __tablename__ = 'scan_results'

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id'))
    scan_date = Column(DateTime, nullable=False, index=True)
    scan_status = Column(String(50), nullable=False)
    error_message = Column(Text)
    grade = Column(String(5))
    score = Column(DECIMAL(5, 2))
    created_at = Column(DateTime, default=func.now())

    domain = relationship("Domain", back_populates="scan_results")
    certificate = relationship("Certificate", uselist=False, back_populates="scan_result")
    tls_versions = relationship("TLSVersion", back_populates="scan_result")
    cipher_suites = relationship("CipherSuite", back_populates="scan_result")
    pqc_info = relationship("PQCInfo", uselist=False, back_populates="scan_result")
    geo_location = relationship("GeoLocation", uselist=False, back_populates="scan_result")

class Certificate(Base):
    __tablename__ = 'certificates'

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    signature_algorithm = Column(String(100))
    public_key_algorithm = Column(String(100))
    public_key_size = Column(Integer)
    issuer = Column(String(255))
    subject = Column(String(255))  # Subject DN
    ca_type = Column(String(50))
    valid_from = Column(DateTime)
    valid_until = Column(DateTime)
    is_valid = Column(Boolean)
    certificate_pem = Column(Text)  # Raw certificate in PEM format

    scan_result = relationship("ScanResult", back_populates="certificate")

class TLSVersion(Base):
    __tablename__ = 'tls_versions'

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    version = Column(String(50), nullable=False)
    is_supported = Column(Boolean, nullable=False)

    scan_result = relationship("ScanResult", back_populates="tls_versions")

class CipherSuite(Base):
    __tablename__ = 'cipher_suites'

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    name = Column(String(255), nullable=False)
    key_exchange = Column(String(100))
    authentication = Column(String(100))
    encryption = Column(String(100))
    mac = Column(String(100))
    is_forward_secret = Column(Boolean)
    is_weak = Column(Boolean)
    tls_version = Column(String(50))

    scan_result = relationship("ScanResult", back_populates="cipher_suites")

class PQCInfo(Base):
    __tablename__ = 'pqc_info'

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    is_supported = Column(Boolean, nullable=False)
    ml_kem_512 = Column(Boolean)
    ml_kem_768 = Column(Boolean)
    ml_kem_1024 = Column(Boolean)
    supported_suites = Column(Text)  # JSON string
    algorithm_combinations = Column(Text)  # JSON string

    scan_result = relationship("ScanResult", back_populates="pqc_info")

class GeoLocation(Base):
    __tablename__ = 'geo_locations'

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    ip_address = Column(String(45))
    country_code = Column(String(2))
    country_name = Column(String(100))
    region = Column(String(100))
    city = Column(String(100))
    latitude = Column(DECIMAL(10, 8))
    longitude = Column(DECIMAL(11, 8))

    scan_result = relationship("ScanResult", back_populates="geo_location")

class StatisticsCache(Base):
    __tablename__ = 'statistics_cache'

    id = Column(Integer, primary_key=True)
    scan_date = Column(DateTime, unique=True, nullable=False)
    statistics_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=func.now())
