"""
Async Database Operations for SIATI
Asynchronous database operations for improved performance
"""
import asyncio
from typing import List, Optional, Dict, Any, Type, TypeVar, Generic
from datetime import datetime
from contextlib import asynccontextmanager
import logging

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
    AsyncEngine
)
from sqlalchemy.orm import selectinload, joinedload
from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.exc import SQLAlchemyError

from app.db.models import (
    Host, Service, Vulnerability, ScoreML, Report, Exploit
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


class AsyncDatabaseManager:
    """Asynchronous database manager for SIATI"""

    def __init__(self, database_url: str = "sqlite+aiosqlite:///./data/pentest.db"):
        """
        Initialize async database manager

        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url
        self.engine: Optional[AsyncEngine] = None
        self.async_session_maker: Optional[async_sessionmaker] = None
        self._initialized = False

    async def initialize(self):
        """Initialize database connection"""
        if self._initialized:
            return

        try:
            # Create async engine
            self.engine = create_async_engine(
                self.database_url,
                echo=False,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20
            )

            # Create async session maker
            self.async_session_maker = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )

            self._initialized = True
            logger.info("Async database manager initialized")

        except Exception as e:
            logger.error(f"Failed to initialize async database: {e}")
            raise

    async def close(self):
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()
            self._initialized = False
            logger.info("Async database connections closed")

    @asynccontextmanager
    async def get_session(self):
        """
        Get async database session context manager

        Yields:
            Async database session
        """
        if not self._initialized:
            await self.initialize()

        async with self.async_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {e}")
                raise
            finally:
                await session.close()


# ============================================================================
# ASYNC REPOSITORIES
# ============================================================================

class BaseAsyncRepository(Generic[T]):
    """Base async repository with common operations"""

    def __init__(self, model: Type[T], db_manager: AsyncDatabaseManager):
        """
        Initialize base repository

        Args:
            model: SQLAlchemy model class
            db_manager: Async database manager
        """
        self.model = model
        self.db_manager = db_manager

    async def get_by_id(self, id: int) -> Optional[T]:
        """
        Get entity by ID

        Args:
            id: Entity ID

        Returns:
            Entity or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(self.model).where(self.model.id == id)
            )
            return result.scalar_one_or_none()

    async def get_all(
        self,
        limit: int = 100,
        offset: int = 0,
        order_by: Optional[str] = None
    ) -> List[T]:
        """
        Get all entities with pagination

        Args:
            limit: Maximum number of results
            offset: Number of results to skip
            order_by: Field to order by

        Returns:
            List of entities
        """
        async with self.db_manager.get_session() as session:
            query = select(self.model)

            if order_by:
                query = query.order_by(getattr(self.model, order_by))

            query = query.limit(limit).offset(offset)

            result = await session.execute(query)
            return result.scalars().all()

    async def create(self, **kwargs) -> T:
        """
        Create new entity

        Args:
            **kwargs: Entity attributes

        Returns:
            Created entity
        """
        async with self.db_manager.get_session() as session:
            entity = self.model(**kwargs)
            session.add(entity)
            await session.flush()
            await session.refresh(entity)
            return entity

    async def update(self, id: int, **kwargs) -> Optional[T]:
        """
        Update entity by ID

        Args:
            id: Entity ID
            **kwargs: Attributes to update

        Returns:
            Updated entity or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                update(self.model)
                .where(self.model.id == id)
                .values(**kwargs)
                .returning(self.model)
            )
            updated_entity = result.scalar_one_or_none()

            if updated_entity:
                await session.refresh(updated_entity)

            return updated_entity

    async def delete(self, id: int) -> bool:
        """
        Delete entity by ID

        Args:
            id: Entity ID

        Returns:
            True if deleted, False otherwise
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                delete(self.model).where(self.model.id == id)
            )
            return result.rowcount > 0

    async def count(self) -> int:
        """
        Count all entities

        Returns:
            Number of entities
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(func.count()).select_from(self.model)
            )
            return result.scalar()


class HostAsyncRepository(BaseAsyncRepository[Host]):
    """Async repository for Host operations"""

    async def get_by_ip(self, ip: str) -> Optional[Host]:
        """
        Get host by IP address

        Args:
            ip: IP address

        Returns:
            Host or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Host)
                .options(selectinload(Host.services))
                .where(Host.ip == ip)
            )
            return result.scalar_one_or_none()

    async def get_with_services(self, id: int) -> Optional[Host]:
        """
        Get host with services loaded

        Args:
            id: Host ID

        Returns:
            Host with services or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Host)
                .options(
                    selectinload(Host.services)
                    .selectinload(Service.vulnerabilities)
                )
                .where(Host.id == id)
            )
            return result.scalar_one_or_none()

    async def search(self, query: str, limit: int = 50) -> List[Host]:
        """
        Search hosts by IP or hostname

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of matching hosts
        """
        async with self.db_manager.get_session() as session:
            search_pattern = f"%{query}%"
            result = await session.execute(
                select(Host)
                .where(
                    or_(
                        Host.ip.ilike(search_pattern),
                        Host.hostname.ilike(search_pattern)
                    )
                )
                .limit(limit)
            )
            return result.scalars().all()


class VulnerabilityAsyncRepository(BaseAsyncRepository[Vulnerability]):
    """Async repository for Vulnerability operations"""

    async def get_by_cve(self, cve: str) -> Optional[Vulnerability]:
        """
        Get vulnerability by CVE ID

        Args:
            cve: CVE identifier

        Returns:
            Vulnerability or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Vulnerability)
                .options(
                    joinedload(Vulnerability.service)
                    .joinedload(Service.host)
                )
                .where(Vulnerability.cve == cve)
            )
            return result.scalar_one_or_none()

    async def get_with_scores(self, id: int) -> Optional[Vulnerability]:
        """
        Get vulnerability with ML scores

        Args:
            id: Vulnerability ID

        Returns:
            Vulnerability with scores or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Vulnerability)
                .options(
                    joinedload(Vulnerability.service)
                    .selectinload(Vulnerability.scores)
                )
                .where(Vulnerability.id == id)
            )
            return result.scalar_one_or_none()

    async def filter_by_severity(
        self,
        severity: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Vulnerability]:
        """
        Filter vulnerabilities by severity level

        Args:
            severity: Severity level
            limit: Maximum results
            offset: Number of results to skip

        Returns:
            List of vulnerabilities
        """
        async with self.db_manager.get_session() as session:
            # Join with ScoreML to filter by label
            result = await session.execute(
                select(Vulnerability)
                .join(ScoreML, Vulnerability.id == ScoreML.vuln_id)
                .where(ScoreML.label == severity)
                .limit(limit)
                .offset(offset)
            )
            return result.scalars().all()

    async def get_high_risk_vulnerabilities(
        self,
        min_score: float = 7.0,
        limit: int = 50
    ) -> List[Vulnerability]:
        """
        Get high-risk vulnerabilities

        Args:
            min_score: Minimum ML score
            limit: Maximum results

        Returns:
            List of high-risk vulnerabilities
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Vulnerability)
                .join(ScoreML, Vulnerability.id == ScoreML.vuln_id)
                .where(ScoreML.score >= min_score)
                .order_by(ScoreML.score.desc())
                .limit(limit)
            )
            return result.scalars().all()

    async def search(self, query: str, limit: int = 50) -> List[Vulnerability]:
        """
        Search vulnerabilities by CVE or description

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of matching vulnerabilities
        """
        async with self.db_manager.get_session() as session:
            search_pattern = f"%{query}%"
            result = await session.execute(
                select(Vulnerability)
                .where(
                    or_(
                        Vulnerability.cve.ilike(search_pattern),
                        Vulnerability.description.ilike(search_pattern)
                    )
                )
                .limit(limit)
            )
            return result.scalars().all()


class ReportAsyncRepository(BaseAsyncRepository[Report]):
    """Async repository for Report operations"""

    async def get_by_vulnerability(self, vuln_id: int) -> List[Report]:
        """
        Get reports for a vulnerability

        Args:
            vuln_id: Vulnerability ID

        Returns:
            List of reports
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Report)
                .where(Report.vuln_id == vuln_id)
                .order_by(Report.timestamp.desc())
            )
            return result.scalars().all()

    async def get_latest_by_vulnerability(self, vuln_id: int) -> Optional[Report]:
        """
        Get latest report for a vulnerability

        Args:
            vuln_id: Vulnerability ID

        Returns:
            Latest report or None
        """
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                select(Report)
                .where(Report.vuln_id == vuln_id)
                .order_by(Report.timestamp.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()


# ============================================================================
# ASYNC SERVICE LAYER
# ============================================================================

class AsyncVulnerabilityService:
    """Async service for vulnerability operations"""

    def __init__(self, db_manager: AsyncDatabaseManager):
        """
        Initialize vulnerability service

        Args:
            db_manager: Async database manager
        """
        self.db_manager = db_manager
        self.vuln_repo = VulnerabilityAsyncRepository(Vulnerability, db_manager)
        self.host_repo = HostAsyncRepository(Host, db_manager)

    async def get_vulnerability_details(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        """
        Get complete vulnerability details with related data

        Args:
            vuln_id: Vulnerability ID

        Returns:
            Complete vulnerability details or None
        """
        vuln = await self.vuln_repo.get_with_scores(vuln_id)
        if not vuln:
            return None

        # Get related data
        service = vuln.service
        host = await self.host_repo.get_by_id(service.host_id) if service else None

        # Get latest report
        report_repo = ReportAsyncRepository(Report, self.db_manager)
        latest_report = await report_repo.get_latest_by_vulnerability(vuln_id)

        return {
            "id": vuln.id,
            "cve": vuln.cve,
            "cvss_score": vuln.cvss_score,
            "cvss_vector": vuln.cvss_vector,
            "cwe": vuln.cwe,
            "description": vuln.description,
            "source": vuln.source,
            "service": {
                "id": service.id if service else None,
                "port": service.port if service else None,
                "protocol": service.protocol if service else None,
                "service": service.service if service else None,
                "version": service.version if service else None
            } if service else None,
            "host": {
                "id": host.id if host else None,
                "ip": host.ip if host else None,
                "hostname": host.hostname if host else None,
                "os": host.os if host else None
            } if host else None,
            "ml_score": vuln.scores[0].score if vuln.scores else None,
            "ml_label": vuln.scores[0].label if vuln.scores else None,
            "ml_confidence": vuln.scores[0].confidence if vuln.scores else None,
            "latest_report": {
                "id": latest_report.id,
                "title": latest_report.title,
                "stage": latest_report.stage,
                "timestamp": latest_report.timestamp.isoformat()
            } if latest_report else None,
            "timestamp": vuln.timestamp.isoformat() if vuln.timestamp else None
        }

    async def get_vulnerability_statistics(self) -> Dict[str, Any]:
        """
        Get vulnerability statistics

        Returns:
            Statistics dictionary
        """
        async with self.db_manager.get_session() as session:
            # Total vulnerabilities
            total_vulns = await session.execute(
                select(func.count()).select_from(Vulnerability)
            )
            total_count = total_vulns.scalar()

            # Severity distribution
            severity_dist = await session.execute(
                select(ScoreML.label, func.count(ScoreML.id))
                .group_by(ScoreML.label)
            )
            severity_results = severity_dist.all()

            severity_distribution = {
                row[0]: row[1] for row in severity_results
            }

            # Average CVSS
            avg_cvss = await session.execute(
                select(func.avg(Vulnerability.cvss_score))
                .where(Vulnerability.cvss_score.isnot(None))
            )
            avg_cvss_value = avg_cvss.scalar() or 0.0

            # High-risk count
            high_risk = await session.execute(
                select(func.count())
                .select_from(
                    select(Vulnerability.id)
                    .join(ScoreML, Vulnerability.id == ScoreML.vuln_id)
                    .where(ScoreML.score >= 7.0)
                    .subquery()
                )
            )
            high_risk_count = high_risk.scalar()

            return {
                "total_vulns": total_count,
                "severity_distribution": severity_distribution,
                "avg_cvss": round(avg_cvss_value, 2),
                "high_risk_count": high_risk_count
            }

    async def batch_get_vulnerabilities(
        self,
        vuln_ids: List[int]
    ) -> List[Dict[str, Any]]:
        """
        Get multiple vulnerabilities in batch

        Args:
            vuln_ids: List of vulnerability IDs

        Returns:
            List of vulnerability details
        """
        tasks = [
            self.get_vulnerability_details(vuln_id)
            for vuln_id in vuln_ids
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and None results
        valid_results = [
            result for result in results
            if not isinstance(result, Exception) and result is not None
        ]

        return valid_results


# ============================================================================
# GLOBAL ASYNC DATABASE MANAGER
# ============================================================================

# Global async database manager instance
async_db_manager = AsyncDatabaseManager()

# Initialize repositories
async def init_async_repositories():
    """Initialize async repositories"""
    await async_db_manager.initialize()

    return {
        "hosts": HostAsyncRepository(Host, async_db_manager),
        "vulnerabilities": VulnerabilityAsyncRepository(Vulnerability, async_db_manager),
        "reports": ReportAsyncRepository(Report, async_db_manager)
    }


# Convenience function for getting async session
async def get_async_session():
    """Get async database session"""
    if not async_db_manager._initialized:
        await async_db_manager.initialize()

    return async_db_manager.get_session()