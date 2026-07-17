from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from backend.database import get_db
from backend.models import Alert, ThreatIntelFeed, User
from backend.auth.rbac import get_current_user
from backend.enrichment import enrich_ip, enrich_hash, enrich_domain

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.post("/enrich/ip/{ip}")
async def enrich_ip_endpoint(ip: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await enrich_ip(ip)
    
    # Save to feed
    if result.get("is_malicious"):
        feed = ThreatIntelFeed(
            ioc_value=ip,
            ioc_type="ip",
            threat_type="malicious_ip",
            confidence=int(result.get("risk_score", 50)),
            source="abuseipdb",
            raw_data=result
        )
        db.add(feed)
        await db.flush()
    
    return result


@router.post("/enrich/hash/{hash_value}")
async def enrich_hash_endpoint(hash_value: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await enrich_hash(hash_value)


@router.post("/enrich/domain/{domain}")
async def enrich_domain_endpoint(domain: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await enrich_domain(domain)


@router.get("/feeds")
async def list_feeds(
    ioc_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(ThreatIntelFeed).where(ThreatIntelFeed.is_active == True)
    if ioc_type:
        query = query.where(ThreatIntelFeed.ioc_type == ioc_type)
    query = query.order_by(ThreatIntelFeed.last_seen.desc()).limit(limit)
    
    result = await db.execute(query)
    feeds = result.scalars().all()
    return [
        {
            "id": f.id,
            "ioc_value": f.ioc_value,
            "ioc_type": f.ioc_type,
            "threat_type": f.threat_type,
            "confidence": f.confidence,
            "source": f.source,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen
        }
        for f in feeds
    ]


@router.get("/feeds/stats")
async def feed_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    by_type = (await db.execute(
        select(ThreatIntelFeed.ioc_type, func.count(ThreatIntelFeed.id))
        .where(ThreatIntelFeed.is_active == True)
        .group_by(ThreatIntelFeed.ioc_type)
    )).all()
    
    total = (await db.execute(select(func.count(ThreatIntelFeed.id)))).scalar()
    
    return {
        "total_iocs": total,
        "by_type": {r[0]: r[1] for r in by_type}
    }
