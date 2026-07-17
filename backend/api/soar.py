from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from backend.database import get_db
from backend.models import Alert, Playbook, PlaybookExecution, User
from backend.schemas import PlaybookOut, PlaybookRunRequest
from backend.auth.rbac import get_current_user
from backend.soar.playbooks import execute_playbook

router = APIRouter(prefix="/soar", tags=["SOAR"])


@router.get("/playbooks", response_model=list)
async def list_playbooks(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Playbook).order_by(Playbook.created_at.desc()))
    playbooks = result.scalars().all()
    return [PlaybookOut.model_validate(p).model_dump() for p in playbooks]


@router.post("/playbooks/{playbook_id}/run")
async def run_playbook(
    playbook_id: str,
    data: PlaybookRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from fastapi import HTTPException
    
    pb_result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = pb_result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    alert = None
    if data.alert_id:
        alert_result = await db.execute(select(Alert).where(Alert.id == data.alert_id))
        alert = alert_result.scalar_one_or_none()
    
    execution = await execute_playbook(
        playbook=playbook,
        db=db,
        alert=alert,
        executed_by=str(current_user.id)
    )
    
    return {
        "execution_id": execution.id,
        "status": execution.status.value,
        "results": execution.results
    }


@router.get("/executions")
async def list_executions(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(PlaybookExecution).order_by(PlaybookExecution.started_at.desc()).limit(limit)
    )
    execs = result.scalars().all()
    return [
        {
            "id": e.id,
            "playbook_id": e.playbook_id,
            "alert_id": e.alert_id,
            "status": e.status.value,
            "results": e.results,
            "started_at": e.started_at,
            "completed_at": e.completed_at
        }
        for e in execs
    ]
