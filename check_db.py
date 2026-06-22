import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from app.models.case import Evidence
from app.config import settings

async def check_evidence():
    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        result = await session.execute(select(Evidence).where(Evidence.id == '759bd798-35d1-400d-8121-bf01a8d2b3f3'))
        evidence = result.scalar_one_or_none()
        
        if evidence:
            print(f"Evidence Found:")
            print(f"  ID: {evidence.id}")
            print(f"  Case ID: {evidence.case_id}")
            print(f"  Status: {evidence.analysis_status}")
            print(f"  File Path: {evidence.file_path}")
            print(f"  Original Filename: {evidence.original_filename}")
        else:
            print("Evidence NOT found in database.")

if __name__ == "__main__":
    asyncio.run(check_evidence())
