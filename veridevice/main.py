from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise
from veridevice.core.config import settings
from veridevice.api import devices, evaluations, admin, webhooks

app = FastAPI(
    title="Veridevice Core",
    version="2.1.0",
)

app.include_router(devices.router, prefix="/api/v1")
app.include_router(devices.admin_router, prefix="/api/v1")
app.include_router(evaluations.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(webhooks.router, prefix="/api/v1")

register_tortoise(
    app,
    db_url=settings.db_url,
    modules={"models": settings.models},
    generate_schemas=True,
    add_exception_handlers=True,
)


@app.get("/")
async def root():
    return {"message": "Veridevice Core is running"}
