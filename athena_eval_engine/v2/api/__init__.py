"""v2 API 模块 — 将 v2 路由挂载到现有 FastAPI app 上。"""
from __future__ import annotations

from fastapi import FastAPI

from .datasources import router as datasources_router
from .routes import router as evaluations_router


def create_v2_app(app: FastAPI):
    """将 v2 路由挂载到现有 FastAPI app 上。"""
    app.include_router(datasources_router)
    app.include_router(evaluations_router)
