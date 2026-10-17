"""v2 API 模块 — 将 v2 路由挂载到现有 FastAPI app 上。"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .datasources import router as datasources_router
from .routes import router as evaluations_router
from .dts import router as dts_router

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "static")


def create_v2_app(app: FastAPI):
    """将 v2 路由挂载到现有 FastAPI app 上。"""
    app.include_router(datasources_router)
    app.include_router(evaluations_router)
    app.include_router(dts_router)

    # 挂载 static/lib 目录（jQuery/jstree 等本地 JS 库）
    lib_dir = os.path.join(_STATIC_DIR, "lib")
    if os.path.isdir(lib_dir):
        app.mount("/static/lib", StaticFiles(directory=lib_dir), name="static-lib")
