"""v2 API 模块 — 将 v2 路由挂载到现有 FastAPI app 上。"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .datasources import router as datasources_router
from .routes import router as evaluations_router
from .dts import router as dts_router
from .dashboard import router as dashboard_router
from .report import router as report_router
from .notify import router as notify_router

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "static")


def create_v2_app(app: FastAPI):
    """将 v2 路由挂载到现有 FastAPI app 上。"""
    app.include_router(datasources_router)
    app.include_router(evaluations_router)
    app.include_router(dts_router)
    app.include_router(dashboard_router)
    app.include_router(report_router)
    app.include_router(notify_router)

    # 静态库（config.js/app.js/app.css）无缓存指纹——no-cache 强制浏览器
    # 每次按 ETag/Last-Modified 重新校验，避免发布后仍用旧标签/旧逻辑
    # （曾致新增状态在筛选/表格中「不全」的假象）
    @app.middleware("http")
    async def _no_cache_static_lib(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static/lib"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    # 挂载 static/lib 目录（jQuery/jstree 等本地 JS 库）
    lib_dir = os.path.join(_STATIC_DIR, "lib")
    if os.path.isdir(lib_dir):
        app.mount("/static/lib", StaticFiles(directory=lib_dir), name="static-lib")
