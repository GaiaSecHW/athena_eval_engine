"""独立健康检查端口（8091）— 不经过 uvicorn 事件循环，不受 GIL 竞争影响。

k8s liveness/readiness probe 改查此端口，避免评测线程密集时事件循环被阻塞
导致 probe 超时 → pod 被 kill → 503。

用标准库 http.server 在独立线程中运行，零依赖、零锁、零 I/O。
"""
from __future__ import annotations
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # 静默，不污染日志


_server: HTTPServer | None = None
_thread: threading.Thread | None = None


def start(port: int = 8091):
    """启动独立健康检查服务（守护线程，进程退出时自动结束）。"""
    global _server, _thread
    if _server is not None:
        return
    _server = HTTPServer(("0.0.0.0", port), _HealthHandler)
    _thread = threading.Thread(target=_server.serve_forever, name="health-probe", daemon=True)
    _thread.start()


def stop():
    """停止健康检查服务。"""
    global _server, _thread
    if _server is not None:
        _server.shutdown()
        _server = None
    _thread = None
