"""独立健康检查端口（8091）— 不经过 uvicorn 事件循环，不受 GIL 竞争影响。

k8s liveness/readiness probe 改查此端口，避免评测线程密集时事件循环被阻塞
导致 probe 超时 → pod 被 kill → 503。

用标准库 socketserver 在独立线程中运行，零依赖、零锁、零 I/O。
TCP 握手由内核处理，但 accept() 仍需 GIL，所以：
- request_queue_size=128 增大内核 accept 队列
- handler 只返回固定字节，GIL 持有时间极短
"""
from __future__ import annotations
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *args):
        pass


class _HealthServer(HTTPServer):
    # 内核 accept 队列大小，默认 5 太小，probe 连续请求时队列满 → SYN 丢弃 → i/o timeout
    request_queue_size = 128
    # 不复用地址（重启时端口释放快）
    allow_reuse_address = True


_server: _HealthServer | None = None
_thread: threading.Thread | None = None


def start(port: int = 8091):
    """启动独立健康检查服务（守护线程，进程退出时自动结束）。"""
    global _server, _thread
    if _server is not None:
        return
    _server = _HealthServer(("0.0.0.0", port), _HealthHandler)
    _thread = threading.Thread(target=_server.serve_forever, name="health-probe", daemon=True)
    _thread.start()


def stop():
    """停止健康检查服务。"""
    global _server, _thread
    if _server is not None:
        _server.shutdown()
        _server.server_close()
        _server = None
    _thread = None
