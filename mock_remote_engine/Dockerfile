FROM python:3.12-slim

RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null \
    || sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null \
    || true

WORKDIR /app
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple \
    --trusted-host pypi.tuna.tsinghua.edu.cn \
    "fastapi>=0.110" "uvicorn[standard]>=0.27" "pydantic>=2"

COPY mock_remote_engine/ ./mock_remote_engine/

ENV TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "mock_remote_engine.app:app", "--host", "0.0.0.0", "--port", "8080"]
