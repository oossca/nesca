FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY requirements.txt .
COPY setup.py .
COPY nesca/ ./nesca/

# 安装Python包
RUN pip install --no-cache-dir -e .

# 创建数据目录
RUN mkdir -p /app/results /app/logs

# 设置入口点
ENTRYPOINT ["python", "-m", "nesca.main"]
CMD ["@targets.txt","-m","scan-and-brute"]