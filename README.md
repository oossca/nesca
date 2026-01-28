# Nesca - Python 命令行版本

传奇的网络扫描器（NEtwork SCAnner）的 Python 重写版本，提供强大的命令行界面。

## 项目描述

Nesca 是一个功能强大的网络扫描和漏洞评估工具，结合了端口扫描、服务枚举和凭据暴力破解功能。这个 Python 版本保持了原 C++ 项目的核心功能，同时提供了现代化的跨平台命令行界面。

## 主要特性

- **端口扫描**: 对单个目标或 IP 范围进行快速多线程端口扫描
- **服务发现**: 自动检测常见端口的服务类型
- **凭据暴力破解**: 多协议认证测试（FTP、SSH、HTTP 等）
- **主机发现**: 基于 ping 的网络范围主机发现
- **灵活输出**: 支持 JSON、CSV 和 HTML 报告生成
- **会话管理**: 保存和恢复扫描会话
- **多协议支持**: FTP、SSH、HTTP Basic、WebForm 认证

## 安装

### 从源码安装

```bash
git clone https://github.com/your-repo/nesca-python.git
cd nesca-python
pip install -r requirements.txt
pip install -e .
```

### 使用 pip 安装（发布后）

```bash
pip install nesca
```

## 系统要求

- Python 3.7+
- 完整依赖列表请查看 `requirements.txt`

## 使用方法

### 基础端口扫描

```bash
# 扫描单个目标的常用端口
nesca -t 192.168.1.1 -m scan

# 扫描指定端口
nesca -t 192.168.1.1 -p 21,22,80,443 -m scan

# 扫描 IP 范围
nesca -t 192.168.1.0/24 -p 1-1000 -m scan

# 扫描多个目标
nesca -t "192.168.1.1,192.168.1.2,192.168.1.3" -m scan

# 从文件读取目标列表
nesca -t @targets.txt -p 21,22,80,443 -m scan
nesca -t -targets.txt -p 21,22,80,443 -m scan  # 也可以用 - 前缀
```

### 凭据暴力破解

```bash
# 破解 FTP 服务
nesca -t 192.168.1.1:21 -m brute -s FTP

# 使用常用凭据快速破解
nesca -t 192.168.1.1:22 -m brute -s SSH --quick

# 使用自定义字典
nesca -t 192.168.1.1:21 -m brute -s FTP -u usernames.txt -w passwords.txt

# 直接指定凭据
nesca -t 192.168.1.1:21 -m brute -s FTP -u "admin,root,user" -w "password,123456"
```

### 组合扫描

```bash
# 扫描并对发现的服务进行暴力破解
nesca -t 192.168.1.0/24 -m scan-and-brute

# 快速扫描和破解（使用常用凭据）
nesca -t 192.168.1.1 -m scan-and-brute --quick
```

### 主机发现

```bash
# 发现网络范围内的活跃主机
nesca -t 192.168.1.0/24 -m discover
```

### 高级选项

```bash
# 自定义线程数和超时时间
nesca -t 192.168.1.1 -p 1-65535 -m scan --threads 100 --timeout 3.0

# 保存结果到文件
nesca -t 192.168.1.1 -m scan -o results.json --format json

# 详细输出
nesca -t 192.168.1.1 -m scan -v

# 静默模式（仅错误）
nesca -t 192.168.1.1 -m scan -q
```

## 命令行选项

### 目标选项
- `-t, --targets`: 目标 IP、范围、CIDR 或文件路径（支持逗号分隔，文件路径用 @ 或 - 前缀）
- `-p, --ports`: 要扫描的端口（单个、逗号分隔或范围）

### 操作模式
- `-m, --mode`: 操作模式（`scan`、`brute`、`scan-and-brute`、`discover`）
- `-s, --service`: 暴力破解的服务类型（FTP、SSH、HTTP 等）

### 暴力破解选项
- `-u, --usernames`: 用户名文件或逗号分隔列表
- `-w, --passwords`: 密码文件或逗号分隔列表
- `--quick`: 使用快速凭据集
- `--threads`: 线程数（默认：20）
- `--timeout`: 连接超时时间（默认：5.0秒）
- `--delay`: 请求间延迟（默认：0.1秒）

### 输出选项
- `-o, --output`: 输出文件名
- `--format`: 输出格式（`json`、`txt`、`csv`、`html`）
- `-v, --verbose`: 详细输出
- `-q, --quiet`: 静默模式（仅错误）

## 支持的服务

- **FTP**: 文件传输协议
- **SSH**: 安全外壳协议
- **HTTP**: HTTP 基础认证
- **HTTPS**: HTTPS 基础认证
- **WebForm**: Web 表单认证
- **Telnet**: （计划中）

## 目标文件格式

可以从文件中批量导入目标地址。目标文件支持以下格式：

```
# 示例目标文件
# 以 # 开头的行为注释，会被忽略
# 空行也会被忽略

# 单个IP地址
192.168.1.1
192.168.1.10

# CIDR格式的IP范围
192.168.2.0/24
10.0.0.1

# 特殊地址
127.0.0.1
```

使用方法：
- `nesca -t @targets.txt` （推荐，使用 @ 前缀）
- `nesca -t -targets.txt` （备选，使用 - 前缀）

## 配置文件管理

Nesca 支持使用配置文件来自定义默认设置和参数。

### 配置文件位置

1. **当前目录**: `nesca.conf` （项目目录）
2. **用户目录**: `~/.nesca.conf` （用户主目录）

### 配置特性

- **智能默认值**: 未提供参数时自动从配置文件读取
- **参数覆盖**: 提供参数时覆盖配置文件中的对应设置
- **配置查看**: 使用 `--show-config` 查看当前配置

### 查看配置

```bash
# 显示当前配置
nesca --show-config
```

### 默认配置示例

```json
{
  "default_threads": 20,          // 默认线程数
  "default_timeout": 5.0,          // 默认超时时间（秒）
  "default_delay": 0.1,            // 默认请求延迟（秒）
  "default_format": "json",          // 默认输出格式
  "common_ports": [21, 22, 23, ...], // 常用端口列表
  "quick_usernames": ["admin", "admini strator", "root", ...], // 快速爆破用户名
  "quick_passwords": ["admin", "password", "123456", ...]  // 快速爆破密码
}
```

### 使用示例

```bash
# 不带参数，使用配置文件中的默认值
nesca -t 192.168.1.1 -m scan

# 带参数，覆盖配置文件中的对应设置
nesca -t 192.168.1.1 -m scan --threads 50 --timeout 2.0

# 混合使用：部分参数来自配置文件，部分来自命令行
nesca -t 192.168.1.1 -p 80,443 --threads 30  # 端口来自默认配置，线程数来自命令行

# 使用自定义配置文件
nesca --config example_config.conf -t 192.168.1.1 -m scan
```

### 自定义配置文件

项目包含一个示例配置文件 `example_config.conf`，可以复制并修改为您的需求：

```bash
# 复制示例配置文件
cp example_config.conf nesca.conf

# 编辑配置文件
notepad nesca.conf  # Windows
nano nesca.conf     # Linux
```

## 字典管理

Nesca 包含了默认的用户名和密码字典。可以使用 `-u` 和 `-w` 选项使用自定义字典。

### 默认字典位置

- 密码字典: `nesca/data/pass.txt`
- 用户名字典: `nesca/data/ftplogin.txt`

### 创建默认字典

```bash
nesca --create-wordlists
```

### 列出支持的服务

```bash
nesca --list-services
```

## 输出格式

### JSON
```json
{
  "scan_info": {
    "timestamp": "2023-12-07T10:30:00",
    "scanner": "Nesca Python CLI",
    "version": "1.0.0"
  },
  "results": {
    "scan_results": {...},
    "brute_force_results": {...}
  }
}
```

### CSV
列：目标、端口、服务、用户名、密码、响应时间、状态

### HTML
包含统计信息和详细结果的交互式网页报告。

## 使用示例

### 企业网络评估
```bash
# 发现企业网络中的所有主机
nesca -t 10.0.0.0/24 -m discover -o hosts_found.json

# 扫描发现主机上的开放服务
nesca -t 10.0.0.1-10.0.0.254 -p 21,22,80,443,3389 -m scan -o services.json

# 破解发现的服务
nesca -t 10.0.0.1-10.0.0.254 -m scan-and-brute --quick -o credentials.json
```

### 快速安全检查
```bash
# 单个目标的快速评估
nesca -t 192.168.1.100 -m scan-and-brute -o quick_assessment.html --format html
```

## 安全注意事项

- 仅扫描您拥有或明确获得测试许可的网络和系统
- 注意有关网络扫描的当地法律法规
- 使用适当的延迟和线程数以避免目标系统过载
- 此工具仅用于教育和授权的安全测试目的

## 贡献

1. Fork 仓库
2. 创建功能分支
3. 进行更改
4. 如果适用，添加测试
5. 提交 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详情请参见 LICENSE 文件。

## 致谢

基于 ISKOPASI 小组的原版 Nesca 项目（pantyusha/nesca）。

## 更新日志

### v1.0.0
- 初始 Python 版本发布
- 核心端口扫描功能
- 多协议暴力破解
- 多种输出格式
- 会话管理
- 命令行界面

## 支持

如有问题、疑问或贡献，请在 GitHub 仓库中开启 issue。