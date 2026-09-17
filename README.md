# CampusNetKeeper

一个用于当前校园 GiWiFi 门户的 Python 自动联网服务。服务会定期检查真实外网连通性；如果请求被校园网门户拦截或外网不可达，就读取门户下发的设备参数，按页面使用的 AES-CBC/ZeroPadding 协议调用登录接口。

已按实际页面 `http://10.4.0.5/gportal/web/login` 适配：

- 登录接口：`/gportal/Web/loginAction`
- 表单参数由门户动态提供，包含 `iv`、NAS、终端 IP 等字段
- AES key：页面公开使用的 `1234567887654321`
- 默认使用百度检查外网；登录成功时先访问门户返回的完成地址，再次检查外网
- 可通过 `NETWORK_INTERFACE=eno1` 强制探测和登录只走指定网口
- Cookie 持久化在 Docker volume 中，账号密码只从环境变量读取

## 使用 Docker Compose

先建立本地配置：

```bash
cp .env.example .env
```

编辑 `.env`，至少填写：

```dotenv
GWIFI_ACCOUNT=你的上网账号
GWIFI_PASSWORD=你的上网密码
NETWORK_INTERFACE=eno1
```

启动：

```bash
docker compose up -d --build
docker compose logs -f
```

停止：

```bash
docker compose down
```

Compose 使用主机网络，因为这类门户通常按终端 IP/MAC 识别设备，并且 `10.4.0.5` 必须能从容器访问。在 Linux 上最可靠；Docker Desktop 若无法从容器访问该地址，可以直接在主机运行 Python 版本。

## 检查频率

容器启动时会立即检查一次，联网后每 24 小时检查一次；普通断网错误每 60 秒重试。要更频繁地检查，例如每 5 分钟一次：

```dotenv
CHECK_INTERVAL=300
```

缩短这个周期可以在校园网中途掉线时更快发现并恢复。

门户返回 `122`、要求短信验证或要求修改密码等不可自动恢复的错误时，默认等待 6 小时再检查，避免不断提交认证。可以通过 `TERMINAL_RETRY_INTERVAL` 调整。

飞牛 OS 同时连接有线和无线网络时，建议设置：

```dotenv
NETWORK_INTERFACE=eno1
```

容器必须使用 `host` 网络模式才能看到宿主机网卡。启动日志会显示绑定的网卡名和 IPv4 地址。

## 直接运行 Python

需要 Python 3.11 或更高版本：

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m campusnet_keeper
```

只检查和尝试登录一次：

```bash
python -m campusnet_keeper --once
```

## 关于“首次认证”

当前实现会在此电脑/容器没有有效校园网会话时自动提交已有账号完成上网认证。账号注册、短信验证码、实名认证或门户要求修改密码时，服务会在日志里给出对应错误，不会尝试绕过这些交互步骤。

门户返回代码 `122` 表示网关不支持绑定当前终端。如果日志同时显示 `sta_port`、`sta_vlan`、`nas_ip` 缺失，需要校园网运营方为该有线终端开放认证，客户端程序无法绕过服务器策略。

门户返回代码 `124` 时表示需要确认绑定当前设备，并可能重新分配已有会话。默认不会自动确认；允许自动确认后，可设置：

```dotenv
ALLOW_SESSION_REPLACE=true
```

## GitHub Actions

`.github/workflows/docker.yml` 会先运行测试，再构建 Docker 镜像。推送到默认分支或 `release-v*` 标签时，镜像发布到：

```text
ghcr.io/<GitHub 用户或组织>/campusnet-keeper
```

Pull Request 只构建和测试，不推送镜像。

## 安全说明

- 不要提交 `.env`；它已加入 `.gitignore`。
- 门户本身使用 HTTP，账号密码在发送前遵循页面逻辑做 AES 加密，但这不等同于 HTTPS。只能在可信的校园网络内运行。
- 日志不会打印账号、密码或加密后的登录载荷。
