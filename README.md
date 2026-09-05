# VPN 例外路由（mac / Windows 小应用）

场景：你在公司/学校 VPN 的同时，仍希望某些站点走**本机网络**，不走当前连接的 VPN。

现在这个项目提供两种用法：

- `vpn_route_bypass.py`：命令行版（核心引擎）
- `vpn_route_bypass_app.py`：状态栏/托盘常驻应用（mac 状态栏点开下拉设置）

> 仅处理 IPv4。

## 它解决什么问题（重要）

很多现代 VPN / 代理客户端（Clash、Mihomo、Surge、SakuraCat 等）会以 **TUN + fake-ip 模式**全流量接管网络：

1. 它们劫持系统 DNS，把域名解析成 `198.18.x.x` 这类**虚拟 IP**（fake-ip）；
2. 传统"解析出真实 IP → 加 host 路由"的方案会拿到假 IP，加路由完全无效；
3. 于是白名单网站依然走代理隧道，访问校内/内网资源失败。

本工具对这种情况做了自动适配：

- 系统解析结果落在 fake-ip/保留网段（默认 `198.18.0.0/15`、`100.64.0.0/10`）时，自动改用 **DoH（HTTPS DNS）** 获取真实 IP；
- 把「域名 → 真实 IP」写入 `/etc/hosts`（**标记段管理**，只动自己管理的区块，不影响你原有 hosts）；
- 再为真实 IP 添加指向本地网关的 host 路由，流量从物理网卡直连，不进代理 TUN；
- 守护模式下周期刷新，代理重启/切换节点导致路由被清时自动重加。

### 校园网/内网站：用 `host_ip_overrides` 指定内网地址

校内/内网站点往往**同时有公网入口和内网入口**，且只有内网入口在你的校园网里才是真正可达的：

- DoH / 公共 DNS 只能解析出**公网 IP**（例如 `203.0.113.88`），但它在你所在的网络里 443 直连常常超时；
- 真正能直连的是**内网 IP**（例如 `10.10.0.21`），但公共 DNS 里不存在这条记录，自动解析拿不到。

解决办法：在 `host_ip_overrides` 里为这类站点手动指定内网 IP，本工具会优先使用该地址写 hosts、加路由，完全绕过代理直接走本地网络。

```json
{
  "prefixes": ["https://intra.school.example"],
  "host_ip_overrides": {
    "https://intra.school.example": "10.10.0.21"
  }
}
```

如何确认内网 IP：在校园网内（不开代理）先解析一次该域名，若得到 `10.x` / `172.16-31.x` / `192.168.x` 即为内网入口；或询问校方/IT。手动加一条 host 路由后能 curl 通即可确定：
```bash
sudo route add -host 10.10.0.21 <本地网关>
curl --resolve intra.school.example:443:10.10.0.21 https://intra.school.example
```

> 对传统 VPN（OpenVPN/WireGuard/AnyConnect 等，DNS 不被劫持）同样兼容，会自动走"纯 host 路由"路径。
> 若代理是"系统代理"模式（非 TUN），系统路由/hosts 方案不适用，需要在代理软件内配置 DIRECT 直连规则。

## 文件

- `vpn_route_bypass.py`：核心路由同步脚本（含 fake-ip 检测、DoH 解析、hosts 管理）
- `vpn_route_bypass_app.py`：系统托盘/状态栏 App，含下拉设置
- `config.example.json`：示例配置

## 环境与依赖

- Python 3.8+
- macOS 或 Windows
- 需要管理员权限运行（否则没法改路由和 hosts）
- 需要额外依赖（仅用于 App）

```txt
pystray
pillow
```

安装：

```bash
python3 -m pip install -r requirements.txt
```

## 配置

把示例复制为运行配置：

```bash
cp config.example.json config.json
```

关键字段说明：

| 字段 | 说明 | 默认 |
| --- | --- | --- |
| `prefixes` | 要走本机网络的网站前缀（逐条） | — |
| `interval_seconds` | 刷新 DNS/路由的周期（秒） | `120` |
| `local_gateway` | 可选，留空则自动识别；识别失败可填网关 IP | `null` |
| `state_file` | 状态文件名（存放于配置文件同目录） | `.vpn_route_bypass_state.json` |
| `dry_run` | 先演练不改系统（不写 hosts、不改路由） | `false` |
| `manage_hosts` | 是否写入 `/etc/hosts` 托管标记段（fake-ip 场景必需） | `true` |
| `doh_enabled` | 是否启用 DoH 兜底解析 | `true` |
| `doh_urls` | DoH 端点列表，`{host}` 会被替换为域名；需返回含 `Answer` 数组的 JSON | 阿里 DoH |
| `fake_ip_ranges` | 视为 fake-ip/劫持的网段，命中则触发 DoH | `198.18.0.0/15`、`100.64.0.0/10` |
| `host_ip_overrides` | 为白名单域名手动指定直连 IP（如校内站的内网地址）。公共 DNS 查不到内网地址，但这类地址往往才是本机网络真正能直连的目标；配置后该域名不再走系统解析/DoH | `{}` |

## 快速上手（推荐 App）

> 推荐用管理员权限运行。mac 直接顶部菜单栏；Windows 在系统托盘。

```bash
python3 vpn_route_bypass_app.py --config config.json
```

运行后你会看到状态图标，点击下拉菜单可直接操作（仅这 5 个按钮）：

- 启动服务 / 停止服务（合并为一个「开关按钮」）
- 添加白名单（直接在下拉输入站点，保存后自动生效）
- 管理站点（下拉查看并移除单个站点）
- 重置配置
- 退出

## 命令行模式（保留）

```bash
python3 vpn_route_bypass.py --config config.json --once      # 一次同步
python3 vpn_route_bypass.py --config config.json             # 常驻刷新
python3 vpn_route_bypass.py --config config.json --cleanup   # 清理（删路由 + 删 hosts 标记段）
```

## macOS 专项建议

- 需要先给 App 赋予辅助权限：如果系统提示，请允许终端/IDE 的完全磁盘/网络控制权限。
- 写入 `/etc/hosts` 需要管理员权限：请以 `sudo` 或管理员身份运行引擎/App。
- 如果 `local_gateway` 自动检测错误，可手工填本机网关（如路由器网关）

如果你要，我可以下一步再继续做：

1. 打包成 `.app`（macOS）与 `.exe`（Windows）可直接双击启动
2. 加上开机自启动/开机自动挂载托盘（mac LaunchAgent + Windows 任务计划）
