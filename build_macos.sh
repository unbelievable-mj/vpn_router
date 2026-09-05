#!/usr/bin/env bash
# 在 macOS 上构建 VPNRouteBypass.app 并打包成 .dmg（通用脚本，本地与 CI 共用）。
#
# 用法：
#   bash build_macos.sh [版本号] [文件名后缀]
#     版本号缺省为 0.0.0；后缀可选，如 "-x64" / "-arm64"（多架构发布时避免重名）
#
# 产物：
#   dist/VPNRouteBypass.app
#   dist/VPNRouteBypass-<version><suffix>.dmg
#
# 说明：
#   - 用 PyInstaller 分别构建 GUI(.app) 与 CLI 引擎两个可执行；
#   - CLI 引擎二进制放入 .app/Contents/MacOS/，由 GUI 以子进程方式调用（引擎需要 root 提权）；
#   - 未配置 Apple Developer ID 时使用 ad-hoc 签名（--sign -）。下载安装被 Gatekeeper 拦截时，
#     运行：xattr -dr com.apple.quarantine /Applications/VPNRouteBypass.app
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="VPNRouteBypass"
VERSION="${1:-0.0.0}"
SUFFIX="${2:-}"
DMG_NAME="${APP_NAME}-${VERSION}${SUFFIX}.dmg"

echo "==> 1/5 构建 GUI .app (PyInstaller windowed)"
python3 -m PyInstaller --noconfirm --clean \
  --windowed \
  --name "$APP_NAME" \
  --add-data "config.example.json:." \
  vpn_route_bypass_app.py

echo "==> 2/5 构建 CLI 引擎 (PyInstaller onefile)"
python3 -m PyInstaller --noconfirm --clean \
  --onefile \
  --name vpn-route-bypass-cli \
  vpn_route_bypass.py

echo "==> 3/5 组装 .app：放入 CLI 引擎二进制"
mkdir -p "dist/$APP_NAME.app/Contents/MacOS"
cp "dist/vpn-route-bypass-cli" "dist/$APP_NAME.app/Contents/MacOS/"

echo "==> 4/5 代码签名（无证书则 ad-hoc）"
codesign --force --deep --sign - "dist/$APP_NAME.app"

echo "==> 5/5 打包 dmg"
rm -f "dist/$DMG_NAME"
hdiutil create -volname "$APP_NAME" \
  -srcfolder "dist/$APP_NAME.app" \
  -ov -format UDZO \
  "dist/$DMG_NAME"

echo "==> 完成：dist/$DMG_NAME"
ls -lh "dist/$DMG_NAME"
