#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/alrufaaey-yahoo/http-proxy-control.git"
APP_DIR="/opt/http-proxy-control"
ENV_FILE="/etc/http-proxy-control.env"
SERVICE_FILE="/etc/systemd/system/http-proxy-control.service"
STATE_DIR="/var/lib/http-proxy-control"
TLS_DIR="/etc/http-proxy-control"

fail() { echo "خطأ: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || fail "شغّل المُثبت بصلاحيات root: sudo bash install.sh"
[[ -r /etc/os-release ]] || fail "يتطلب Ubuntu أو Debian حديثًا."
. /etc/os-release
[[ "${ID:-}" == "ubuntu" || "${ID:-}" == "debian" ]] || fail "التوزيعة المدعومة هي Ubuntu أو Debian."
[[ ! -e "$APP_DIR" ]] || fail "$APP_DIR موجود بالفعل؛ لا أستبدل ملفات تثبيت موجودة. راجع دليل التحديث في README."

read -r -p "منفذ لوحة التحكم HTTPS [8443]: " panel_port
panel_port="${panel_port:-8443}"
[[ "$panel_port" =~ ^[0-9]+$ ]] && (( panel_port >= 1024 && panel_port <= 65535 )) || fail "المنفذ يجب أن يكون بين 1024 و65535."
read -r -p "اسم مستخدم مدير اللوحة (حروف/أرقام/._@-): " panel_user
[[ "$panel_user" =~ ^[A-Za-z0-9_.@-]{3,64}$ ]] || fail "اسم المستخدم غير صالح (3 إلى 64 محرفًا)."
read -r -s -p "كلمة مرور مدير اللوحة (16 محرفًا على الأقل): " panel_pass; echo
(( ${#panel_pass} >= 16 )) || fail "اختر كلمة مرور من 16 محرفًا على الأقل."
read -r -s -p "أعد كلمة المرور: " panel_pass2; echo
[[ "$panel_pass" == "$panel_pass2" ]] || fail "كلمتا المرور غير متطابقتين."

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip openssl ca-certificates

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"; unset panel_pass panel_pass2' EXIT
git clone --depth 1 "$REPO_URL" "$TMP_DIR/source"
install -d -m 0755 "$APP_DIR"
cp -a "$TMP_DIR/source/app" "$APP_DIR/"
install -m 0644 "$TMP_DIR/source/requirements.txt" "$APP_DIR/requirements.txt"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --disable-pip-version-check --no-cache-dir -r "$APP_DIR/requirements.txt"

id -u proxyctl >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin proxyctl
install -d -o proxyctl -g proxyctl -m 0750 "$STATE_DIR"
install -d -o root -g proxyctl -m 0750 "$TLS_DIR"
if [[ ! -s "$TLS_DIR/tls.key" || ! -s "$TLS_DIR/tls.crt" ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
    -keyout "$TLS_DIR/tls.key" -out "$TLS_DIR/tls.crt" \
    -subj "/CN=http-proxy-control" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi
chown root:proxyctl "$TLS_DIR/tls.key" "$TLS_DIR/tls.crt"
chmod 0640 "$TLS_DIR/tls.key" "$TLS_DIR/tls.crt"

panel_hash="$(printf '%s' "$panel_pass" | (cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c 'import sys; from app.store import password_hash; print(password_hash(sys.stdin.read()))'))"
session_secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
cat > "$ENV_FILE" <<EOF
PANEL_USERNAME=$panel_user
PANEL_PASSWORD_HASH=$panel_hash
SESSION_SECRET=$session_secret
PANEL_PORT=$panel_port
PANEL_SSL_CERT=$TLS_DIR/tls.crt
PANEL_SSL_KEY=$TLS_DIR/tls.key
APP_DB=$STATE_DIR/proxy.db
EOF
chown root:proxyctl "$ENV_FILE"
chmod 0640 "$ENV_FILE"
unset panel_pass panel_pass2 panel_hash session_secret

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=HTTP/HTTPS Proxy Control Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=proxyctl
Group=proxyctl
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/python -m app.run
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=$STATE_DIR
CapabilityBoundingSet=
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"
systemctl daemon-reload
systemctl enable --now http-proxy-control.service

PUBLIC_IP="$(curl -4fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
echo
echo "اكتمل التثبيت."
echo "لوحة التحكم: https://${PUBLIC_IP:-عنوان-الخادم}:$panel_port"
echo "اسم المستخدم: $panel_user"
echo "شهادة HTTPS الافتراضية ذاتية التوقيع؛ سيعرض المتصفح تحذيرًا. تحقق من عنوان IP قبل المتابعة."
echo "افتح منفذ اللوحة في جدار الحماية/لوحة مزود VPS: TCP/$panel_port. لا يفتح المُثبت المنافذ تلقائيًا."
echo "بعد الدخول أنشئ منفذ Proxy ببيانات منفصلة، ثم افتح TCP لذلك المنفذ فقط."
echo "الحالة: systemctl status http-proxy-control"
echo "السجلات: journalctl -u http-proxy-control -f"
