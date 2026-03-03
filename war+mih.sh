#!/bin/sh

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear

echo -e "${YELLOW}Проверяем зависимости...${NC}"
echo -e "${YELLOW}Обновляем пакеты...${NC}"

if ! opkg update >/dev/null 2>&1; then
    echo -e "\n${RED}Ошибка обновления пакетов!${NC}"
    exit 1
fi

for pkg in wireguard-tools curl jq coreutils-base64; do
    if ! opkg list-installed 2>/dev/null | grep -qF "^$pkg "; then
        echo -e "${GREEN}Устанавливаем:${NC} $pkg"
        opkg install "$pkg" >/dev/null 2>&1 || {
            echo -e "\n${RED}Ошибка установки ${NC}$pkg"
            exit 1
        }
    fi
done

echo -e "${YELLOW}Генерируем ключи...${NC}"
priv="$(wg genkey)"
pub="$(printf "%s" "$priv" | wg pubkey)"

api="https://api.cloudflareclient.com/v0i1909051800"

ins() {
    curl -s \
        -H "User-Agent: okhttp/3.12.1" \
        -H "Content-Type: application/json" \
        -X "$1" "$api/$2" "${@:3}"
}

sec() {
    ins "$1" "$2" -H "Authorization: Bearer $3" "${@:4}"
}

echo -e "${GREEN}Регистрируем устройство в Cloudflare...${NC}"

response=$(ins POST "reg" \
-d "{\"install_id\":\"\",\"tos\":\"$(date -u +%FT%TZ)\",\"key\":\"${pub}\",\"fcm_token\":\"\",\"type\":\"ios\",\"locale\":\"en_US\"}")

id=$(echo "$response" | jq -r '.result.id')
token=$(echo "$response" | jq -r '.result.token')

if [ -z "$id" ] || [ "$id" = "null" ]; then
    echo -e "${RED}Ошибка регистрации:${NC}"
    echo "$response"
    exit 1
fi

echo -e "${GREEN}Активируем WARP...${NC}"

response=$(sec PATCH "reg/${id}" "$token" -d '{"warp_enabled":true}')

peer_pub=$(echo "$response" | jq -r '.result.config.peers[0].public_key')
client_ipv4=$(echo "$response" | jq -r '.result.config.interface.addresses.v4')
client_ipv6=$(echo "$response" | jq -r '.result.config.interface.addresses.v6')

if [ -z "$peer_pub" ] || [ "$peer_pub" = "null" ]; then
    echo -e "\n${RED}Ошибка получения конфигурации${NC}"
    exit 1
fi

conf=$(cat <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${client_ipv4}, ${client_ipv6}
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1280
S1 = 0
S2 = 0
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0x5245474953544552207369703a676f6f676c652e636f6d205349502f322e300d0a5669613a205349502f322e302f554450203139322e3136382e3132312e36323a353036303b6272616e63683d7a39684734624b6635633762313765616462303238333334346136633033610d0a4d61782d466f7277617264733a2037300d0a546f3a203c7369703a7573657240676f6f676c652e636f6d3e0d0a46726f6d3a203c7369703a7573657240676f6f676c652e636f6d3e3b7461673d323938376135316463353839613831650d0a43616c6c2d49443a2036313663363636333036613366393361336665636635663233366239386431360d0a435365713a20312052454749535445520d0a436f6e746163743a203c7369703a75736572403139322e3136382e34352e3139303a353036303e0d0a557365722d4167656e743a205a6f6970657220352e302e300d0a457870697265733a20363139310d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>

[Peer]
PublicKey = ${peer_pub}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:4500
PersistentKeepalive = 25
EOF
)

echo
echo -e "${GREEN}========== ${YELLOW}WARP CONFIG${GREEN} ==========${NC}"
echo "$conf"
echo -e "${GREEN}=================================${NC}"
echo

echo "$conf" > /root/WARP.conf
echo -e "${YELLOW}Файл сохранён:${NC} /root/WARP.conf"


echo -e "${GREEN}Применяем WARP.conf в Mihomo${NC}"

IN="/root/WARP.conf"
OUT="/etc/mihomo/config.yaml"
TMP="$(mktemp)"

[ -r "$IN" ] || { echo "Can't read $IN" >&2; exit 1; }
command -v awk >/dev/null 2>&1 || { echo "Missing awk" >&2; exit 1; }

awk -v OUT="$TMP" '
function trim(s){ gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s }
function lc(s){ return tolower(s) }
function yaml_quote(s){
  gsub(/\\/,"\\\\",s)
  gsub(/"/,"\\\"",s)
  gsub(/\r/,"",s)
  return "\"" s "\""
}
function split_endpoint(s,    a,n){
  s=trim(s)
  n=split(s,a,":")
  if(n<2){ host=s; port="" } else {
    port=a[n]
    host=a[1]
    for(i=2;i<n;i++) host=host ":" a[i]
  }
}
BEGIN{
  sec=""
  addr4=""; addr6=""; dns=""; mtu=""
  priv=""; pub=""; psk=""; allowed=""; endpoint=""; keep=""
  s1=""; s2=""; jc=""; jmin=""; jmax=""; h1=""; h2=""; h3=""; h4=""
  i1=""; i2=""; i3=""; i4=""; i5=""
}
{
  raw=$0
  line=$0
  sub(/[;#].*$/, "", line)
  line=trim(line)
  if(line=="") next

  if(line ~ /^\[.*\]$/){
    sec=lc(trim(substr(line,2,length(line)-2)))
    next
  }

  if(index(line,"=")==0) next
  key=trim(substr(line,1,index(line,"=")-1))
  val=trim(substr(line,index(line,"=")+1))
  k=lc(key)

  if(sec=="interface"){
    if(k=="address"){
      gsub(/,/, " ", val)
      n=split(val, a, /[ \t]+/)
      for(i=1;i<=n;i++){
        if(a[i] ~ /:/) addr6=a[i]; else addr4=a[i]
      }
    } else if(k=="privatekey") priv=val
    else if(k=="dns") dns=val
    else if(k=="mtu") mtu=val
    else if(k=="s1") s1=val
    else if(k=="s2") s2=val
    else if(k=="jc") jc=val
    else if(k=="jmin") jmin=val
    else if(k=="jmax") jmax=val
    else if(k=="h1") h1=val
    else if(k=="h2") h2=val
    else if(k=="h3") h3=val
    else if(k=="h4") h4=val
    else if(k=="i1") i1=val
    else if(k=="i2") i2=val
    else if(k=="i3") i3=val
    else if(k=="i4") i4=val
    else if(k=="i5") i5=val
  } else if(sec=="peer"){
    if(k=="publickey") pub=val
    else if(k=="presharedkey") psk=val
    else if(k=="allowedips") { gsub(/[ \t]+/, "", val); allowed=val }
    else if(k=="endpoint") endpoint=val
    else if(k=="persistentkeepalive") keep=val
  }
}
END{
  if(priv=="" || pub=="" || endpoint==""){
    print "WARP.conf missing required fields (PrivateKey/PublicKey/Endpoint)" > "/dev/stderr"
    exit 2
  }
  split_endpoint(endpoint)

  ip=addr4; sub(/\/32$/, "", ip)
  ipv6=addr6; sub(/\/128$/, "", ipv6)

  if(allowed=="") allowed="0.0.0.0/0,::/0"
  n=split(allowed, aip, ",")
  # YAML список allowed-ips (как у тебя в примере)
  allowed_block=""
  for(i=1;i<=n;i++){
    if(aip[i]=="") continue
    allowed_block = allowed_block "      - " yaml_quote(aip[i]) "\n"
  }

  print "mixed-port: 7890" > OUT
  print "allow-lan: false" >> OUT
  print "tcp-concurrent: true" >> OUT
  print "mode: rule" >> OUT
  print "log-level: info" >> OUT
  print "ipv6: false" >> OUT
  print "external-controller: 0.0.0.0:9090" >> OUT
  print "external-ui: ui" >> OUT
  print "external-ui-url: https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz" >> OUT
  print "secret: \"\"" >> OUT
  print "unified-delay: true" >> OUT
  print "profile:" >> OUT
  print "  store-selected: true" >> OUT
  print "  store-fake-ip: true" >> OUT
  print "" >> OUT

  print "proxy-groups:" >> OUT
  print "  - name: GLOBAL" >> OUT
  print "    type: select" >> OUT
  print "    proxies:" >> OUT
  print "      - WARP" >> OUT
  print "      - REJECT" >> OUT
  print "" >> OUT

  print "rules:" >> OUT
  print "  - \"MATCH,GLOBAL\"" >> OUT
  print "" >> OUT

  print "proxies:" >> OUT
  print "  - name: WARP" >> OUT
  print "    type: wireguard" >> OUT
  print "    server: " host >> OUT
  if(port!="") print "    port: " port >> OUT
  print "    private-key: " yaml_quote(priv) >> OUT
  print "    udp: true" >> OUT
  if(ip!="") print "    ip: " ip >> OUT
  if(ipv6!="") print "    ipv6: " ipv6 >> OUT
  print "    public-key: " yaml_quote(pub) >> OUT
  if(psk!="") print "    pre-shared-key: " yaml_quote(psk) >> OUT
  print "    allowed-ips:" >> OUT
  printf "%s", allowed_block >> OUT
  if(mtu!="") print "    mtu: " mtu >> OUT
  if(keep!="") print "    persistent-keepalive: " keep >> OUT

  # Если есть хоть один AWG-параметр — добавляем блок
  if(s1!="" || s2!="" || jc!="" || jmin!="" || jmax!="" || h1!="" || h2!="" || h3!="" || h4!="" || i1!="" || i2!="" || i3!="" || i4!="" || i5!=""){
    print "    amnezia-wg-option:" >> OUT
    if(s1!="")  print "      s1: " s1 >> OUT
    if(s2!="")  print "      s2: " s2 >> OUT
    if(jc!="")  print "      jc: " jc >> OUT
    if(jmin!="")print "      jmin: " jmin >> OUT
    if(jmax!="")print "      jmax: " jmax >> OUT
    if(h1!="")  print "      h1: " h1 >> OUT
    if(h2!="")  print "      h2: " h2 >> OUT
    if(h3!="")  print "      h3: " h3 >> OUT
    if(h4!="")  print "      h4: " h4 >> OUT
    if(i1!="")  print "      i1: " yaml_quote(i1) >> OUT
    if(i2!="")  print "      i2: " yaml_quote(i2) >> OUT
    if(i3!="")  print "      i3: " yaml_quote(i3) >> OUT
    if(i4!="")  print "      i4: " yaml_quote(i4) >> OUT
    if(i5!="")  print "      i5: " yaml_quote(i5) >> OUT
  }

  print "    ip-version: ipv4" >> OUT
}
' "$IN"

chmod 600 "$TMP"
mkdir -p "$(dirname "$OUT")"
mv -f "$TMP" "$OUT"

/etc/init.d/mihomo reload
/etc/init.d/mihomo restart

echo -e "${GREEN}Готово !${NC}"
