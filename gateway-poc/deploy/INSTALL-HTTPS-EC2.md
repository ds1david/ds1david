# Primeira instalacao HTTPS na EC2 Ubuntu

O servico antigo `gateway-poc` nao atende o protocolo HTTPS novo. DNS sozinho nao
faz a migracao. Este roteiro usa o usuario `gateway-poc` criado na instalacao anterior.
Use o novo pacote gateway do MESMO preparo distribuido ao Windows; nao gere chaves
independentes em cada maquina. Nao reutilize o ZIP anteriormente publicado no Git.

## 1. Intermediario: enviar somente o pacote gateway

No PowerShell, dentro de `gateway-poc`, no ambiente em que SSH funciona:

```powershell
scp -r .\bundles-https\gateway aws-frp:secure-gateway-upload/
```

No Linux, o equivalente e `scp -r bundles-https/gateway aws-frp:secure-gateway-upload/`.
O destino e a pasta privada de upload ja preparada. Nao envie chaves do agente.

## 2. EC2 Linux: conferir arquivos e instalar dependencias

```bash
git -C ~/ds1david pull --ff-only
ls -l ~/secure-gateway-upload/gateway/{config.json,ca.crt,gateway.crt,gateway.key,signing.key,agent-signing.pub}
id gateway-poc
sudo apt update
sudo apt install -y python3-venv haproxy
```

Pare se algum arquivo estiver ausente. O certificado precisa cobrir os dois SANs
`secure-gateway.sicredi.space` e `agent-gateway.sicredi.space`. Ele tambem precisa ser
aceitavel para a verificacao de origem da inspecao corporativa; prefira cadeia publica.

## 3. EC2 Linux: instalar codigo e pacote privado

```bash
sudo install -d -o root -g root -m 0755 /opt/gateway-poc-https
sudo install -o root -g root -m 0644 ~/ds1david/gateway-poc/{https_poc.py,poc.py,stream.py,requirements-https.txt} /opt/gateway-poc-https/
sudo python3 -m venv /opt/gateway-poc-https/.venv
sudo /opt/gateway-poc-https/.venv/bin/python -m pip install -r /opt/gateway-poc-https/requirements-https.txt
sudo install -d -o root -g gateway-poc -m 0750 /etc/gateway-poc-https
sudo install -o root -g gateway-poc -m 0640 ~/secure-gateway-upload/gateway/{config.json,ca.crt,gateway.crt,gateway.key,signing.key,agent-signing.pub} /etc/gateway-poc-https/
```

Ajuste o banco antirrepeticao para a pasta gravavel do servico:

```bash
sudo python3 - <<'PY'
import json
from pathlib import Path
p = Path('/etc/gateway-poc-https/config.json')
c = json.loads(p.read_text(encoding='utf-8-sig'))
c['replay_db'] = '/var/lib/gateway-poc-https/replay.sqlite'
p.write_text(json.dumps(c, indent=2), encoding='utf-8')
PY
```

Esse e o unico ajuste ao config padrao da EC2. Se usar outros nomes para arquivos
de certificado publico/cadeia completa, copie-os tambem e ajuste `tls_cert`/`tls_key`.

## 4. EC2 Linux: iniciar listeners internos

```bash
sudo install -o root -g root -m 0644 ~/ds1david/gateway-poc/deploy/gateway-poc-https.service /etc/systemd/system/gateway-poc-https.service
sudo systemd-analyze verify /etc/systemd/system/gateway-poc-https.service
sudo systemctl daemon-reload
sudo systemctl enable --now gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
sudo journalctl -u gateway-poc-https -n 20 --no-pager
sudo ss -ltnp 'sport = :9443 or sport = :9444'
```

Esperado: `active (running)`, evento `https_gateway_started` e Python somente em
127.0.0.1:9443/9444. Nao prossiga se o servico falhar.

## 5. EC2 Linux: encaminhar 443 com HAProxy

O trecho abaixo pressupoe HAProxy recem-instalado. Se ja houver rotas de outros
servicos, revise e mescle a configuracao em vez de sobrescreve-la.

```bash
sudo haproxy -c -f ~/ds1david/gateway-poc/deploy/haproxy-https.cfg
sudo cp -p /etc/haproxy/haproxy.cfg "/etc/haproxy/haproxy.cfg.before-secure-gateway-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -o root -g root -m 0644 ~/ds1david/gateway-poc/deploy/haproxy-https.cfg /etc/haproxy/haproxy.cfg
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
```

Depois de validar os listeners novos, libere 443 do gateway antigo na janela de mudanca:

```bash
sudo systemctl stop gateway-poc
sudo systemctl enable haproxy
sudo systemctl restart haproxy
sudo systemctl status haproxy --no-pager
sudo ss -ltnp 'sport = :443'
```

Esperado: HAProxy em 443; SNI `agent-gateway` vai para 9444, `secure-gateway` para 9443.
Se outro processo ocupar 443, identifique-o antes de alterar servicos. Mantenha DNS
only e Security Group restrito as origens autorizadas. Nao exponha 9443/9444.

## 6. Repetir testes

Windows restrito:

```powershell
.\Start-RestrictedLab.ps1 -Mode Check
```

Esperado: `{"ready": true}`. Depois execute `.\Start-RestrictedLab.ps1` e mantenha aberto.
No intermediario, execute `.\Start-HttpsClient.ps1`.

Se falhar, acompanhe `sudo journalctl -u gateway-poc-https -f` e correlacione o horario.
O diagnostico novo distingue `https_http_error` (com `http_status`),
`https_unexpected_content_type`, autenticacao de aplicacao e TLS. HTTP 403 sozinho
nao prova que foi o gateway quem recusou; confira o journal.

## Rollback

Em janela aprovada:

```bash
sudo systemctl stop haproxy
sudo systemctl stop gateway-poc-https
sudo systemctl start gateway-poc
```

Isso restaura somente o protocolo antigo no caminho em que ele ja era autorizado.
Preserve estado e logs. Defina quais unidades devem permanecer habilitadas no boot.
