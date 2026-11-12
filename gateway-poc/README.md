# Gateway e agente Python — POC controlada

Projeto **secure-gateway**. Repositório oficial:
[ds1david/ds1david](https://github.com/ds1david/ds1david), pasta `gateway-poc/`.

Para o novo agente HTTPS com assinaturas de aplicação, cliente separado com mTLS,
launcher PowerShell e preparação de GitLab/Artifactory, consulte
[HTTPS-POC.md](HTTPS-POC.md). Os comandos antigos abaixo continuam destinados ao
transporte mTLS original e não devem ser misturados com os pacotes HTTPS novos.

Implementação independente de FRP, usando apenas a biblioteca padrão do Python 3.11+.
O gateway atende RPC com frames JSON sobre TCP/mTLS. O agente Windows consulta o gateway
a cada dois segundos por conexão de saída, lê um serviço fictício em loopback e devolve
somente uma resposta sintética validada. Um cliente separado, também com certificado,
consulta o resultado. Há também encaminhamento TCP contínuo exclusivo para um servidor
de eco fictício. Não é uma VPN nem um publicador de serviços corporativos nesta versão.

O código só aceita `lab-status` e `lab-catalog`, correspondentes a GETs fixos
`http://127.0.0.1:18765/status` e `/catalog`. Não aceita URL, destino, cabeçalhos,
corpo HTTP, credenciais, redirecionamentos ou comandos remotos nessas consultas. O conteúdo retornado precisa
ser exatamente o fixture esperado. Isso mantém GitLab/Artifactory reais fora desta POC.
O terceiro serviço `lab-echo` conecta somente a `127.0.0.1:18766` e demonstra transporte
TCP binário com portas locais no cliente. Não há ocultação, instalação automática,
persistência ou alteração de antivírus/EDR.

## Executar no Windows sem administrador

Use um Python aprovado pela organização, instalado para o usuário. Execute em terminais
PowerShell visíveis, na pasta `gateway-poc`. O runtime não requer pip nem pacotes externos.
O gerador de certificados de teste requer OpenSSL 3 (por exemplo, o fornecido com Git
for Windows); não baixe executáveis para contornar controles de endpoint.

```powershell
python --version
python make_lab_certs.py
python -m unittest discover -s tests -p test_poc.py -v
```

Se OpenSSL não estiver no local padrão, acrescente ao gerador
`--openssl 'C:\caminho-aprovado\openssl.exe'`. Os testes procuram OpenSSL no PATH
ou no local padrão do Git. A geração recusa sobrescrever a pasta de destino.
Os testes geram certificados temporários e usam apenas loopback; precisam da porta
18765 e 18766 livres. Não execute os testes com o laboratório manual aberto.

Terminal 1 (laboratório):

```powershell
python poc.py lab
```

Terminal 2 (gateway local, somente loopback):

```powershell
python poc.py gateway --cert certs/gateway.crt --key certs/gateway.key
```

Terminal 3 (agente para status):

```powershell
python poc.py agent --cert certs/agent.crt --key certs/agent.key
```

Terminal 4 (cliente):

```powershell
python poc.py query --cert certs/client.crt --key certs/client.key
```

Resultado esperado: `{"result": {"service": "lab-status", "synthetic": true, "status": "ok"}}`.
Para testar catálogo, execute outro agente e cliente com `--service lab-catalog`.
É permitido apenas um pedido pendente globalmente; consultas concorrentes recebem `busy`.
`query` retorna código 1 para erros. Pare os processos com Ctrl+C. O agente encerra
depois da operação em andamento (até aproximadamente 12 segundos).

### Encaminhamento TCP por porta local

Com `lab` e `gateway` ainda abertos, inicie outro agente e um encaminhador cliente:

```powershell
python poc.py agent --service lab-echo --cert certs/agent.crt --key certs/agent.key
python poc.py forward --service lab-echo --local-port 18080 --cert certs/client.crt --key certs/client.key
```

Em outro terminal, confirme que bytes atravessam cliente → gateway → agente → eco:

```powershell
python -c "import socket; s=socket.create_connection(('127.0.0.1',18080),timeout=12); s.sendall(b'laboratorio'); print(s.recv(100)); s.close()"
```

Resultado esperado: `b'laboratorio'`. Para EC2, acrescente `--host` e `--port 443`
ao agente e a `forward`. A porta cliente fica sempre em `127.0.0.1`; não aceita
bind público. Outros processos da mesma máquina podem usá-la: mantenha o cliente
em estação de laboratório confiável e encerre-o ao terminar. A autenticação mTLS é
do encaminhador, não de cada processo local.

O transporte TCP permite bytes binários, mas seu destino é fixo no eco fictício.
Cada conexão tem limite agregado de 1 MiB nas duas direções, duração de 60 segundos
e inatividade de dez segundos. Ao fechar uma direção, encerra ambas; não implementa
half-close nem retomada de sessão. Ctrl+C no agente pode aguardar a sessão corrente
por até cerca de 65 segundos. Não está dimensionado para downloads ou bancos reais.

Guarde os arquivos em uma pasta privada do perfil do usuário. Em Windows, `chmod`
não implementa isolamento por ACL: configure uma ACL NTFS permitindo apenas seu usuário
e os administradores exigidos pela política corporativa. Verifique com `icacls certs`.
Não use compartilhamento de rede para chaves privadas. O gerador é exclusivamente de
laboratório: a CA dura sete dias, os certificados dois dias, e as chaves não têm senha
para permitir execução automatizada. Para EC2, prefira emissão e custódia pela PKI aprovada.

O gerador usa perfil de emissão explícito: CA sem restrição de EKU a servidor,
certificado `gateway` com `serverAuth`, e `agent`/`client` com `clientAuth`.
Ao terminar, valida as cadeias em modo estrito, os usos TLS, o hostname do gateway e
os fingerprints da política. Assim, configurações locais de emissão do OpenSSL não
acrescentam restrições de servidor à CA descartável. Não altera a configuração global.

## Identidade, autorização e limites

TLS mínimo 1.2, CA explícita em ambos os lados, certificado de cliente obrigatório,
validação do hostname/SAN no cliente e agente. Cada certificado tem papel e serviços
autorizados em `policy.json`, indexados pelo SHA-256 do certificado DER inteiro.
Uma CA válida sozinha não dá acesso. Use um certificado por agente/cliente, nunca
compartilhe a mesma chave entre máquinas. A política gerada autoriza os dois serviços
sintéticos e o eco para facilitar o laboratório; reduza a lista de cada identidade conforme o teste.

```json
{
  "<sha256-do-certificado-DER-em-64-hex-minusculos>": {
    "role": "agent",
    "services": ["lab-status"]
  }
}
```

Papéis aceitos: `agent` (pull) e `client` (query ou open para eco). Um agente não escolhe o destino.
O gateway verifica o serviço antes da atribuição e valida o resultado. O certificado
de servidor deve ter EKU serverAuth; os demais, clientAuth. O gerador emite esses usos.

Limites fixos: oito conexões simultâneas incluindo handshake, um pedido pendente,
frame máximo de 4096 bytes, handshake de quatro segundos, prazo total de frame de
quatro segundos no gateway, oito segundos aguardando agente, dois segundos de timeout
de leitura local. Cada identidade tem janela de 60 segundos com até 30 conexões de
cliente ou 90 de agente (inclui pedidos negados após autenticação). O agente consulta
a cada dois segundos e reconecta com espera exponencial de 1–30 segundos mais jitter.
Negação explícita espera 30 segundos. Não há fila persistente, replay ou garantia de
entrega; após falha, o cliente repete a consulta sintética idempotente.
Esses limites reduzem volume; não constituem um SLA de banda nem defesa completa contra
DoS. Restrinja as origens no Security Group. A consulta local tem corpo e resposta fixos.

Logs JSON em stdout incluem horário UTC, eventos, fingerprint, serviço e identificador
aleatório de correlação. Não registram conteúdo HTTP, certificados, chaves, tokens,
URL livre, endereços corporativos ou texto de exceção. O resultado da consulta aparece
no terminal do cliente. Encaminhe o journal a armazenamento aprovado com retenção e
acesso restritos; fingerprints são metadados de identidade. Rate limiting do journal
pode descartar eventos em sobrecarga. Não há auditoria imutável embutida.

## Deploy planejado na EC2

Contexto histórico: EC2 `frp-gateway`, `i-0180d7a7c60475b5c`, região `us-east-2`,
IP observado `3.14.245.241`. O hostname `secure-gateway.sicredi.space` foi inferido na
conversa anterior: confirme na zona Cloudflare e confirme o IP atual/Elastic IP antes
de emitir o certificado ou alterar DNS. Nenhuma alteração AWS/Cloudflare foi executada
por esta implementação.

Mantenha o registro A em **DNS only**. Este é TCP/TLS próprio, não HTTPS; o proxy HTTP
comum da Cloudflare não transporta esse protocolo nem preserva o mTLS ponta a ponta.
Não habilite proxy HTTP nem terminação TLS intermediária. Confirme que esse protocolo
é permitido pela rede de origem; TCP/443 aberto não prova autorização da aplicação.

1. Homologue o agente Python e o protocolo com a segurança de endpoint. Execute a
   POC somente em máquina de laboratório autorizada. Não restaure ferramentas bloqueadas.
2. Confirme Linux/systemd e Python 3.11+ na EC2. Planeje a liberação de 443: FRP anterior
   pode estar usando a porta. Pare o serviço anterior apenas em janela aprovada, sem
   apagar sua configuração; registre o rollback.
3. No Security Group permita TCP/443 somente aos IPs de saída dos laboratórios e
   clientes autorizados; SSH/SSM somente para administração aprovada. Não exponha 18765/18766.
4. Em estação de emissão controlada, gere certificados para o hostname confirmado
   (exemplo: `python make_lab_certs.py --out certs-ec2 --hostname secure-gateway.sicredi.space`).
   Proteja também essa pasta e não a versione. Nunca copie `ca.key`, `agent.key` ou
   `client.key` para a EC2. Para substituir a CA descartável, use a PKI aprovada e
   recalcule fingerprints na política.
5. Copie `poc.py` e `stream.py` para `/opt/gateway-poc/`. Copie somente `ca.crt`, `gateway.crt`,
   `gateway.key` e `policy.json` para `/etc/gateway-poc/`. Transfira por canal aprovado.
   Crie usuário de sistema sem login `gateway-poc`; diretórios e código pertencem a
   root, chave e política `root:gateway-poc` modo 0640, pasta de configuração 0750.
   Não distribua código gravável pelo usuário do serviço.
6. Instale a unidade [gateway-poc.service](deploy/gateway-poc.service) em
   `/etc/systemd/system/`. Os comandos abaixo exigem administrador **da EC2**, não do Windows:

```sh
sudo systemd-analyze verify /etc/systemd/system/gateway-poc.service
sudo systemctl daemon-reload
sudo systemctl enable --now gateway-poc
sudo systemctl status gateway-poc
sudo journalctl -u gateway-poc --since '10 minutes ago'
```

A unidade concede apenas a capacidade de bind na porta 443, limita recursos e usa
filesystem somente leitura. Revise a compatibilidade das diretivas com a distribuição.
Configure limites e retenção globais de journald para o orçamento de disco da EC2.
O arquivo foi preparado, mas não foi executado numa EC2 nesta sessão.

No Windows do laboratório, copie somente `ca.crt`, `agent.crt`, `agent.key`. No cliente,
somente `ca.crt`, `client.crt`, `client.key`. Use caminhos explícitos se não estiverem
em `certs/`. Mantenha o serviço fictício ligado no Windows e execute:

```powershell
Resolve-DnsName secure-gateway.sicredi.space
Test-NetConnection secure-gateway.sicredi.space -Port 443
python poc.py agent --host secure-gateway.sicredi.space --port 443 --cert certs/agent.crt --key certs/agent.key
# Em outro computador/terminal autorizado, com a chave do cliente:
python poc.py query --host secure-gateway.sicredi.space --port 443 --cert certs/client.crt --key certs/client.key
```

## Operação, revogação e rollback

### Diagnosticar connection_rejected / agent_reconnect

Atualize o código e reinicie os processos para usar os campos `stage` e `reason`.
`agent_started` indica início; `agent_connected` confirma que um poll foi respondido
após autenticação e autorização. Sem consultas, o agente permanece aguardando trabalho.
Não é necessário executar `lab` para validar apenas a conexão com o gateway:

```powershell
python poc.py check --host localhost --port 8443 --cert certs/agent.crt --key certs/agent.key
```

Resultado esperado: `{"ready": true}`. O teste não consome pedidos pendentes nem
conecta a serviços locais. No teste em um único computador, `localhost` exige SAN
`DNS:localhost` no certificado do gateway; um certificado emitido para o domínio da
EC2 não serve para esse nome. Em máquinas diferentes, `localhost` aponta para a própria
máquina: use o hostname do gateway e um certificado que contenha esse mesmo hostname.

| reason | Verificação |
| --- | --- |
| `hostname_mismatch` | O `--host` deve corresponder ao SAN do certificado do gateway. |
| `untrusted_ca`, `peer_rejected_ca` | Gateway e agente devem confiar na CA que emitiu o certificado do outro; não gere uma CA diferente por máquina. |
| `certificate_expired`, `peer_certificate_expired` | Certificados de laboratório duram dois dias; emita um conjunto novo e atualize política e processos. |
| `certificate_not_yet_valid` | Confira data/hora dos computadores e validade do certificado. |
| `client_certificate_required`, `peer_rejected_certificate` | Confira os arquivos de certificado/chave do agente e seus usos permitidos. |
| `certificate_wrong_purpose`, `peer_certificate_wrong_purpose` | O agente precisa de `clientAuth`; a CA também precisa permitir esse uso. Um certificado de gateway com apenas `serverAuth` será recusado como agente. |
| `connection_refused` | Confira se o gateway está ativo e se host/porta são os mesmos. |
| `file_not_found` | Confira a pasta atual e os caminhos `--ca`, `--cert` e `--key`; não é uma falha de rede. |
| `access_denied` | Use `stage` para distinguir acesso negado aos arquivos de uma conexão negada pelo sistema. |
| `not_tls` | O processo conectado não está usando o protocolo TLS esperado. |
| `timeout`, `connection_closed`, `tls_error` | Confira os dois lados, porta em uso e eventual interrupção de rede/endpoint. |

`stage=tls_handshake` indica falha antes de receber a identidade; `request_frame`
indica falha na leitura do pedido; `service_exchange` indica operação já autorizada.
Não envie chaves privadas para diagnóstico. Os códigos não incluem texto bruto de exceção.

No cliente, `tls_ca_load` identifica a leitura de `--ca`, `tls_identity_load` a leitura
de certificado/chave, `tcp_connect` a conexão TCP e `response_frame` a resposta do
gateway. Quando disponíveis, `errno` e `winerror` são registrados como números, sem
texto de exceção ou caminhos de arquivos. Versões anteriores usavam `network_error`
também para arquivos ausentes ou sem permissão. Antes de gerar novos certificados,
confirme a pasta de execução e esses caminhos:

```powershell
Get-Location
Test-Path certs-local-v2/ca.crt
Test-Path certs-local-v2/agent.crt
Test-Path certs-local-v2/agent.key
```

Os três resultados devem ser `True` se esse foi o nome escolhido para o conjunto.

`certificate_wrong_purpose` confirma um uso incompatível na cadeia apresentada ao
gateway; não comprova interceptação de proxy. O gerador anterior dependia da configuração
local do OpenSSL na emissão da CA, que podia acrescentar extensões incompatíveis.
Também é possível ter selecionado o certificado errado ou misturado conjuntos.
Para verificar um conjunto completo já emitido, na estação de emissão, sem conexão de
rede e sem ler chaves privadas:

```powershell
python make_lab_certs.py --verify-only --out certs --hostname localhost
```

Essa verificação é destinada ao conjunto completo produzido pelo gerador, incluindo
`unknown.crt` para testes negativos e `policy.json`. Se falhar, informa qual papel
não passou na validação. Use o hostname real de emissão se ele não for `localhost`.
Atualizar o código não corrige certificados antigos: emita um conjunto novo para o
laboratório e reinicie gateway e agente com CA e política correspondentes.

As verificações de propósito também se aplicam às CAs da cadeia, conforme a
[documentação de verificação do OpenSSL](https://docs.openssl.org/3.4/man1/openssl-verification-options/).

Para isolar certificados locais inconsistentes, pare agente e gateway com Ctrl+C,
crie uma pasta **nova** e use exatamente esse conjunto nos dois processos:

```powershell
python make_lab_certs.py --out certs-local --hostname localhost
python poc.py gateway --ca certs-local/ca.crt --cert certs-local/gateway.crt --key certs-local/gateway.key --policy certs-local/policy.json
# Outro terminal, na mesma pasta:
python poc.py check --host localhost --port 8443 --ca certs-local/ca.crt --cert certs-local/agent.crt --key certs-local/agent.key
python poc.py agent --host localhost --port 8443 --ca certs-local/ca.crt --cert certs-local/agent.crt --key certs-local/agent.key
```

Se `certs-local` já existir, escolha outro nome e ajuste todos os caminhos. Não misture
a política antiga com certificados novos. Preserve os certificados da EC2 separadamente.

### Operação regular

Mantenha quatro terminais separados na mesma pasta para o teste: gateway, agente,
laboratório e query. `agent_connected` comprova um poll bem-sucedido naquele instante;
o agente precisa continuar executando quando a query for enviada. Ctrl+C encerra o
agente e agora registra `agent_stopped`. Enquanto está ativo e autenticado, registra
`agent_polling` a cada aproximadamente 30 segundos. Se houver falhas, procure
`agent_reconnect` ou `agent_denied`. O `lab` registra `lab_request` somente para as
duas rotas fixas sintéticas, sem conteúdo ou caminhos fornecidos pelo cliente.

Em `request_finished`, `reason=agent_not_polling` significa que nenhum agente recolheu
o pedido para aquele serviço dentro de oito segundos; confirme agente ativo, `--service`,
host e porta nos três processos. `reason=agent_response_timeout` indica pedido recolhido
sem resposta no prazo; procure `request_assigned` e os logs do agente.
`reason=lab_unavailable` indica que o agente recebeu o pedido, mas não conseguiu validar
uma resposta do laboratório. Um agente com `--service lab-echo` não atende `lab-status`.

- `agent_timeout`: agente desconectado, serviço divergente, identidade sem autorização
  ou rede bloqueada. Confira horário, SAN, validade e eventos JSON; nunca desligue a validação TLS.
- `lab_unavailable`/`invalid_lab_response`: suba `python poc.py lab` e confirme porta
  18765 livre. O resultado precisa ser o fixture exato; um serviço real será recusado.
- `denied`: confira fingerprint, papel e lista de serviços. `rate_limit`/`busy`:
  aguarde a janela e reduza consultas; não aumente limites antes de revisar a causa.
- Rotação: emita certificado novo, inclua seu fingerprint, reinicie gateway e agente
  com as novas credenciais e remova o fingerprint antigo. Reinício corta sessões.
- Revogação emergencial: remova fingerprint e reinicie o gateway imediatamente; para
  CA comprometida, substitua CA e todas as identidades. Não há consulta CRL/OCSP nesta
  POC. A política é carregada no início; editar sem reiniciar não revoga conexões.
- Rollback: pare agentes com Ctrl+C, `sudo systemctl disable --now gateway-poc`,
  retire a regra de rede da POC e restaure o serviço anterior somente se autorizado.
  Preserve logs conforme retenção e revogue/destrua chaves descartáveis conforme política.

## Condição para GitLab/Artifactory reais

O modelo solicitado é **portas locais no cliente**, sem publicação pública de serviços.
O inventário [services.pending.json](services.pending.json) registra os destinos pedidos:

| Serviço | Destino interno solicitado | Situação |
| --- | --- | --- |
| GitLab | `https://gitlab.sicredi.net:443` | Desabilitado |
| Artifactory | `http://artifactory.sicredi.net:80` | Desabilitado |
| Oracle | `aceitacaopag-liquidacao-direta-db-oradb.dev.sicredi.cloud:1531` | Desabilitado |

O runtime não lê esse inventário. Editar `enabled` não habilita tráfego. Um futuro
cadastro de serviços precisa de allowlist nos dois lados (gateway e agente), identidade
por certificado, porta local escolhida, destino e porta exatos, limites por serviço e
aprovação registrada. A inclusão de outros tipos de serviço seguirá o mesmo processo;
não se pretende aceitar um destino arbitrário fornecido pelo cliente.

Para HTTPS, um encaminhamento TCP preserva o TLS do serviço, mas o cliente deve usar
o hostname original para SNI e validação de certificado. `https://localhost:porta`
pode falhar na validação. Não desligue a verificação: defina resolução/roteamento
aprovados para preservar hostname e porta. URLs absolutas, redirects, cookies e callbacks
do GitLab/Artifactory podem exigir configuração de aplicação ou um adaptador HTTP
revisado; o túnel TCP sozinho não garante compatibilidade. Artifactory foi solicitado
em HTTP: o segmento agente–serviço não terá TLS nesse caso. Oracle precisa de revisão
de autenticação e TLS/TCPS nativos e de possíveis redirects do listener. O mTLS desta
POC protege os dois enlaces com a EC2, não substitui a segurança do serviço de destino.

Esta versão não possui chave de configuração para destinos reais. Uma extensão exige
homologação documentada da segurança de endpoint, autorização específica do binário/script
e identidade do agente, responsáveis pelos serviços, escopo de rede, métodos, dados,
clientes, retenção e prazo de acesso. Exige também revisão de ameaças, credenciais
individuais, isolamento de destinos, limites adequados, revogação e testes novos. Essa
aprovação não é presumida pelo funcionamento da POC nem pela conectividade TCP.

Referências: [Python ssl](https://docs.python.org/3/library/ssl.html) e
[limitações de proxy Cloudflare](https://developers.cloudflare.com/dns/proxy-status/limitations/).
