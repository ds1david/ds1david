# Testes HTTPS no Windows restrito e preparação dos serviços

Repositório oficial: https://github.com/ds1david/ds1david, pasta `gateway-poc/`.

Esta versão acrescenta `https_poc.py` sem substituir o protocolo antigo de `poc.py`.
O agente usa HTTPS com mensagens JWS/JWT RS256 assinadas nos dois sentidos. O cliente
continua em outro endpoint com mTLS. As chaves de assinatura são individuais e distintas
das chaves TLS. A CA corporativa não é uma credencial de agente.

## O que já funciona e o que depende do ambiente

- Consultas aos fixtures `lab-status`/`lab-catalog` e TCP binário para `lab-echo`.
- Launcher PowerShell com padrões internos, sem administrador, serviço oculto,
  alteração de execution policy ou instalação automática de dependências.
- Gateway e agente preparados para destinos fixos GitLab e Artifactory, desabilitados
  por padrão e dependentes de autorização explícita nos dois lados e no cliente.
- Não há chave para desativar a validação TLS. No agente, `ssl.create_default_context()`
  usa a confiança do sistema operacional, incluindo a store Windows. Uma CA corporativa
  oficial em PEM também pode ser indicada por `corporate_ca` no config do agente.
- O proxy corporativo continua participando do transporte. Os dados JWS são assinados,
  não cifrados adicionalmente para evitar inspeção. Não se presume autorização de rede
  a partir de uma CA confiável. Não há suporte automático a PAC, autenticação de proxy
  explícito ou CONNECT: o canal usa conexão HTTPS direta, adequada ao caminho transparente
  identificado nos testes. Um caminho que exija proxy explícito necessita adaptação aprovada.
- Ainda é preciso testar a rede real. Os testes automatizados são locais; não demonstram
  que o equipamento corporativo permitirá a aplicação. Se a inspeção verificar o certificado
  da origem, uma CA privada de laboratório pode ser recusada por ela.

## 1. Preparar uma única vez no intermediário autorizado

Atualize o clone oficial. Em `gateway-poc`, use um ambiente Python 3.11+ aprovado.
No PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-https.txt
```

No Linux, os equivalentes são `python3 -m venv .venv` e
`.venv/bin/python -m pip install -r requirements-https.txt`.
Em ambiente restrito use o índice/wheelhouse aprovado. Os launchers não executam pip.

O certificado TLS de servidor precisa cobrir os DOIS nomes:

```
secure-gateway.sicredi.space        cliente mTLS
agent-gateway.sicredi.space         agente HTTPS
```

Para teste descartável, emita um conjunto novo, sem substituir o conjunto antigo:

```powershell
.\.venv\Scripts\python.exe make_lab_certs.py --out certs-https --hostname secure-gateway.sicredi.space --agent-hostname agent-gateway.sicredi.space
.\.venv\Scripts\python.exe prepare_https.py --cert-dir certs-https
```

O segundo comando cria `bundles-https/gateway`, `bundles-https/agent` e
`bundles-https/client`, cada qual com `config.json` e somente suas credenciais.
Recusa sobrescrever o destino. Todos os arquivos dessa pasta são privados para fins
de distribuição e ignorados pelo Git. Proteja a pasta por ACL no Windows e permissões
no Linux. `chmod` no Windows não substitui ACL NTFS.

Não reutilize conjuntos de chaves que já passaram pelo Git, inclusive ZIPs: trate-os
como expostos, emita CA e identidades novas e atualize as políticas nos três ambientes.
Remover o arquivo da versão atual não elimina cópias do histórico. O preparo usa
`certs-https` por padrão para separar o conjunto novo dos certificados antigos.

Para o deploy através da inspeção, prefira certificado de CA pública no gateway,
com os dois SANs e cadeia completa. O certificado descartável dura dois dias e não
resolve a confiança da inspeção na origem. Para substituir o certificado de servidor,
coloque a cadeia/chave oficiais no pacote gateway e ajuste `tls_cert`/`tls_key` nele.
`ca.crt` continua sendo a CA dos certificados individuais dos clientes.

Distribua por canal aprovado:

| Destino | O que recebe |
| --- | --- |
| EC2 | Somente `bundles-https/gateway/` e código |
| Windows restrito | Somente `bundles-https/agent/` e código |
| Intermediário cliente | Somente `bundles-https/client/` e código |

Preserve a estrutura de pastas no Windows, ao lado dos scripts. Nunca distribua
`ca.key`. O agente não recebe `gateway.key`; a EC2 não recebe a chave de assinatura
do agente nem a chave TLS do cliente. As chaves públicas cruzadas são distribuídas
no pacote e não são aprendidas pela rede.

## 2. Preparar a EC2 e o DNS

Para os comandos completos de primeira instalacao no Ubuntu, use
[INSTALL-HTTPS-EC2.md](deploy/INSTALL-HTTPS-EC2.md). `gateway-poc-https` e HAProxy
precisam estar ativos ANTES do primeiro Check no Windows restrito.

Adicione o registro A `agent-gateway.sicredi.space` para a mesma EC2. Mantenha ambos
os registros em DNS only. O endpoint antigo não pode continuar ocupando 443 quando
HAProxy for assumir a porta; faça a transição em janela aprovada e preserve o rollback.
Restrinja 443 no Security Group às origens autorizadas. Não exponha 9443/9444.

Na EC2, obtenha o código pelo GitHub e instale Python/venv e HAProxy pelo canal da
distribuição. A configuração em `deploy/haproxy-https.cfg` roteia SNI para:

```
443 / secure-gateway       -> 127.0.0.1:9443 / cliente mTLS
443 / agent-gateway        -> 127.0.0.1:9444 / agente HTTPS
```

HAProxy NÃO termina TLS nessa configuração. Seu certificado permanece no Python.
Revise e mescle a configuração se já houver outros serviços; não sobrescreva rotas
existentes. Valide com `sudo haproxy -c -f /etc/haproxy/haproxy.cfg` antes de reiniciar.
Os arquivos systemd e HAProxy foram preparados; não foram executados numa EC2 nesta sessão.

Instale `poc.py`, `stream.py`, `https_poc.py` e `requirements-https.txt` em
`/opt/gateway-poc-https`, pertencentes a root. Crie a venv nesse diretório e instale as
dependências nela. Instale o pacote gateway em `/etc/gateway-poc-https` com diretório
0750 e arquivos 0640, `root:gateway-poc`. Use o usuário sem login `gateway-poc` da POC.

No `config.json` da EC2, altere SOMENTE o caminho de estado:

```json
"replay_db": "/var/lib/gateway-poc-https/replay.sqlite"
```

A unidade `deploy/gateway-poc-https.service` cria esse diretório gravável por meio de
`StateDirectory`. O restante do filesystem do serviço fica somente leitura.
Instale-a em `/etc/systemd/system/`, valide com `systemd-analyze verify`, faça
`daemon-reload` e inicie `gateway-poc-https`. Confira:

```bash
sudo systemctl status gateway-poc-https --no-pager
sudo journalctl -u gateway-poc-https -f
```

O evento inicial é `https_gateway_started`. A aplicação deve escutar somente em
127.0.0.1:9443/9444; HAProxy escuta em 443. Configure retenção de journal e backups
protegidos do estado. O banco não pode ser apagado durante a validade das mensagens
se for necessário manter a proteção contra repetição após reinício.

## 3. Windows restrito: um comando para o laboratório e agente

Receba o código e o pacote `bundles-https/agent/` do MESMO preparo instalado na EC2.
Disponibilize as dependências em Python aprovado ou em `.venv`, conforme o passo 1.
A partir da pasta dos scripts:

```powershell
.\Start-RestrictedLab.ps1
```

O padrão resolve caminhos pela pasta do script, verifica credenciais e dependências,
valida a resposta assinada do endpoint, inicia os dois fixtures em loopback e executa
o agente `lab-status` no mesmo processo Python. Deixe o terminal aberto. Ctrl+C encerra
o teste; nada é instalado para inicialização automática. Pare os laboratórios antigos
antes: as portas 18765 e 18766 precisam estar livres.

Outros modos disponíveis, sem repetir certificados, hostname ou porta:

```powershell
.\Start-RestrictedLab.ps1 -Mode Check
.\Start-RestrictedLab.ps1 -Service lab-echo
.\Start-RestrictedLab.ps1 -Mode Agent -Service lab-status
```

`Agent` não inicia fixtures. `Lab` executa somente os fixtures antigos. Se a política
de execução bloquear o script, use o processo corporativo de revisão/assinatura;
o roteiro não altera nem contorna essa política.

Em caso de `untrusted_ca`, confirme a confiança oficial da CA corporativa no Python
utilizado. O campo opcional `corporate_ca` aceita um caminho relativo ao config para
um bundle PEM fornecido oficialmente. Não exporte nem distribua chaves da CA.

## 4. Cliente no intermediário

Com código, dependências e `bundles-https/client/` disponíveis:

```powershell
.\Start-HttpsClient.ps1 -Mode Check
.\Start-HttpsClient.ps1
```

O segundo comando consulta `lab-status`. Resultado esperado: JSON com `status: ok`.
O gateway deve mostrar `https_session_started`, `https_request_assigned` e
`https_session_finished`. Para Linux:

```bash
.venv/bin/python https_poc.py query --config bundles-https/client/config.json
```

Para TCP binário, inicie o agente com `-Service lab-echo` e, no intermediário:

```powershell
.\Start-HttpsClient.ps1 -Mode Forward -Service lab-echo
```

O cliente escuta somente em 127.0.0.1:18083. Use outro terminal para testar:

```powershell
python -c "import socket; s=socket.create_connection(('127.0.0.1',18083),timeout=12); s.sendall(b'lab-https'); print(s.recv(100)); s.close()"
```

## 5. Preparação de GitLab e Artifactory

Os destinos são fixos no código: `gitlab.sicredi.net:443` e `artifactory.sicredi.net:80`.
Os configs gerados mantêm ambos `enabled: false`, sem permissão do cliente. Não há
parâmetro remoto para fornecer outro host ou porta. O código do agente também nega
destinos não cadastrados. Os testes nunca conectam a esses serviços reais.

Depois da homologação específica, o administrador deve registrar, nos configs do agente,
gateway e cliente, o serviço habilitado e uma aprovação com esta estrutura:

```json
"approval": {
  "agent_id": "windows-lab-01",
  "endpoint_security": "referencia-da-homologacao",
  "service_owner": "referencia-da-autorizacao-do-servico",
  "expires_utc": "AAAA-MM-DDTHH:MM:SSZ"
}
```

Esses campos são registros administrativos; o programa não consulta um sistema de
aprovações e não declara a homologação por conta própria. Uma aprovação ausente,
incompleta, expirada ou para outra identidade é recusada. A EC2 também precisa incluir
o serviço na lista `clients/<fingerprint>/services` do cliente autorizado. Reinicie
o gateway ao alterar políticas. Não copie exemplos com referências fictícias para ativar.

Após isso, as interfaces preparadas são `Start-RestrictedLab.ps1 -Mode Agent -Service
gitlab` e `Start-HttpsClient.ps1 -Mode Forward -Service gitlab`. Artifactory usa o mesmo
fluxo com `artifactory`. Os modos recusam execução na configuração distribuída por padrão.

Portas locais reservadas: GitLab 18443 e Artifactory 18081. Para GitLab, preserve o
hostname original/SNI e a validação HTTPS do serviço. Não use `https://localhost:18443`
com verificação desativada. Este incremento fornece TCP local; um proxy CONNECT local
para navegador/Git ainda NÃO foi implementado. Login, SSO, redirects e callbacks reais
precisam de revisão e testes. Artifactory HTTP não tem TLS no trecho agente–destino;
avaliar HTTPS com o responsável antes de dados reais. Não há credenciais GitLab no agente.

## Limites, auditoria e revogação

Uma sessão global, 1 MiB agregado, 60 segundos por sessão, inatividade de dez segundos,
blocos de 4096 bytes, oito conexões por listener, 30 pedidos/minuto por cliente e 1200
mensagens/minuto do único agente cadastrado nesta POC. As requisições HTTP são curtas;
isso limita desempenho. Não é ainda dimensionado ou homologado para clones grandes,
uploads de artefatos ou conexões concorrentes de navegador. Os limites são configuráveis
por pacote, mas precisam de nova validação antes de aumentá-los para serviços reais.

Cada requisição assinada dura até 30 segundos e tem identificador único persistido em
SQLite. Respostas são assinadas pelo gateway e vinculadas à requisição. Sequência e
identificador aleatório vinculam os blocos à sessão. As mensagens não são comandos de
shell. Assinaturas não garantem disponibilidade diante de um intermediário que bloqueie
ou atrase tráfego. Mantenha os relógios sincronizados.

Logs incluem serviço, fingerprint do cliente, correlação e bytes. Não incluem tokens,
conteúdo dos blocos, cabeçalhos de aplicação, cookies ou chaves. Metadados continuam
sujeitos à política de retenção. Revogue clientes removendo seus fingerprints e
reiniciando; revogue o agente removendo/trocando sua chave pública e reiniciando. Para
rotacionar chaves de assinatura, prepare e distribua um novo conjunto consistente.

Rollback: pare o agente, o serviço `gateway-poc-https` e a rota nova do HAProxy;
restaure o gateway anterior somente no caminho em que ele é autorizado. Preserve
estado e logs conforme a retenção. Não há modificação de EDR ou da política de rede.
