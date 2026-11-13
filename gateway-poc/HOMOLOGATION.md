# Homologacao temporaria: tokens individuais e agente em segundo plano

Este perfil habilita GitLab e Artifactory para a validacao solicitada pelo operador.
Registra autorizacao do solicitante do TESTE, nao aprovacao corporativa: o campo
`corporate_approval` permanece `pending`. Validade maxima: 24 horas. Nao e configuracao
de producao. O laboratorio padrao permanece desabilitando destinos reais ate aplicar
a politica. Os testes automatizados usam apenas fixtures em loopback.

## Autenticacao

- Cliente -> AWS: TLS validado e token bearer individual aleatorio de 256 bits. O
  gateway guarda somente SHA-256, comparado em tempo constante, com ID, validade,
  escopo de servicos e revogacao. Quem possuir o token pode usar esse escopo; nao e
  atestacao de postura da maquina. O token nao vai ao agente nem aos servicos.
- Agente -> AWS: HTTPS validado e JWS RS256 assinado nos dois sentidos. Chaves existentes
  sao preservadas; mensagens duram 30 segundos, IDs unicos sao persistidos no SQLite e
  respostas/blocos sao vinculados a requisicao/sessao/sequencia.
- GitLab/Artifactory: credenciais, MFA, SSO e permissoes nativas continuam exigidas.
  O token do gateway nao substitui o login de nenhuma dessas aplicacoes.

Nao depende de Cloudflare Zero Trust nem usa o token FRP antigo. No perfil token,
o listener cliente deixa de exigir certificado TLS de cliente e exige o token dentro
do TLS. O modo `mtls` anterior continua disponivel para rollback. Validacao do servidor
nunca e desligada. O certificado publico/renovacao Certbot e o HAProxy permanecem iguais.

Proteja `client.token` por ACL no Windows; chmod nao substitui ACL NTFS. Nao compartilhe
tokens, nao os coloque na URL, chat ou Git. Cada processo local que usa o proxy compartilha
a identidade do cliente, portanto use uma estacao confiavel. O proxy escuta so em loopback.
Se houver inspecao TLS no enlace do cliente, o intermediario autorizado pode observar
o bearer token. A validade curta e a revogacao limitam seu uso, mas nao o tornam imune
a copia; esse e um limite do modelo escolhido em relacao ao mTLS.

## 0. Publicar codigo: somente na maquina de desenvolvimento

Repositorio oficial: https://github.com/ds1david/ds1david. Na raiz do repositorio,
depois de revisar e testar as alteracoes, publique somente codigo e documentacao:

```powershell
git status --short
git diff --check
git add gateway-poc/.gitignore gateway-poc/README.md gateway-poc/HOMOLOGATION.md gateway-poc/homologation.py gateway-poc/https_poc.py gateway-poc/poc.py gateway-poc/stream.py gateway-poc/Start-RestrictedLab.ps1 gateway-poc/Start-HttpsClient.ps1 gateway-poc/deploy/gateway-poc-https.service gateway-poc/tests/test_https.py gateway-poc/tests/test_client_admin.py
git diff --cached --stat
git commit -m "Update controlled gateway homologation"
git push origin main
```

Se a versao ja foi publicada, pule esse bloco. EC2, Windows restrito e intermediario
apenas recebem codigo com `git pull --ff-only origin main`; nao fazem push de arquivos
operacionais. Nao use `git add .`: certificados, chaves, tokens, bundles, configuracoes
locais e logs nao devem ser publicados. Se o pull falhar por alteracoes locais, pare
e revise; nao use reset/force para apagar configuracoes.

## 1. Preparar no aws-frp (EC2 Linux)

Atualize o codigo e instale os quatro modulos, preservando configuracoes e certificados:

```bash
git -C ~/ds1david pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/ds1david/gateway-poc/{https_poc.py,poc.py,stream.py,homologation.py} /opt/gateway-poc-https/
python3 /opt/gateway-poc-https/homologation.py prepare --out ~/bundles-homologation --client-id intermediario-01 --agent-id windows-lab-01 --hours 24
```

Execute quando estiver pronto: a janela de 24 horas comeca na geracao. Padroes:
`intermediario-01`, `windows-lab-01`, ambos os servicos. O solicitante registrado e o
usuario Linux. Informe outro `--agent-id` se sua identidade foi alterada.

Cria uma pasta nova `bundles-homologation` e recusa sobrescrever uma existente:

| Arquivo | Destinatario |
| --- | --- |
| gateway-policy.json | EC2: politica e hash; nao contem token completo |
| agent-policy.json | Windows restrito: politica sem token |
| client-policy.json + client.token | Transferir somente ao intermediario cliente |

O resumo nao imprime o token. Para clientes adicionais use `issue-client` na EC2,
conforme a secao de novos clientes; nao gere outra politica do agente.

## 2. Atualizar EC2 e aplicar a politica gateway

Na EC2 Linux:

```bash
sudo python3 /opt/gateway-poc-https/homologation.py apply --config /etc/gateway-poc-https/config.json --policy ~/bundles-homologation/gateway-policy.json
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
```

O helper cria backup e altera somente autenticacao, escopo de teste e limites. Preserva
`tls_cert`, `tls_key`, `tls_ca`, chaves de assinatura, URLs e replay DB. Nao substitua o
config inteiro pelo antigo do intermediario: isso poderia desfazer o certificado publico.
Nao altere HAProxy ou Certbot. O nome antigo do backend `client_mtls` e apenas uma etiqueta.

No intermediario com SSH, dentro de `gateway-poc`, baixe os arquivos privados:

```powershell
git pull --ff-only origin main
New-Item -ItemType Directory -Force .\bundles-homologation | Out-Null
scp aws-frp:bundles-homologation/agent-policy.json .\bundles-homologation/
scp aws-frp:bundles-homologation/client-policy.json .\bundles-homologation/
scp aws-frp:bundles-homologation/client.token .\bundles-homologation/
```

`aws-frp` representa o alias/endereco SSH ja utilizado. Transfira somente a politica
do agente ao Windows restrito. Nao envie o token ao agente nem publique esses arquivos.

## 3. Windows restrito: aplicar e verificar tudo antes de iniciar

Transfira por canal aprovado somente `agent-policy.json` para
`gateway-poc/bundles-homologation/`. Na pasta `gateway-poc`:

```powershell
git pull --ff-only origin main
python homologation.py apply --config bundles-https/agent/config.json --policy bundles-homologation/agent-policy.json
.\Start-RestrictedLab.ps1 -Mode Check
.\Start-RestrictedLab.ps1
```

Check verifica configuracao/arquivos/dependencias, validade, canal assinado com AWS para
os dois servicos, DNS/conexao dos destinos e HEAD HTTP(S) em cada raiz. GitLab mantem
validacao TLS. Aceita 2xx/3xx e desafio 401 como conectividade, com
`application_login: not_tested_on_agent`. O login real continua no cliente. HTTP
403/404/405/5xx falha e nenhum agente inicia. Se necessario configure `readiness_paths`
no agente com um caminho relativo conhecido do servico, definido com seu responsavel.

No perfil homologacao, o ultimo comando repete o preflight, inicia quatro workers
limitados em segundo plano e retorna ao prompt somente depois do marcador de pronto.
Se falhar, informa os logs. Nao instala servico, tarefa agendada ou inicio automatico;
nao altera EDR ou execution policy. O processo continua visivel nas ferramentas do Windows.

```powershell
.\Start-RestrictedLab.ps1 -Mode Status
.\Start-RestrictedLab.ps1 -Mode Stop
.\Start-RestrictedLab.ps1 -Foreground
```

Status mostra PID real e caminhos dos logs. Stop confere executavel e horario de
criacao para nao encerrar outro processo caso o PID seja reutilizado. O ultimo comando
e a alternativa de primeiro plano. Logs/metadados ficam em
`%LOCALAPPDATA%\secure-gateway\agent`; acompanhe com `Get-Content CAMINHO -Tail 30 -Wait`.
Defina retencao local. Status indica processo ativo, nao login na aplicacao. Ao expirar
o escopo de homologacao, o pool encerra; nao renova autorizacao sozinho.

## 4. Cliente intermediario

Mantenha `client.token` ao lado de `client-policy.json`:

```powershell
python homologation.py apply --config bundles-https/client/config.json --policy bundles-homologation/client-policy.json
.\Start-HttpsClient.ps1 -Mode Check
.\Start-HttpsClient.ps1
```

O ultimo comando inicia o proxy local `127.0.0.1:18080`; deixe esse terminal do cliente
aberto. Linux: use `.venv/bin/python` no apply e
`https_poc.py proxy --config bundles-https/client/config.json`.

## 5. Validar aplicacoes

Em outro terminal do intermediario:

```powershell
curl.exe --proxy http://127.0.0.1:18080 --head https://gitlab.sicredi.net/
curl.exe --proxy http://127.0.0.1:18080 --head http://artifactory.sicredi.net/
```

GitLab usa CONNECT para preservar hostname/SNI e HTTPS nativo. Artifactory usa HTTP
para o host/porta fixos. O proxy nao aceita um destino arbitrario. Para testar Git,
substitua o caminho por um projeto de teste ao qual voce ja tenha acesso:

```powershell
git -c http.proxy=http://127.0.0.1:18080 ls-remote https://gitlab.sicredi.net/SEU_GRUPO/SEU_PROJETO.git
```

Use seu gerenciador de credenciais aprovado, nao um PAT na URL. Se o Git nao confiar
na cadeia HTTPS corporativa, configure a CA oficial/backend TLS aprovado; nao desligue
`sslVerify`. Browser/SSO pode envolver outros dominios, nao liberados por padrao.

Para Artifactory, valide leitura de um artefato pequeno com a ferramenta e credenciais
existentes, usando esse proxy apenas para o teste. Escrita somente em repositorio de
teste que voce possa alterar. HTTP/80 nao oferece TLS entre agente e Artifactory;
defina HTTPS antes de credenciais/dados sensiveis. Nenhuma senha nativa e guardada no agente.

## Novos clientes: administrar exclusivamente no aws-frp

Depois da configuracao inicial, nao use `prepare` para adicionar clientes. Na EC2,
o comando abaixo cadastra somente o novo cliente, sem alterar a politica do agente,
certificados ou clientes existentes. Recusa IDs repetidos e servicos expirados.
A validade e o menor prazo entre `--hours` e a autorizacao atual dos servicos.

```bash
sudo python3 /opt/gateway-poc-https/homologation.py issue-client \
  --config /etc/gateway-poc-https/config.json \
  --client-id cliente-02 --services gitlab artifactory --hours 24 \
  --out /etc/gateway-poc-https/client-bundles/cliente-02
sudo systemctl restart gateway-poc-https
```

O diretorio privado gerado contem `client-policy.json` e `client.token`. Transfira
esses dois arquivos por canal aprovado somente ao respectivo cliente, usando o
intermediario com SSH se necessario. Nunca ao Windows restrito ou ao GitHub.
O cliente precisa tambem da configuracao base de cliente, CA e codigo existentes;
o pacote de token nao substitui essa instalacao. No cliente, aplique a politica
como na etapa 4. O Windows restrito continua executando o mesmo agente, sem mudancas.
O reinicio do gateway interrompe as sessoes ativas; o agente reconecta.

## Limites, diagnostico e revogacao

Perfil: quatro sessoes globais, 16 MiB agregados/sessao, cinco minutos, inatividade de
30 segundos, 120 aberturas/minuto/cliente e 1200 mensagens HTTPS/minuto do agente.
Continua uma POC por requisicoes HTTP, sem promessa para clones grandes ou muitos assets.

- `service_disabled_or_expired`: politica/identidade/prazo. Nao renova sozinho.
- `client_or_service_denied`: confira token correspondente, cliente ativo e escopo.
- `target_http_not_ready`: preflight do destino falhou; confira HTTP status/readiness.
- Proxy local 403: destino/metodo nao permitido. 502: abertura pelo gateway falhou.
  HTTP 401/403 apos CONNECT pode ser da aplicacao e exige credenciais/permissoes nativas.
- `gateway_busy`: quatro sessoes em uso; nao remova limites para mascarar falha.

Na EC2, para revogar um cliente e encerrar sessoes via reinicio:

```bash
sudo python3 /opt/gateway-poc-https/homologation.py revoke --config /etc/gateway-poc-https/config.json --client-id intermediario-01
sudo systemctl restart gateway-poc-https
```

Para renovar/rotacionar, prepare outra pasta com o mesmo ID e reaplique os tres arquivos
coerentes. O token antigo perde validade apos atualizar/reiniciar o gateway. Nao declare
aprovacao corporativa inexistente no JSON. Para rollback, pare agente/proxy, restaure
os backups `config.json.before-homologation-*` nos tres ambientes e reinicie o gateway.
Os backups sao privados e preservam os caminhos do certificado publico.
