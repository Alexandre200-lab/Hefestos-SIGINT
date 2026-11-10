# CHANGELOG — Hefestos SIGINT

## v5.0.0 — 2026-11-10

Reescrita completa a partir da v4.1. A v4.1 **não compilava** e anunciava
propriedades de segurança que o código não implementava. Todas as correções
abaixo foram verificadas por build real dos três nós e por testes estáticos
(`test_functional.sh`).

### Adicionado

- Biblioteca compartilhada real em `lib/` (`library.properties` + `lib/src/`),
  compilada com `arduino-cli --libraries <raiz>`.
- Vault de configuração em NVS (`Preferences`) cifrado com AES-256-GCM e
  payload TLV (Wi-Fi, credenciais HTTP, TOTP, PSK, enrollments).
- Provisionamento por PSK de deployment + `HKDF-SHA256(PSK, salt=node_id)`,
  com chave distinta por nó.
- Frame LoRa binário versionado, cabeçalho de 15 bytes usado como AAD.
- `TRACK_ACK` autenticado e retransmissão com backoff no Node 1.
- Anti-replay estrito por `(epoch, contador)` com janela apenas para
  diagnóstico de perda.
- Dashboard HTTP com login usuário + senha + TOTP, sessões com expiração e
  binding por IP, rate limit por IP e bloqueio progressivo.
- Varredura de espectro não-bloqueante com RSSI/SNR reais do Si4735 e
  restauração da sintonia do operador.
- Detecção de interferência com estados `NORMAL`, `DEGRADED`, `NOISE_RISE`
  e `LINK_LOSS` baseados em métricas de RF.
- Encaminhamento Node 2 → Node 3 por UART2 com frames CRC16, fila
  não-bloqueante e protocolo de requisição/resposta.
- Log forense append-only com cadeia SHA-256, timestamps UTC, recuperação de
  estado no boot e exportação JSONL + hash final.
- Comandos de console para provisionamento, diagnóstico, sintonia, varredura,
  exportação e reset.
- `build.sh` com validação da versão do core e `test_functional.sh` com
  invariantes de pinagem, protocolo, anti-replay, TOTP e ausência de segredos.

### Corrigido

- Build: includes `../lib/...` substituídos por biblioteca; `SD.begin()` com
  assinatura correta; API real do LoRa (`parsePacket`/`readBytes`); API real do
  Si4735; APIs mbedtls 2.x.
- Criptografia: `decryptConfig()` que sempre falhava; chave regenerada a cada
  boot; AES-128 disfarçado de AES-256; nonce não determinístico; cabeçalho não
  autenticado; `isRNGReady()` que não media entropia; colisão de flags.
- Anti-replay: removido o caminho de `RESYNC` que aceitava capturas antigas.
- Elétrica: conflito SCK/LED no GPIO7 do Node 3; UART0 usada para link em
  Node 2 e Node 3; GPS em UART0 no Node 1; pinos de strapping/flash no C3.
- ESM: varredura que reportava RSSI do LoRa; jamming que sempre dizia
  `NORMAL`; Node 2 que nunca enviava dados ao Node 3; handlers HTTP
  bloqueantes que perdiam capturas.
- Segurança operacional: Telnet removido; TOTP efetivamente verificado;
  dashboard sem injeção de HTML; nenhuma rotina imprime segredos.

### Removido

- `src/lib/` (headers duplicados e obsoletos).
- `src/Node3_Caixa_Preta_Arduino/` (legado Arduino Uno, incompatível).
- `secure_storage.h`, `crypto_hmac.h` (não usados e redundantes).
- `Node2_Base_Hefestos.ino.bak`.
- Symlink quebrado `{runtime.tools.esptool_py.path}`.
- Artefatos de build versionados (`build/`, `.bin`, `.elf`, `.map`).
- Telnet, EEPROM e dependências `AESLib`/`SoftwareSerial`.

### Quebra de compatibilidade

- O protocolo LoRa v4 (payload textual `ALVO_01|lat|lon`) não é compatível.
  Todos os nós precisam ser regravados.
- O vault v4 (EEPROM) não é migrado. É necessário re-provisionar o PSK e as
  credenciais.
- O Node 3 agora usa UART1 (pinos 20/21) e o Node 2 usa UART2 (pinos 16/17).
- O login HTTP exige TOTP; sem relógio sincronizado, use o console serial.

### Migração da v4.1

1. Regravar os três nós com a v5.0.0.
2. Em cada nó, gravar o mesmo PSK de 32 bytes (`psk <64 hex>`).
3. No Node 2, configurar Wi-Fi (opcional), usuário/senha e cadastrar o TOTP.
4. Ajustar o relógio (`settime <unix>`) ou aguardar o primeiro fix GNSS.
5. Confirmar `status` nos três consoles e o primeiro track no dashboard.

> O histórico anterior deste arquivo foi removido por descrever funcionalidades
> e estados (“production ready”) que não existiam no código da v4.x.
