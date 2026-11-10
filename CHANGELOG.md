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
- Teste de round-trip do protocolo serial executado no host
  (`tests/serial_roundtrip.cpp` + stub mínimo em `tests/stub/`): 33
  verificações cobrindo payload com `0xAA`/`0x55`, frames concatenados, frame
  corrompido, frame truncado, alimentação byte a byte e payload máximo.
- Ressincronização do receptor serial por varredura de frame íntegro
  (início + comprimento + `END` + CRC16), com descarte automático de lixo.

### Corrigido

- **Protocolo serial (crítico):** o parser de frames lia `LEN`, `CRC` e
  `PAYLOAD` com 1 byte de deslocamento. O código compilava e passava nos
  testes estáticos, mas o link Node 2 ↔ Node 3 jamais decodificava um frame —
  o log forense recebia apenas lixo. Corrigido e coberto por round-trip.
- **Ressincronização serial:** um byte `0xAA` perdido ou um frame truncado
  fazia o receptor perder o frame válido seguinte. Agora o receptor varre o
  buffer procurando um frame íntegro (CRC conferido) e se recupera sozinho.
- Build: includes `../lib/...` substituídos por biblioteca; `SD.begin()` com
  assinatura correta; API real do LoRa (`parsePacket`/`readBytes`); API real do
  Si4735; APIs mbedtls 2.x.
- Criptografia: `decryptConfig()` que sempre falhava; chave regenerada a cada
  boot; AES-128 disfarçado de AES-256; nonce não determinístico; cabeçalho não
  autenticado; `isRNGReady()` que não media entropia; colisão de flags.
- HKDF: o `info` era truncado silenciosamente quando não cabia no bloco
  `T(i)` (violava a RFC 5869); agora a derivação aborta em vez de producing
  material de chave errado.
- Vault: `setSecret()` recarrega o cache após gravar (sem isso, um `save()`
  posterior apagava as credenciais recém-provisionadas); `save()` agora
  verifica o retorno da escrita na NVS.
- Log forense: o número de sequência só é confirmado depois da gravação
  bem-sucedida no SD (antes um erro de escrita queimava um `seq`).
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
- `IMPLEMENTATION_GUIDE_v2.md` e `OPERATION_MANUAL_v2.md`: documentos da v2/v4
  obsoletos, com credenciais fixas e afirmações contrárias ao código real.
- Código morto: `epochUtcToDate()` (implementação errada e sem uso),
  `JammingDetector::tick()`, `wipePeers()` sem chamada, `seqPrefs` e
  `serCrcErrors` no Node 2, expiração de beacon FM sem comando associado.

### Segurança do repositório

- Histórico reescrito com `git filter-repo`: removidas as credenciais fixas
  da v4.x (senha de Wi-Fi em texto claro e segredo de TOTP) e os artefatos de
  build versionados. O `.git` passou de 48 MB para 516 KB.
- **As credenciais usadas na v4.x devem ser consideradas comprometidas e
  rotacionadas** (senha do Wi-Fi, senha HTTP, novo TOTP).
- O purge do remoto exige *force-push* do histórico reescrito; mesmo assim o
  valor publicado deve ser trocado.

### Quebra de compatibilidade

- O protocolo LoRa v4 (payload textual `ALVO_01|lat|lon`) não é compatível.
  Todos os nós precisam ser regravados.
- O vault v4 (EEPROM) não é migrado. É necessário re-provisionar o PSK e as
  credenciais.
- O Node 3 agora usa UART1 (pinos 0/2) e o Node 2 usa UART2 (pinos 16/17).
- O Node 2 usa GPIO13 para o reset do Si4735 (GPIO12 é strapping do ESP32).
- O login HTTP exige TOTP; sem relógio sincronizado, use o console serial.
- O histórico do Git foi reescrito: clones existentes precisam ser
  refetidos (`git fetch && git reset --hard origin/main`).

### Migração da v4.1

1. Regravar os três nós com a v5.0.0.
2. Em cada nó, gravar o mesmo PSK de 32 bytes (`psk <64 hex>`).
3. No Node 2, configurar Wi-Fi (opcional), usuário/senha e cadastrar o TOTP.
4. Ajustar o relógio (`settime <unix>`) ou aguardar o primeiro fix GNSS.
5. Confirmar `status` nos três consoles e o primeiro track no dashboard.

> O histórico anterior deste arquivo foi removido por descrever funcionalidades
> e estados (“production ready”) que não existiam no código da v4.x.
