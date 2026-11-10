# CHANGELOG — Hefestos SIGINT

## v5.1.0 — 2026-11-10

### Adicionado

- **Estado anti-replay persistido por par (fecha a vulnerabilidade de replay
  pós-reboot).** O estado (`epoch` + high-water do contador) vivia apenas em
  RAM: um frame capturado por SDR — com tag GCM legítima, portanto
  criptograficamente autenticado — era **aceito como frame novo** depois que
  o receptor reiniciava, porque o par recomeçava sem `epoch`/contador.
  - `lib/src/peer_state.h` (novo): `PeerStateStore` (formato serializado
    little-endian, 8 bytes por par) e `PeerReplayGuard` (estado em RAM +
    sinalização de persistência urgente).
  - `lib/src/config.h`: novo TLV `HEF_TLV_PEER_STATE` (`0x0A`) no vault
    cifrado, com `getPeerState()` / `putPeerState()` / `getEnrollment()`.
  - `lib/src/secure_protocol.h`: `RxSequence::hydrate()` e `exportState()`.
  - `src/Node2_Base_Hefestos`: `restorePeerStates()` reidrata os pares
    conhecidos no boot; gravação **imediata** quando o epoch muda e flush
    periódico a cada `HEF_PEER_STATE_FLUSH_MS` (60 s) para o contador.
  - `tests/anti_replay_persistence.cpp` (novo, host): 75 verificações,
    incluindo o cenário crítico de replay após reinício simulado e um bloco
    que demonstra que **sem** a reidratação o mesmo frame seria aceito.
  - `tests/framework.h` (novo): micro-framework de teste reutilizável no host.
  - Indicadores novos em `/api/peers` e no console: `stale_epoch`, `resyncs`,
    `epoch`, `counter`, `state_persisted`.
- **Orçamento de RF e conformidade regulatória (item 1.2 do plano).** A
  v5.0.0 operava o link LoRa com SF10 a 1 frame/s sem nenhuma verificação de
  espectro: o ciclo completo (telemetria + ACK) ocupava 2256,9 ms de tempo
  no ar a cada 1000 ms — **225,7% de duty cycle**, fisicamente impossível,
  com 6,5 Ah/dia só de TX.
  - `lib/src/link_budget.h` (novo): `HefLinkParams`, `HefLinkBudget`
    (`airtimeUs`/`airtimeMs`/`dutyCyclePercent`/`txEnergyMah`/
    `minIntervalForDuty`) e `HefDutyGuard` (janela deslizante de 1 h em
    baldes de 1 min).
  - `lib/src/band_plan.h` (novo): perfis regionais de referência
    `915-ANATEL`, `915-FCC` e `868-ETSI` (faixa, SF/BW/CR, EIRP, limite de
    duty cycle). O perfil ativo é o de compilação (`HEF_BAND_PROFILE`).
  - `tools/airtime.py` (novo, executável): CLI de cálculo de airtime/duty/
    energia com `--selftest` (valida a fórmula contra a tabela oficial do
    RP002), `--profile`, `--sweep`.
  - `tests/link_budget.cpp` (novo, host): 51 verificações — tabela RP002,
    lei de escalonamento `2^ΔSF`, valores do projeto, parâmetros inválidos,
    intervalo mínimo por perfil e o guard de duty cycle (que precisa
    **recusar** a transmissão violadora).
  - `lib/src/link_protocol.h`: `HEF_TRACK_FRAME_LEN` e `HEF_ACK_FRAME_LEN`
    (tamanho real dos frames no ar, usado pelo cálculo de airtime).
  - Node 1: guard de duty cycle **antes e depois** da TX, intervalo efetivo
    (configurado ∧ mínimo do perfil ∧ mínimo exigido pelo duty cycle),
    jitter de ±10% para dessincronizar a frota, contador `txDenied` e
    comando de console `budget`.
  - Node 2: guard de duty cycle no `sendAck()` (o ACK da base **é uma
    transmissão**), contador `acksDenied`, objeto `rf_budget` em
    `/api/status` e comando de console `budget`.
  - `test_functional.sh`: novo grupo 8/9 (orçamento de RF), que executa
    também `tools/airtime.py --selftest` e verifica estaticamente que os
    parâmetros do firmware são viáveis e que o guard está aplicado no Node 1
    **e** no Node 2.
- **Política de TX adaptativa (item 1.3 do plano).** A transmissão deixa de
  ser periódica e passa a ser **por evento**: a posição alterou mais que
  `LORA_MIN_MOVE_M` (10 m) **ou** passou `LORA_HEARTBEAT_TX_MS` (60 s).
  - `lib/src/tx_policy.h` (novo): `HefTxPolicy` (decisão de TX, com
    Haversine para a distância e jitter do piso via RNG **injetado**) e
    `HefBeaconPolicy` (duty cycle próprio e corte por bateria do beacon FM).
    A referência de posição é a do **último frame reportado** (não a da
    última posição observada): assim, uma transmissão negada **não perde o
    movimento** — ele fica pendente e é reportado na próxima oportunidade.
    `onTxFailed()` reprograma o piso de intervalo para que a re-tentativa
    não vire um flood de log.
  - `tests/tx_policy.cpp` (novo, host): 77 verificações, incluindo os
    casos de aresta: movimento **não perdido** durante o piso de intervalo,
    **movimento pendente preservado quando a TX é negada**, **primeira
    posição válida reportada**, **piso válido antes do primeiro contato**,
    heartbeat com alvo parado, comportamento sem fix GNSS, jitter do piso e
    corte do beacon por bateria.
  - `lib/src/hefestos_pins.h`: `LORA_MIN_MOVE_M`, `LORA_HEARTBEAT_TX_MS`,
    `LORA_TX_MAX_RETRIES`, `FM_BEACON_ON_MS`, `FM_BEACON_OFF_MS`,
    `FM_BEACON_MIN_BATTERY_PCT`.
  - Node 1: loop guiado pela política (movimento/heartbeat), comando
    `policy`, contadores `txEvents`/`txHeartbeats`/`txSuppressed`, e beacon
    FM com duty cycle próprio (3 s ON / 27 s OFF = 10%) e corte automático
    travado abaixo de 20% de bateria (rearm manual por `fm rearm`).
  - `test_functional.sh`: novo grupo 9/10 (política de TX), com verificações
    estáticas de que o Node 1 usa a política adaptativa, que o retry é
    limitado a 1 por evento, que o ACK curto está coerente entre os nós,
    que o contador do emissor **não pode ser reescrito** e que o movimento
    pendente **sobrevive a uma TX negada**.
- **ACK curto (2 bytes).** O payload do ACK passou de 4 bytes para 2:
  byte 0 = flags (`OK` / `DUPLICATE` / `GPS_VALID`), byte 1 = RSSI do frame
  recebido quantizado (−130..−3 dBm). Os 4 bytes anteriores eram
  **redundantes** (repetiam o contador, que já está no cabeçalho — e o
  cabeçalho é autenticado como AAD pelo GCM). O payload de 2 bytes carrega
  informação **nova**: o emissor passa a saber a qualidade do link vista
  pela base. O frame no ar cai de 35 B para 33 B e o airtime do ACK de
  236,0 ms para 225,8 ms (SF8).

### Corrigido

- **Link LoRa fisicamente inviável.** `LORA_SF` 10 → **8** e intervalo de TX
  1 s → **30 s** (`LORA_TX_INTERVAL_MIN_MS`). O duty cycle cai de 221,6%
  para **1,85%** e o consumo de TX de 6,38 Ah/dia para **0,053 Ah/dia**.
  SF8 entrega ainda ≈3× mais alcance que SF10 na mesma potência.
- **Retentativa excessiva.** A v5.0.0 fazia até **3 transmissões por
  evento** (1 original + 2 retries). Agora são no máximo **2**
  (`LORA_TX_MAX_RETRIES = 1`). O retry continua reutilizando o **mesmo**
  `(epoch, counter)`, que a base reconhece como duplicata — o anti-replay
  permanece estrito.
- **Contador de TX alocado dentro da função de envio.** A retransmissão
  reescrevia o contador da sequência para "desfazer" o advance. Agora o
  contador é alocado **uma vez por evento** pelo chamador e repassado à
  retentativa, o que elimina a manipulação do estado da sequência.
- **Contador do emissor podia ser REESCRITO (bug latente que mataria o
  enlace).** O `TxSequence` expunha `setCounter()`, usado pela
  retransmissão para desfazer a alocação. Se a reescrita ocorresse
  **depois** de um frame já ter saído (por exemplo, numa retentativa cuja
  cifragem falhou depois do primeiro envio ter chegado à base), o próximo
  evento reutilizaria um contador que a base **já tinha aceito** — e a
  base rejeitaria um frame legítimo como `REPLAY`, matando o enlace.
  - `setCounter()` foi **removido** de `lib/src/secure_protocol.h`: a
    sequência de contadores é estritamente monotônica. Uma alocação
    desperdiçada apenas abre uma lacuna, que o receptor trata normalmente.
  - `tests/anti_replay_persistence.cpp` demonstra o ciclo completo (a base
    aceita o contador 1, o emissor o reusa, a base **rejeita** o frame com
    `REPLAY`), provando que qualquer reuso de contador é fatal.
  - `test_functional.sh`: verificação estática de que o setter não
    reaparece.
- **Movimento PERDIDO quando a transmissão era negada.** A política
  avançava a referência de posição no instante da **detecção** do
  movimento. Se a TX fosse negada depois (duty cycle, erro de cifragem), o
  evento já tinha sido consumido e a base ficaria com uma posição obsoleta
  — sem nenhum registro do fato. Agora a referência é a do **último frame
  reportado**: o movimento fica **pendente** e é reportado na próxima
  oportunidade. O contador `txSuppressed` torna o caso visível.
- **Flood de log quando a transmissão era negada.** O loop principal chama
  `evaluate()` milhares de vezes por segundo; sem um piso válido, cada
  iteração re-tentaria a TX, incrementando `txDenied` e escrevendo no log
  — um flood que, sozinho, esgota a flash e o buffer da serial.
  `onTxFailed()` reprograma o piso de intervalo, e o piso passou a valer
  **também antes do primeiro contato**.
- **A primeira posição válida podia ficar sem reportar.** Se o nó
  transmissions sem fix (num túnel, por exemplo), a referência ficava
  inválida e a próxima posição válida não era tratada como evento — a
  base ficava sem saber **nenhuma** posição daquele nó. Agora a primeira
  posição válida é reportada imediatamente.
- **GPS poll de 1 Hz — constante morta removida.** `GPS_POLL_INTERVAL_MS`
  (1000 ms) **não** controlava nenhuma leitura do GPS: o Node 1 drena a
  UART do GNSS continuamente no loop e o módulo decide a própria taxa de
  saída. Na prática ela governava o **intervalo de transmissão** do link
  LoRa (hoje `LORA_TX_INTERVAL_MIN_MS` + orçamento de duty cycle). O
  gargalo real era o rádio, que consumia mais que o GNSS. A constante foi
  removida de `lib/src/hefestos_pins.h` — um arquivo que se declara "fonte
  única de verdade" não pode manter uma constante morta e enganosa.
- **Enlace morria após uma queda longa de link.** O salto do contador dentro
  da mesma epoch era comparado com a janela de bits (1024) e rejeitado como
  `FAR` — sem caminho de recuperação. Agora a janela de bits serve apenas
  para contar lacunas e existe um segundo limite (`HEF_COUNTER_MAX_GAP`,
  65536): saltos maiores que a janela reancoram o high-water (frame legítimo
  de um enlace que ficou horas sem réceptionar); acima do limite máximo o
  frame é rejeitado (falha fechada) e o enlace só ressincroniza com um epoch
  novo.
- **Vault: falha fechada em vez de descarte silencioso.** `tlvAppend()`
  devolvia o mesmo `pos` quando o espaço acabava, descartando a entrada
  silenciosamente. Para o estado anti-replay isso seria uma falha de
  segurança (o par perderia o epoch persistido). Agora `save()` e
  `setSecret()` calculam o tamanho antes de escrever e **recusam** a gravação
  se não couber. O limite `HEF_VAULT_MAX_PLAIN` (blob − header − tag GCM)
  passa a ser a referência única, e um teste de host prova que o pior caso
  (todos os campos no máximo + 8 pares) cabe.
- **Vault: o estado anti-replay não regride ao rodar `setSecret()`.**
  `setSecret()` reescreve o TLV a partir do plaintext gravado, que pode estar
  mais velho que o espelho em RAM; agora a entrada `HEF_TLV_PEER_STATE` é
  sempre reescrita a partir do espelho em RAM (a versão mais recente).
- `save()` verifica o retorno da escrita na NVS (`putBytes`).

### Documentado

- README §9.6 (novo): "Política de TX adaptativa (Node 1)" — disparo por
  movimento ou heartbeat, as arestas da política (evento não perdido no
  piso, edge-triggering, ausência de fix), ACK curto, retentativa e beacon
  FM com duty cycle próprio e corte por bateria.
- README §9.5 (novo): "Orçamento de RF e conformidade regulatória" — o que
  estava errado, a configuração adotada, os perfis regionais de referência,
  como o firmware impede a violação e como verificar (console `budget`,
  `/api/status.rf_budget`, `tools/airtime.py`).
- README §3.5.1: estado anti-replay persistido, política de gravação, janela
  residual de 60 s, indicador de migração de vault v5.0.0 e limites do epoch
  de 16 bits.
- README §5.4 (novo): parâmetros de RF do link LoRa (constantes e origem).
- README §2.3, §9.1, §11 e §14 atualizados: duty cycle viabilizado,
  perfis regionais, comandos `budget` e `policy`, 10 grupos de teste
  (+213 verificações no host) e as novas limitações conhecidas.

### Correção de estimativa (documento do plano)

- **O tempo no ar do plano de escala estava errado.** O plano original
  calculava **4564 ms** para SF10/54 B e deduzia **757%** de duty cycle e
  13,2 Ah/dia de TX. A tabela oficial de airtime do **RP002** (LoRaWAN
  Regional Parameters) dá **1312,8 ms** para SF10/54 B. A fórmula correta
  foi validada contra as **9 referências** da tabela oficial
  (SF7/10/12 × 12/51/115 B, erro < 0,001 ms) e contra a lei de
  escalonamento exata `2^ΔSF`.
- Os números reais da v5.0.0 são: **225,7%** de duty cycle e **6,5 Ah/dia**
  de TX (com o ACK de 4 B; com o ACK curto de 2 B da v5.1.0 seriam 221,6%
  e 6,38 Ah/dia). A conclusão do plano (inviável) permanece — o que muda é
  a magnitude, e portanto a urgência da correção. Um duty cycle de 221% ainda
  é fisicamente impossível.
- `tools/airtime.py --selftest` é agora a fonte da verdade da fórmula e está
  wired na suíte de testes, para que uma regressão na conta seja detectada
  automaticamente.

### Validação de bancada pendente

- O aceite do item 1.3 ("≤ 0,5 Ah/dia medido em bancada") **não pode ser
  verificado neste ambiente** (sem hardware). As estimativas de firmware
  cobrem apenas o TX LoRa (0,053 Ah/dia no pior caso). Os consumos
  dominantes — GNSS em tracking contínuo e RX do SX1276 em espera de ACK —
  dependem do item 1.7 (deep sleep).
- O corte de radiação do beacon FM (`PROP_TX_ENABLE`, 0x3E06 do Si4713)
  também precisa de confirmação em bancada: nenhum Si4713 está conectado
  neste ambiente.

---

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
