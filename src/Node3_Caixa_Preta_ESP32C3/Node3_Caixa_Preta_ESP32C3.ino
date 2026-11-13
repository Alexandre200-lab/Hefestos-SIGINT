// =====================================================================
// Node 3 - Caixa Preta Forense (ESP32-C3) - v5.0.0
//
// Funcoes:
//   - Recebe registros do Node2 por UART1 (frames binarios com CRC16).
//   - Grava log append-only com cadeia de hash SHA-256 no cartao SD.
//   - Mantem um ring buffer de capturas em RAM (consultavel pelo Node2).
//   - Responde requisicoes do Node2 (capturas, exportacao, estado).
//   - Sincroniza o relogio UTC pelo Node2 (timestamps absolutos).
//
// v5.0.0 - Correcoes em relacao a v4.x:
//   - Pinagem corrigida: SCK=4 / MISO=5 / MOSI=6 / CS=10. Na v4 o SCK e o
//     LED verde compartilhavam GPIO7 (conflito eletrico real).
//   - SPI.begin(sck, miso, mosi, cs) + SD.begin(cs, SPI, 10 MHz): a v4
//     chamava SD.begin() com assinatura inexistente no core ESP32.
//   - UART1 para o link com o Node2: UART0 fica livre para o console.
//   - Log com hash encadeado + timestamp UTC (a v4 gravava CSV com
//     millis() desde o boot, sem integridade e sem hora absoluta).
//   - Tratamento de requisicoes (a v4 so recebia heartbeats).
//   - Nenhum delay() bloqueante no caminho de dados.
// =====================================================================
#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include <HardwareSerial.h>
#include <ArduinoJson.h>
#include <esp_efuse.h>
#include <esp_system.h>
#include <Preferences.h>

#include <hefestos_pins.h>
#include <serial_protocol.h>
#include <link_protocol.h>
#include <field_log.h>
#include <debug.h>
#include <reset_tracker.h>
#include <watchdog.h>
#include <watchdog_policy.h>

// =====================================================================
// Globais
// =====================================================================
static DebugLogger   dbg;
static FieldLog      fieldLog;
static HefSerialTx   serTx;
static HefSerialRx   serRx;
static HardwareSerial node2Serial(1);   // UART1 -> Node2

static uint16_t nodeId = 0;
static bool     sdOk = false;
static uint32_t lastSdRetryMs = 0;
static uint32_t lastFrameMs = 0;
static uint32_t framesData = 0;
static uint32_t framesReq = 0;
static uint32_t lastUtc = 0;
static uint32_t captureSeq = 0;
static uint32_t logAppendFails = 0;   // registros recusados pelo log (item 1.6)

// =====================================================================
// Ring buffer de capturas (RAM)
// =====================================================================
// A definicao do struct fica ANTES de qualquer definicao de funcao:
// o gerador de prototipos do Arduino Core insere os prototipos no
// ponto da PRIMEIRA definicao de funcao do sketch. Se `struct Capture`
// estivesse depois, o prototipo gerado
// (`static Capture* captureAtAge(uint16_t);`) viria antes do struct e
// o build quebraria com "'Capture' does not name a type".
struct Capture {
    bool     valid;
    uint32_t seq;
    uint32_t utc;
    uint8_t  type;
    uint16_t len;
    char     data[192];
};
static Capture captures[HEF_CAPTURE_RING];
static uint16_t capHead = 0;
static uint16_t capCount = 0;

// =====================================================================
// Causa de reinicio e contadores de operacao (v5.1.0, item 1.4)
// =====================================================================
// A caixa preta e' o dispositivo que MAIS precisa registrar por que
// reiniciou: e' ela que guarda a evidencia. Se ela reinicia em laco por
// brownout, a cadeia de hash do log fica truncada sem que ninguem
// perceba — e a cadeia truncada e' indistinguivel de uma cadeia
// manipulada.
static Preferences     resetPrefs;
static HefResetTracker resetTracker;
static uint8_t         bootResetReason = HEF_RST_UNKNOWN;
static uint8_t         bootIntentKind  = HEF_RESET_INTENT_NONE;

static void persistResetState() {
    uint8_t blob[HEF_RESET_BLOB_LEN];
    resetTracker.exportBlob(blob, sizeof(blob));
    size_t written = resetPrefs.putBytes(HEF_NVS_KEY_RESET, blob,
                                         sizeof(blob));
    if (written == sizeof(blob)) {
        resetTracker.markPersisted();
    } else {
        dbg.logWarning("Falha ao gravar o estado de reinicio na NVS");
    }
}

// Registra a causa do boot e persiste os contadores (quando a guarda de
// desgaste permite).
static uint8_t setupResetTracking() {
    resetPrefs.begin(HEF_NVS_NAMESPACE_RESET, false);

    uint8_t blob[HEF_RESET_BLOB_LEN];
    size_t  n = resetPrefs.getBytes(HEF_NVS_KEY_RESET, blob, sizeof(blob));
    if (n >= HEF_RESET_BLOB_LEN) {
        if (!resetTracker.importBlob(blob, sizeof(blob))) {
            dbg.logWarning("Estado de reinicio invalido: contadores zerados");
        }
    }

    bootResetReason = (uint8_t)esp_reset_reason();
    bool gravar = resetTracker.begin(bootResetReason,
                                     HEF_RESET_PERSIST_EVERY_BOOTS);

    // Le e CONSOME a intencao do reinicio anterior. A sequence tem de
    // bater com o numero deste boot; depois de lida, a intencao e'
    // removida para nao reaparecer nos boots seguintes.
    HefResetIntent intent;
    memset(&intent, 0, sizeof(intent));
    size_t ni = resetPrefs.getBytes(HEF_NVS_KEY_RESET_INTENT, &intent,
                                    sizeof(intent));
    if (ni == sizeof(intent) &&
        hefResetIntentMatches(intent, resetTracker.counters().boots)) {
        bootIntentKind = intent.kind;
        resetPrefs.remove(HEF_NVS_KEY_RESET_INTENT);
    }

    if (gravar) persistResetState();
    return bootResetReason;
}

// Reinicio controlado: a causa fica registrada antes de sair.
static void hefRestart(uint8_t intentKind, uint8_t reason) {
    HefResetIntent intent;
    memset(&intent, 0, sizeof(intent));
    intent.kind     = intentKind;
    intent.reason   = reason;
    intent.sequence = resetTracker.counters().boots + 1;
    resetPrefs.putBytes(HEF_NVS_KEY_RESET_INTENT, &intent, sizeof(intent));

    if (resetTracker.shouldPersistNow()) persistResetState();

    // Toda a evidencia que ja chegou tem de estar no cartao antes de
    // sair: o buffer RAM nao sobrevive a um reinicio (item 1.6).
    if (fieldLog.isOpen()) fieldLog.flush((uint32_t)millis(), true);

    Serial.printf("Reiniciando (intencao=%u, causa=%s)...\n",
                  intentKind, hefResetReasonName(reason));
    Serial.flush();
    delay(50);
    ESP.restart();
}

// =====================================================================
// Progresso das operacoes longas no SD (v5.1.0, item 1.4)
// =====================================================================
// A releitura da cadeia de hash (no boot) e a exportacao JSONL podem
// processar dezenas de milhares de registros. Num SD lento isso leva
// MINUTOS — tempo suficiente para o watchdog de 30 s derrubar o
// dispositivo no meio de uma operacao legitima.
//
// O callback abaixo alimenta o watchdog, mas SO em pontos onde a
// operacao REALMENTE avancou (um registro processado). Se o SD travar
// no meio, o callback deixa de ser chamado e o watchdog expira
// normalmente: o travamento vira um reinicio com causa visivel, em vez
// de ficar mascarado.
static void onLogProgress(void* ctx, uint32_t records) {
    (void)ctx;
    uint32_t now = (uint32_t)millis();
    if (hefWatchdogLongOpStep(now)) {
        dbg.logf("SD: %u registros processados", (unsigned)records);
    }
}

static void pushCapture(uint8_t type, const char* data, uint16_t len) {
    Capture& c = captures[capHead];
    c.valid = true;
    c.seq = ++captureSeq;
    c.utc = lastUtc;
    c.type = type;
    if (len > sizeof(c.data) - 1) len = sizeof(c.data) - 1;
    if (len && data) memcpy(c.data, data, len);
    c.data[len] = 0;
    c.len = len;

    capHead = (uint16_t)((capHead + 1) % HEF_CAPTURE_RING);
    if (capCount < HEF_CAPTURE_RING) capCount++;
}

static Capture* captureAtAge(uint16_t age) {
    if (age >= capCount) return nullptr;
    uint16_t idx = (uint16_t)((capHead + HEF_CAPTURE_RING - 1 - age) % HEF_CAPTURE_RING);
    return &captures[idx];
}

// =====================================================================
// Hardware
// =====================================================================
static void ledInit() {
    pinMode(N3_LED_GREEN, OUTPUT);
    pinMode(N3_LED_RED, OUTPUT);
    digitalWrite(N3_LED_GREEN, LOW);
    digitalWrite(N3_LED_RED, LOW);
}

static void buzzerInit() {
    ledcSetup(0, 2000, 8);
    ledcAttachPin(N3_BUZZER, 0);
    ledcWrite(0, 0);
}

static void beep(uint16_t ms) {
    ledcWrite(0, 80);
    delay(ms);
    ledcWrite(0, 0);
}

static bool mountSd() {
    SPI.begin(N3_SD_SCK, N3_SD_MISO, N3_SD_MOSI, N3_SD_CS);
    if (!SD.begin(N3_SD_CS, SPI, HEF_SD_SPI_HZ)) {
        sdOk = false;
        return false;
    }
    sdOk = true;
    return true;
}

static void setupIdentity() {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    nodeId = (uint16_t)(((uint16_t)mac[4] << 8) | mac[5]);
    if (nodeId == 0) nodeId = 1;
}

// =====================================================================
// Respostas ao Node2
// =====================================================================
static void sendResponse(uint8_t req, const String& json) {
    uint8_t payload[HEF_SER_MAX_PAYLOAD];
    payload[0] = req;

    size_t n = json.length();
    if (n > sizeof(payload) - 1) {
        // Nunca truncar JSON no meio: envia um erro valido.
        const char* err = "{\"error\":\"resposta grande demais\"}";
        n = strlen(err);
        memcpy(payload + 1, err, n);
    } else {
        memcpy(payload + 1, json.c_str(), n);
    }

    uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
    int fl = serTx.encode(HEF_SER_RESPONSE, serTx.nextSeq(),
                          payload, (uint16_t)(n + 1), frame);
    if (fl > 0) node2Serial.write(frame, (size_t)fl);
}

static String buildLogInfo() {
    DynamicJsonDocument doc(2048);
    doc["records"] = fieldLog.recordCount();
    doc["total_records"] = fieldLog.totalRecordCount();
    doc["seq"] = fieldLog.seq();
    doc["sd"] = sdOk;
    doc["file"] = "HEFLOG.BIN";
    doc["utc"] = lastUtc;
    doc["node_id"] = nodeId;

    char hex[HEF_HASH_LEN * 2 + 1];
    FieldLog::bytesToHexLocal(fieldLog.chainHead(), HEF_HASH_LEN, hex, sizeof(hex));
    doc["chain"] = hex;

    // --- Lote, rotacao e saude do cartao (v5.1.0, item 1.6) ---
    // A caixa preta reporta a propria operacao de escrita: um cartao
    // que esta recusando gravacoes (fail closed) ou um buffer que esta
    // perdendo registros precisa ser visivel ANTES de a evidencia
    // faltar.
    doc["pending_bytes"] = (uint32_t)fieldLog.pendingBytes();
    doc["pending_records"] = fieldLog.pendingRecordCount();
    doc["flushes"] = fieldLog.flushCount();
    doc["write_errors"] = fieldLog.writeErrorCount();
    doc["dropped"] = fieldLog.droppedCount();
    doc["retries"] = fieldLog.retryCount();
    doc["append_fails"] = logAppendFails;
    doc["file_bytes"] = fieldLog.fileBytes();
    doc["next_index"] = fieldLog.nextFileIndex();
    doc["archives"] = fieldLog.archiveCount();
    doc["checkpoints"] = fieldLog.checkpointCount();
    doc["log_corrupt"] = fieldLog.isCorrupt();
    doc["log_refusing"] = fieldLog.isRefusing();
    doc["card_full"] = fieldLog.isCardFull();
    doc["flush_bytes"] = HEF_LOG_FLUSH_BYTES;
    doc["flush_ms"] = HEF_LOG_FLUSH_MS;
    doc["writes_per_day"] = HefLogBatch::estimatedFlushesPerDay(
        86400, 143, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);

    const HefSdHealth& h = fieldLog.health();
    JsonObject hd = doc.createNestedObject("health");
    hd["mounted"] = h.mounted;
    hd["writable"] = h.writable;
    hd["total_bytes"] = h.totalBytes;
    hd["used_bytes"] = h.usedBytes;
    hd["free_bytes"] = h.freeBytes;
    hd["note"] = h.note;

    doc["ser_ok"] = serRx.framesOk();
    doc["ser_crc"] = serRx.crcErrors();
    doc["ser_ovf"] = serRx.overflows();

    // --- Causa de reinicio e watchdog (v5.1.0, item 1.4) ---
    // A caixa preta reporta a propria saude de reinicio ao Node2: e'
    // ela que guarda a evidencia, e uma cadeia truncada por reinicio
    // em laco precisa ser visivel para quem investiga.
    const HefResetCounters& rc = resetTracker.counters();
    doc["reset_reason"] = hefResetReasonName(bootResetReason);
    doc["reset_reason_code"] = bootResetReason;
    doc["reset_fault"] = hefResetIsFault(bootResetReason);
    doc["reset_brownout"] = hefResetIsBrownout(bootResetReason);
    doc["boots"] = rc.boots;
    doc["brownouts"] = rc.brownouts;
    doc["wdt_resets"] = rc.wdtResets;
    doc["sw_resets"] = rc.swResets;
    doc["panics"] = rc.panics;
    doc["reset_intent"] = hefResetIntentName(bootIntentKind);
    doc["reset_intent_kind"] = bootIntentKind;
    doc["watchdog_active"] = hefWatchdogActive();
    doc["watchdog_timeout_s"] = hefWatchdogTimeoutS();

    String out;
    serializeJson(doc, out);
    return out;
}

static String buildCaptureLast() {
    DynamicJsonDocument doc(512);
    Capture* c = captureAtAge(0);
    if (!c) {
        doc["count"] = 0;
    } else {
        doc["count"] = capCount;
        doc["seq"] = c->seq;
        doc["utc"] = c->utc;
        doc["type"] = c->type;
        doc["data"] = c->data;
    }
    String out;
    serializeJson(doc, out);
    return out;
}

static String buildCaptureList(uint16_t maxItems) {
    DynamicJsonDocument doc(1200);
    doc["count"] = capCount;
    JsonArray arr = doc.createNestedArray("items");

    if (maxItems > capCount) maxItems = capCount;
    if (maxItems > 4) maxItems = 4;

    for (uint16_t i = 0; i < maxItems; i++) {
        Capture* c = captureAtAge(i);
        if (!c) break;
        JsonObject o = arr.createNestedObject();
        o["seq"] = c->seq;
        o["utc"] = c->utc;
        o["type"] = c->type;
        // Limita o texto para caber em um frame serial de 512 bytes.
        char trunc[44];
        size_t cp = c->len < sizeof(trunc) - 1 ? c->len : sizeof(trunc) - 1;
        memcpy(trunc, c->data, cp);
        trunc[cp] = 0;
        o["data"] = trunc;
    }
    String out;
    serializeJson(doc, out);
    return out;
}

static void handleRequest(uint8_t req) {
    framesReq++;
    switch (req) {
        case HEF_REQ_CAPTURE_LAST:
            sendResponse(req, buildCaptureLast());
            break;
        case HEF_REQ_CAPTURE_LIST:
            sendResponse(req, buildCaptureList(4));
            break;
        case HEF_REQ_CAPTURE_CLEAR:
            capHead = 0;
            capCount = 0;
            memset(captures, 0, sizeof(captures));
            sendResponse(req, "{\"ok\":true,\"count\":0}");
            break;
        case HEF_REQ_LOG_EXPORT: {
            bool integrity = false;
            bool ok = false;
            if (sdOk && fieldLog.isOpen()) {
                ok = fieldLog.exportJsonl("HEFLOG.JSONL", "HEFLOG.HASH", &integrity);
            }
            DynamicJsonDocument doc(256);
            doc["ok"] = ok;
            doc["integrity"] = integrity;
            doc["records"] = fieldLog.recordCount();
            doc["file"] = "HEFLOG.JSONL";
            String out;
            serializeJson(doc, out);
            sendResponse(req, out);
            break;
        }
        case HEF_REQ_LOG_INFO:
            sendResponse(req, buildLogInfo());
            break;
        default:
            sendResponse(req, "{\"error\":\"requisicao desconhecida\"}");
            break;
    }
}

// =====================================================================
// Recepcao do Node2
// =====================================================================
static void onSerialFrame(const HefSerFrame& f, void*) {
    lastFrameMs = millis();

    switch (f.type) {
        case HEF_SER_DATA:
            framesData++;
            if (f.len > 0) {
                char text[193];
                uint16_t n = f.len < sizeof(text) - 1 ? f.len : sizeof(text) - 1;
                memcpy(text, f.payload, n);
                text[n] = 0;

                // Sanitiza para o log/JSON (mantem apenas imprimiveis).
                for (uint16_t i = 0; i < n; i++) {
                    if ((uint8_t)text[i] < 32 || (uint8_t)text[i] > 126) text[i] = '?';
                }

                pushCapture(HEF_SER_DATA, text, n);
                if (sdOk && fieldLog.isOpen()) {
                    if (!fieldLog.appendText(HEF_SER_DATA, text)) {
                        // Buffer cheio, cartao recusando (fail closed) ou
                        // log corrompido. O registro NAO e' perdido em
                        // silencio: o contador aparece em status/info.
                        logAppendFails++;
                    }
                }

                digitalWrite(N3_LED_GREEN, HIGH);
                digitalWrite(N3_LED_GREEN, LOW);
            }
            break;

        case HEF_SER_TIME:
            if (f.len >= 4) {
                uint32_t utc = getU32(f.payload);
                if (utc >= 1704067200UL) {
                    lastUtc = utc;
                    fieldLog.setTime(utc);
                }
            }
            break;

        case HEF_SER_REQUEST:
            if (f.len >= 1) handleRequest(f.payload[0]);
            break;

        case HEF_SER_HEARTBEAT:
            if (f.len >= 4) {
                uint32_t up = getU32(f.payload);
                (void)up;
            }
            break;

        default:
            break;
    }
}

// =====================================================================
// Console serial (UART0)
// =====================================================================
static void printHelp() {
    Serial.println();
    Serial.println("=== HEFESTOS SIGINT v5 - Node3 (Caixa Preta) ===");
    Serial.println("help           esta ajuda");
    Serial.println("status         estado do log/SD/link");
    Serial.println("info           JSON de estado do log");
    Serial.println("caps           lista as ultimas capturas");
    Serial.println("clear          limpa o ring de capturas (RAM)");
    Serial.println("export         exporta o log para JSONL no SD");
    Serial.println("time <unix>    ajusta o relogio UTC");
    Serial.println("archive        forca a rotacao do log atual");
    Serial.println("purge confirm  apaga TODA a evidencia (irreversivel)");
    Serial.println("reboot         reinicia (motivo registrado)");
    Serial.println("resets         causa do reinicio e contadores");
}

static void handleConsole(char* line) {
    if (strncmp(line, "help", 4) == 0) {
        printHelp();
    } else if (strncmp(line, "status", 6) == 0) {
        Serial.printf("node_id=%u sd=%s log=%s records=%u caps=%u\n",
                      nodeId, sdOk ? "ok" : "ausente",
                      fieldLog.isOpen() ? "aberto" : "fechado",
                      fieldLog.recordCount(), capCount);
        Serial.printf("lote: pendente=%u B (%u reg) flushes=%u erros=%u "
                      "perdidos=%u falhas_append=%u\n",
                      (unsigned)fieldLog.pendingBytes(),
                      fieldLog.pendingRecordCount(),
                      fieldLog.flushCount(), fieldLog.writeErrorCount(),
                      fieldLog.droppedCount(), logAppendFails);
        const HefSdHealth& h = fieldLog.health();
        Serial.printf("cartao: %s livre=%u KB total=%u KB (%s)\n",
                      h.writable ? "gravavel" : "NAO gravavel",
                      (unsigned)(h.freeBytes / 1024),
                      (unsigned)(h.totalBytes / 1024), h.note);
        if (fieldLog.isCorrupt()) {
            Serial.println("ALERTA: cadeia marcada como CORROMPIDA "
                           "(fail closed: recusando novas escritas)");
        }
        if (fieldLog.isRefusing()) {
            Serial.println("ALERTA: log recusando registros (cartao cheio "
                           "ou insalubre). Nada e' apagado automaticamente.");
        }
        Serial.printf("frames: data=%u req=%u crc=%u ovf=%u\n",
                      framesData, framesReq, serRx.crcErrors(), serRx.overflows());
        Serial.printf("utc=%u\n", lastUtc);
        Serial.printf("reinicio=%s watchdog=%s (%u s)\n",
                      hefResetReasonName(bootResetReason),
                      hefWatchdogActive() ? "ativo" : "INATIVO",
                      (unsigned)hefWatchdogTimeoutS());
        Serial.printf("motivo do reinicio anterior: %s\n",
                      hefResetIntentName(bootIntentKind));
    } else if (strncmp(line, "resets", 6) == 0) {
        const HefResetCounters& c = resetTracker.counters();
        Serial.printf("causa do boot: %s (%u)\n",
                      hefResetReasonName(bootResetReason), bootResetReason);
        Serial.printf("boots=%u brownouts=%u wdt=%u sw=%u panic=%u\n",
                      (unsigned)c.boots, (unsigned)c.brownouts,
                      (unsigned)c.wdtResets, (unsigned)c.swResets,
                      (unsigned)c.panics);
        Serial.printf("motivo do reinicio anterior: %s\n",
                      hefResetIntentName(bootIntentKind));
    } else if (strncmp(line, "info", 4) == 0) {
        Serial.println(buildLogInfo());
    } else if (strncmp(line, "caps", 4) == 0) {
        Serial.println(buildCaptureList(4));
    } else if (strncmp(line, "clear", 5) == 0) {
        capHead = 0;
        capCount = 0;
        memset(captures, 0, sizeof(captures));
        Serial.println("OK: capturas limpas");
    } else if (strncmp(line, "export", 6) == 0) {
        if (!sdOk || !fieldLog.isOpen()) {
            Serial.println("ERRO: SD indisponivel");
        } else {
            // Operacao longa: alimenta o watchdog durante a exportacao
            // (so em pontos de avanco real).
            hefWatchdogBeginLongOp(hefWatchdogTimeoutS());
            bool integrity = false;
            bool ok = fieldLog.exportJsonl("HEFLOG.JSONL", "HEFLOG.HASH", &integrity);
            Serial.printf("export: %s | integridade: %s | registros: %u\n",
                          ok ? "ok" : "falhou",
                          integrity ? "OK" : "VIOLADA",
                          fieldLog.recordCount());
        }
    } else if (strncmp(line, "time ", 5) == 0) {
        uint32_t u = (uint32_t)strtoul(line + 5, nullptr, 10);
        if (u < 1704067200UL) Serial.println("ERRO: epoch invalido");
        else { lastUtc = u; fieldLog.setTime(u); Serial.println("OK: relogio ajustado"); }
    } else if (strncmp(line, "archive", 7) == 0) {
        if (!sdOk || !fieldLog.isOpen()) {
            Serial.println("ERRO: SD indisponivel");
        } else if (fieldLog.archive((uint32_t)millis())) {
            Serial.printf("OK: log rotacionado (proximo indice=%u)\n",
                          fieldLog.nextFileIndex());
        } else {
            Serial.println("ERRO: rotacao falhou (log continua no arquivo atual)");
        }
    } else if (strncmp(line, "purge", 5) == 0) {
        // Exclusao EXPLICITA. O firmware NUNCA apaga evidencia
        // automaticamente: quando o cartao enche, ele para de aceitar e
        // reporta (fail closed). Apagar exige o comando e a palavra
        // "confirm".
        if (strcmp(line, "purge confirm") != 0) {
            Serial.println("purge apaga TODA a evidencia (logs, manifesto e");
            Serial.println("checkpoints) de forma IRREVERSIVEL.");
            Serial.println("Se tem certeza, digite: purge confirm");
        } else if (!sdOk) {
            Serial.println("ERRO: SD indisponivel");
        } else if (fieldLog.purgeAll()) {
            Serial.println("OK: evidencia apagada; log vazio recriado");
        } else {
            Serial.println("ERRO: purge falhou");
        }
    } else if (strncmp(line, "format", 6) == 0) {
        Serial.println("Comando 'format' removido. Use 'purge confirm' "
                       "(apaga TUDO, irreversivel).");
    } else if (strncmp(line, "reboot", 6) == 0) {
        // Reinicio CONTROLADO: a intencao e' gravada antes de sair, para
        // que o proximo boot nao pareca um travamento inexplicado.
        hefRestart(HEF_RESET_INTENT_USER, HEF_RST_SW);
    } else {
        Serial.println("Comando desconhecido. Use 'help'.");
    }
}

// =====================================================================
// Setup / loop
// =====================================================================
void setup() {
    Serial.begin(115200);
    dbg.begin(115200);
    dbg.log("Node3 v5.1.0: inicializando");

    // --- Causa do reinicio (v5.1.0, item 1.4) ---
    uint8_t reason = setupResetTracking();

    // --- Watchdog de tarefa ---
    // A caixa preta escreve no SD: um travamento no meio de uma
    // gravacao deixa a cadeia de hash truncada SEM AVISO. O watchdog
    // garante que o travamento vire um reinicio com causa visivel.
    HefWatchdogState wdt = hefWatchdogInit();
    if (wdt.active) {
        Serial.printf("watchdog: ativo (timeout %u s%s)\n",
                      (unsigned)wdt.timeoutS,
                      wdt.preInitialized ? ", timeout pre-existente" : "");
    } else {
        Serial.println("watchdog: INATIVO (falha na inicializacao)");
    }

    ledInit();
    buzzerInit();
    setupIdentity();

    // O progresso das operacoes longas no SD alimenta o watchdog.
    fieldLog.setProgressCallback(onLogProgress, nullptr);

    // Link com o Node2 em UART1 (UART0 = console).
    node2Serial.begin(115200, SERIAL_8N1, N3_UART_RX, N3_UART_TX);

    if (mountSd()) {
        // A releitura da cadeia de hash pode levar MINUTOS num log
        // grande (num SD lento). O watchdog e' alimentado durante a
        // operacao, mas SO em pontos de avanco real: um travamento do
        // SD continua sendo detectado.
        hefWatchdogBeginLongOp(hefWatchdogTimeoutS());
        if (fieldLog.begin(nodeId, "HEFLOG.BIN")) {
            dbg.log("SD montado; log aberto");
            // Saude do cartao no boot (item 1.6): teste de escrita/
            // leitura + espaco livre. Cartao cheio = fail closed.
            if (!fieldLog.healthCheck()) {
                dbg.logError("Saude do cartao: teste de escrita FALHOU");
            } else {
                const HefSdHealth& h = fieldLog.health();
                Serial.printf("cartao: %u KB livres de %u KB (%s)\n",
                              (unsigned)(h.freeBytes / 1024),
                              (unsigned)(h.totalBytes / 1024), h.note);
            }
        } else {
            dbg.logError("SD montado, mas o log nao abriu");
        }
    } else {
        dbg.logError("SD nao detectado - operando so em RAM");
        digitalWrite(N3_LED_RED, HIGH);
    }

    beep(120);

    Serial.println();
    Serial.println("=================================================");
    Serial.println(" HEFESTOS SIGINT v5.1.0 - NODE 3 (CAIXA PRETA)");
    Serial.println("=================================================");
    Serial.printf("node_id: %u\n", nodeId);
    Serial.printf("reinicio: %s | boots=%u brownouts=%u wdt=%u sw=%u panic=%u\n",
                  hefResetReasonName(reason),
                  (unsigned)resetTracker.counters().boots,
                  (unsigned)resetTracker.counters().brownouts,
                  (unsigned)resetTracker.counters().wdtResets,
                  (unsigned)resetTracker.counters().swResets,
                  (unsigned)resetTracker.counters().panics);
    if (bootIntentKind != HEF_RESET_INTENT_NONE) {
        Serial.printf("motivo do reinicio anterior: %s\n",
                      hefResetIntentName(bootIntentKind));
    }
    Serial.printf("SD: %s | log: %s | registros: %u\n",
                  sdOk ? "ok" : "ausente",
                  fieldLog.isOpen() ? "aberto" : "fechado",
                  fieldLog.recordCount());
    Serial.println("=================================================");
    printHelp();
}

void loop() {
    uint32_t now = millis();

    // Console
    static char cmd[96];
    static uint8_t cmdLen = 0;
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            cmd[cmdLen] = 0;
            if (cmdLen > 0) handleConsole(cmd);
            cmdLen = 0;
        } else if (cmdLen < sizeof(cmd) - 1) {
            cmd[cmdLen++] = c;
        }
    }

    // Link serial com o Node2
    serRx.feed(node2Serial, onSerialFrame, nullptr);

    // --- Flush do log em LOTES (v5.1.0, item 1.6) ---
    // O buffer so grava quando o gatilho dispara (4 KB ou 30 s). A
    // chamada e' barata quando nao ha nada pendente.
    fieldLog.flush(now);

    // --- Saude do cartao (v5.1.0, item 1.6) ---
    // Teste de escrita/leitura + espaco livre a cada HEF_SD_HEALTH_MS.
    // Cartao cheio = fail closed (para de aceitar, NUNCA apaga).
    static uint32_t lastHealthMs = 0;
    if (sdOk && (now - lastHealthMs >= HEF_SD_HEALTH_MS)) {
        lastHealthMs = now;
        if (!fieldLog.healthCheck()) {
            dbg.logWarning("Saude do cartao: teste de escrita falhou");
        }
    }

    // Re-tentativa de SD (a cada 30 s)
    if (!sdOk && (now - lastSdRetryMs) > 30000UL) {
        lastSdRetryMs = now;
        if (mountSd()) {
            // Releitura da cadeia: operacao longa possivel.
            hefWatchdogBeginLongOp(hefWatchdogTimeoutS());
            fieldLog.begin(nodeId, "HEFLOG.BIN");
            fieldLog.healthCheck();
            digitalWrite(N3_LED_RED, LOW);
            dbg.log("SD recuperado");
        }
    }

    // --- Flush dos contadores de reinicio ---
    // Os contadores que a guarda de desgaste deixou em RAM sao gravados
    // aqui. Sem isso, um dispositivo que reiniciou 9 vezes por brownout
    // (sem completar a janela de 10 boots) perderia a contagem.
    static uint32_t lastResetFlush = 0;
    if (now - lastResetFlush >= HEF_RESET_FLUSH_MS) {
        lastResetFlush = now;
        if (resetTracker.shouldPersistNow()) persistResetState();
    }

    // LED verde: pisca lento enquanto o link estiver vivo
    static uint32_t lastBlink = 0;
    if (now - lastBlink > 2000UL) {
        lastBlink = now;
        bool linkAlive = (lastFrameMs != 0) && ((now - lastFrameMs) < 15000UL);
        digitalWrite(N3_LED_GREEN, linkAlive ? HIGH : LOW);
        digitalWrite(N3_LED_RED, (!sdOk || !linkAlive) ? HIGH : LOW);
    }

    delay(1);
}
