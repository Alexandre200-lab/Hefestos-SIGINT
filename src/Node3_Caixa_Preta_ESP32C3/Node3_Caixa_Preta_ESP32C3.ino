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

#include <hefestos_pins.h>
#include <serial_protocol.h>
#include <link_protocol.h>
#include <field_log.h>
#include <debug.h>

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

// =====================================================================
// Ring buffer de capturas (RAM)
// =====================================================================
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
    DynamicJsonDocument doc(768);
    doc["records"] = fieldLog.recordCount();
    doc["sd"] = sdOk;
    doc["file"] = "HEFLOG.BIN";
    doc["utc"] = lastUtc;
    doc["node_id"] = nodeId;

    char hex[HEF_HASH_LEN * 2 + 1];
    FieldLog::bytesToHexLocal(fieldLog.chainHead(), HEF_HASH_LEN, hex, sizeof(hex));
    doc["chain"] = hex;

    doc["ser_ok"] = serRx.framesOk();
    doc["ser_crc"] = serRx.crcErrors();
    doc["ser_ovf"] = serRx.overflows();

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
                    fieldLog.appendText(HEF_SER_DATA, text);
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
    Serial.println("format         apaga HEFLOG.BIN (perde a cadeia)");
    Serial.println("reboot         reinicia");
}

static void handleConsole(char* line) {
    if (strncmp(line, "help", 4) == 0) {
        printHelp();
    } else if (strncmp(line, "status", 6) == 0) {
        Serial.printf("node_id=%u sd=%s log=%s records=%u caps=%u\n",
                      nodeId, sdOk ? "ok" : "ausente",
                      fieldLog.isOpen() ? "aberto" : "fechado",
                      fieldLog.recordCount(), capCount);
        Serial.printf("frames: data=%u req=%u crc=%u ovf=%u\n",
                      framesData, framesReq, serRx.crcErrors(), serRx.overflows());
        Serial.printf("utc=%u\n", lastUtc);
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
    } else if (strncmp(line, "format", 6) == 0) {
        if (!sdOk) { Serial.println("ERRO: SD indisponivel"); return; }
        if (SD.exists("HEFLOG.BIN")) SD.remove("HEFLOG.BIN");
        if (SD.exists("HEFLOG.JSONL")) SD.remove("HEFLOG.JSONL");
        if (SD.exists("HEFLOG.HASH")) SD.remove("HEFLOG.HASH");
        fieldLog.begin(nodeId, "HEFLOG.BIN");
        Serial.println("OK: log apagado e recriado");
    } else if (strncmp(line, "reboot", 6) == 0) {
        Serial.println("Reiniciando...");
        delay(100);
        ESP.restart();
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
    dbg.log("Node3 v5.0.0: inicializando");

    ledInit();
    buzzerInit();
    setupIdentity();

    // Link com o Node2 em UART1 (UART0 = console).
    node2Serial.begin(115200, SERIAL_8N1, N3_UART_RX, N3_UART_TX);

    if (mountSd()) {
        if (fieldLog.begin(nodeId, "HEFLOG.BIN")) {
            dbg.log("SD montado; log aberto");
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
    Serial.println(" HEFESTOS SIGINT v5.0.0 - NODE 3 (CAIXA PRETA)");
    Serial.println("=================================================");
    Serial.printf("node_id: %u\n", nodeId);
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

    // Re-tentativa de SD (a cada 30 s)
    if (!sdOk && (now - lastSdRetryMs) > 30000UL) {
        lastSdRetryMs = now;
        if (mountSd()) {
            fieldLog.begin(nodeId, "HEFLOG.BIN");
            digitalWrite(N3_LED_RED, LOW);
            dbg.log("SD recuperado");
        }
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
