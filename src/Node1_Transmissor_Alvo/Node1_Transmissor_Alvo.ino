// =====================================================================
// Node 1 - Emissor / Alvo (ESP32-WROOM-32) - Hefestos SIGINT v5.0.0
//
// Emite telemetria de rastreamento (posicao + qualidade do fix) por LoRa
// em frames binarios autenticados (AES-256-GCM).
//
// v5.0.0 - Mudancas relevantes:
//   - Protocolo binario versionado (link_protocol.h) em vez do texto
//     "ALVO_01|lat|lon". Agora carrega epoch UTC, HDOP, altitude, velocidade,
//     curso, satelites, qualidade do fix e nivel de bateria.
//   - Provisionamento de chave por PSK de deploy com HKDF (provisioning.h).
//     Na v4.x cada chip derivava a chave do proprio MAC do efuse, o que
//     tornava IMPOSSIVEL o Node1 e o Node2 falarem (chaves diferentes).
//   - Anti-replay com epoch + contador monotONICO estrito.
//   - Retransmissao com ACK e backoff exponencial (o "CSMA/CA" da v4.x era
//     um parsePacket() que engolia pacotes, nao era sensing algum).
//   - Beacon FM (Si4713) com controle de potencia e sintonia por serial.
// =====================================================================
#include <SPI.h>
#include <LoRa.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <Adafruit_Si4713.h>
#include <Preferences.h>
#include <esp_battery.h>

#include <config.h>
#include <crypto_gcm.h>
#include <debug.h>
#include <hefestos_pins.h>
#include <link_protocol.h>
#include <provisioning.h>
#include <secure_protocol.h>

// ---------------------------------------------------------------------
// Estado global
// ---------------------------------------------------------------------
static ConfigVault vault;
static DebugLogger  dbg;
static AeadGcm      gcm;
static TxSequence   txSeq;

static Preferences seqPrefs;
static uint16_t    nodeId       = 0;
static uint8_t     linkKey[HEF_KEY_LEN];
static bool        keyReady     = false;
static uint8_t     keyId        = 1;

static HardwareSerial gpsSerial(N1_SERIAL_GPS);
static TinyGPSPlus    gps;
static Adafruit_Si4713 fmTx = Adafruit_Si4713(N1_FM_RST);

static uint32_t lastTxMs       = 0;
static uint32_t txCount        = 0;
static uint32_t ackCount       = 0;
static uint32_t retryCount     = 0;
static uint32_t gpsFixCount    = 0;
static uint8_t  lastSeqByte    = 0;

// Beacon FM
static bool     fmBeaconEnabled = false;
static uint16_t fmFreqKHz       = 100100;
static uint8_t  fmPower         = 60;   // 0..255 (Adafruit Si4713)
static uint32_t fmBeaconUntilMs = 0;

// ---------------------------------------------------------------
// Callback de recepcao (ACK do Node2)
// ---------------------------------------------------------------
static volatile uint32_t gAckCounter = 0xFFFFFFFFUL;
static volatile bool      gGotAck    = false;

static void onLoRaReceive(uint8_t* payload, uint16_t length) {
    if (length < HEF_HEADER_LEN + HEF_TAG_LEN) return;
    if (payload[0] != HEF_LINK_MAGIC) return;
    if (payload[1] != HEF_LINK_VERSION) return;
    if (payload[2] != HEF_MSG_TRACK_ACK) return;

    uint16_t ackEpoch = (uint16_t)((payload[5] << 8) | payload[6]);
    uint32_t ackCtr   = ((uint32_t)payload[7] << 24) | ((uint32_t)payload[8] << 16) |
                        ((uint32_t)payload[9] << 8)  | payload[10];
    if (ackEpoch != txSeq.epoch()) return;
    if (ackCtr != txSeq.counter()) return;

    gAckCounter = ackCtr;
    gGotAck = true;
}

// ---------------------------------------------------------------
// Sequencia TX persistida (epoch + contador)
// ---------------------------------------------------------------
static void loadSequence() {
    seqPrefs.begin("hefseq", false);
    uint16_t epoch = 0;
    uint32_t counter = 0;
    seqPrefs.getBytes("epoch", &epoch, sizeof(epoch));
    seqPrefs.getBytes("ctr", &counter, sizeof(counter));

    if (epoch == 0) {
        // Primeiro boot: epoch novo derivado da entropia do hardware.
        epoch = deriveEpoch(nodeId, (uint32_t)millis());
    } else {
        // Boot subsequente: epoch NOVO (o receptor precisa distinguir a
        // nova sessao do emissor de um replay da sessao antiga).
        epoch = deriveEpoch(nodeId, (uint32_t)millis());
    }
    txSeq.begin(epoch, counter);
    seqPrefs.putBytes("epoch", &epoch, sizeof(epoch));
    seqPrefs.putBytes("ctr", &counter, sizeof(counter));
    seqPrefs.end();
    dbg.logf("TX sequence: epoch=%u counter=%u", epoch, counter);
}

static void persistCounter() {
    uint32_t c = txSeq.counter();
    seqPrefs.begin("hefseq", false);
    seqPrefs.putBytes("ctr", &c, sizeof(c));
    seqPrefs.end();
}

// ---------------------------------------------------------------
// Provisionamento de chave
// ---------------------------------------------------------------
static bool applyKeyFromPsk() {
    const uint8_t* psk = vault.getPsk();
    if (!psk) return false;
    if (!deriveNodeKey(psk, HEF_KEY_LEN, nodeId, linkKey, sizeof(linkKey))) return false;
    gcm.setKey(linkKey, sizeof(linkKey));
    keyReady = true;
    return true;
}

// ---------------------------------------------------------------
// Bateria (divisor resistivo em N1_BAT_ADC)
// ---------------------------------------------------------------
static uint8_t readBatteryPct() {
#if defined(ESP32) && !defined(CONFIG_IDF_TARGET_ESP32C3)
    analogReadResolution(12);
    uint32_t raw = analogRead(N1_BAT_ADC);
    // Vbat = raw / 4095 * 3.3 * (R1+R2)/R2 ; assume divisor 2:1 (6.6 V max)
    float volts = (raw / 4095.0f) * 3.3f * 2.0f;
    if (volts <= 3.0f) return 0;
    if (volts >= 4.2f) return 100;
    return (uint8_t)(((volts - 3.0f) / 1.2f) * 100.0f);
#else
    return 255; // desconhecido
#endif
}

// ---------------------------------------------------------------
// Construcao e envio do frame de tracking
// ---------------------------------------------------------------
static bool buildAndSendTrack(uint8_t retry) {
    if (!keyReady) return false;

    gpsValid = gps.location.isValid() && gps.satelliteCount() >= GPS_MIN_SATS &&
               gps.location.age() < GPS_FIX_MAX_AGE_MS &&
               gps.location.age() > 0;

    uint8_t payload[HEF_TRACK_PAYLOAD_LEN];
    uint8_t statusFlags = 0;
    if (gpsValid) statusFlags |= HEF_TRACK_GPS_VALID;
    uint8_t batt = readBatteryPct();
    if (batt != 255 && batt < 20) statusFlags |= HEF_TRACK_LOW_BATTERY;

    uint32_t epochUtc = 0;
    if (gpsValid && gps.time.isValid() && gps.date.isValid()) {
        // Sem NTP no emissor: usa a hora do GNSS quando disponivel.
        struct tm t;
        memset(&t, 0, sizeof(t));
        t.tm_year = gps.date.year() - 1900;
        t.tm_mon  = gps.date.month() - 1;
        t.tm_mday = gps.date.day();
        t.tm_hour = gps.time.hour();
        t.tm_min  = gps.time.minute();
        t.tm_sec  = gps.time.second();
        time_t tt = timegm(&t);
        if (tt > 1704067200) epochUtc = (uint32_t)tt;
    }

    linkPackTrack(payload, epochUtc,
                  gpsValid ? gps.location.lat() : 0.0,
                  gpsValid ? gps.location.lng() : 0.0,
                  (int16_t)(gpsValid ? (int16_t)gps.altitude.meters() : 0),
                  (uint16_t)(gpsValid ? (uint16_t)(gps.speed.mps() * 100.0f) : 0),
                  (uint16_t)(gpsValid ? (uint16_t)gps.course.degrees() : 0),
                  (uint8_t)(gpsValid ? (uint8_t)(gps.hdop.hdop() * 10.0f) : 0),
                  (uint8_t)gps.satelliteCount(),
                  (uint8_t)gps.fixQuality(),
                  batt,
                  statusFlags);

    uint32_t counter = txSeq.next();
    uint8_t hdr[HEF_HEADER_LEN];
    if (!linkBuildHeader(hdr, HEF_MSG_TRACK, statusFlags, keyId,
                         txSeq.epoch(), counter, HEF_TRACK_PAYLOAD_LEN)) {
        return false;
    }

    uint8_t out[HEF_MAX_FRAME];
    memcpy(out, hdr, HEF_HEADER_LEN);
    int ctLen = gcm.encrypt(payload, HEF_TRACK_PAYLOAD_LEN,
                            out + HEF_HEADER_LEN, sizeof(out) - HEF_HEADER_LEN,
                            (uint32_t)(keyId ^ nodeId), counter,
                            hdr, HEF_HEADER_LEN);
    if (ctLen < 0) {
        dbg.logError("AEAD encrypt falhou");
        txSeq.setCounter(counter - 1);
        return false;
    }
    uint16_t frameLen = (uint16_t)(HEF_HEADER_LEN + ctLen);

    // Coloca o radio em RX antes de transmitir: garante que o NOVEIRO
    // interrompa o reception se o frame estiver em curso.
    LoRa.receive();
    delay(2);

    LoRa.beginPacket();
    LoRa.write(out, frameLen);
    LoRa.endPacket();

    txCount++;
    lastTxMs = millis();
    gGotAck = false;

    // Espera ACK (se o Node2 estiver no alcance).
    uint32_t waitStart = millis();
    while (!gGotAck && (millis() - waitStart) < 120) {
        delay(5);
    }
    if (gGotAck) {
        ackCount++;
    } else if (retry < 2) {
        retryCount++;
        uint32_t backoff = (1UL << retry) * 200UL + (esp_random() % 150UL);
        delay(backoff);
        // Reutiliza o MESMO counter (retransmissao e' segura: o
        // receptor detecta duplicidade pelo contador).
        txSeq.setCounter(counter - 1);
        return buildAndSendTrack(retry + 1);
    }
    persistCounter();
    return true;
}

// ---------------------------------------------------------------
// Beacon FM (Si4713)
// ---------------------------------------------------------------
static void fmTune() {
    if (!fmBeaconEnabled) return;
    fmTx.setTXpower(fmPower);
    fmTx.tuneFM((uint16_t)(fmFreqKHz / 10));
}

// ---------------------------------------------------------------
// Console serial (provisionamento e diagnostico)
// ---------------------------------------------------------------
static void printHelp() {
    Serial.println();
    Serial.println("=== HEFESTOS SIGINT v5 - Node1 (Emissor) ===");
    Serial.println("help              esta ajuda");
    Serial.println("status            estado do link");
    Serial.println("id                node_id deste no");
    Serial.println("psk <64 hex>     define o PSK de deploy (32 bytes hex)");
    Serial.println("psk show          mostra se o PSK esta configurado");
    Serial.println("fm on|off        liga/desliga o beacon FM");
    Serial.println("fm freq <kHz>    sintonia do beacon FM");
    Serial.println("fm power <0-255>  potencia do beacon FM");
}

static void handleConsole(char* line) {
    if (strncmp(line, "help", 4) == 0) {
        printHelp();
    } else if (strncmp(line, "status", 6) == 0) {
        Serial.printf("node_id: %u | key: %s\n", nodeId, keyReady ? "OK" : "AUSENTE");
        Serial.printf("epoch: %u | counter: %u\n", txSeq.epoch(), txSeq.counter());
        Serial.printf("TX: %u | ACK: %u | retry: %u\n", txCount, ackCount, retryCount);
        Serial.printf("GPS fix: %u | sats: %u | hdop: %.1f\n",
                      gpsFixCount, (int)gps.satelliteCount(), gps.hdop.hdop());
    } else if (strncmp(line, "id", 2) == 0) {
        Serial.printf("node_id: %u\n", nodeId);
    } else if (strncmp(line, "psk show", 7) == 0) {
        Serial.println(vault.hasPsk() ? "PSK: configurado" : "PSK: ausente");
    } else if (strncmp(line, "psk ", 4) == 0) {
        uint8_t psk[HEF_KEY_LEN];
        int n = hexToBytes(line + 4, psk, sizeof(psk));
        if (n != (int)HEF_KEY_LEN) {
            Serial.println("ERRO: esperado PSK de 64 caracteres hex");
        } else if (!vault.setDeploymentPsk(psk, HEF_KEY_LEN)) {
            Serial.println("ERRO: falha ao gravar o vault");
        } else if (!applyKeyFromPsk()) {
            Serial.println("ERRO: falha na derivacao da chave");
        } else {
            Serial.println("OK: PSK gravado (criptografado no NVS). Reinicie os demais nos.");
        }
        memset(psk, 0, sizeof(psk));
    } else if (strncmp(line, "fm on", 5) == 0) {
        fmBeaconEnabled = true;
        fmTune();
        Serial.println("OK: beacon FM ligado");
    } else if (strncmp(line, "fm off", 6) == 0) {
        fmBeaconEnabled = false;
        Serial.println("OK: beacon FM desligado");
    } else if (strncmp(line, "fm freq", 7) == 0) {
        long f = atol(line + 8);
        if (f >= 87500 && f <= 108000) {
            fmFreqKHz = (uint16_t)f;
            fmTune();
            Serial.printf("OK: FM %.1f MHz\n", fmFreqKHz / 1000.0f);
        } else {
            Serial.println("ERRO: faixa FM invalida (87500..108000 kHz)");
        }
    } else if (strncmp(line, "fm power", 8) == 0) {
        long p = atol(line + 9);
        if (p >= 0 && p <= 255) {
            fmPower = (uint8_t)p;
            fmTune();
            Serial.printf("OK: potencia FM %u\n", fmPower);
        } else {
            Serial.println("ERRO: potencia fora de 0..255");
        }
    } else {
        Serial.println("Comando desconhecido. Use 'help'.");
    }
}

// ---------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    dbg.begin(115200);

    dbg.log("Node1 v5.0.0: inicializando");

    // GPS em UART2 (UART0 fica reservado ao console)
    gpsSerial.begin(9600, SERIAL_8N1, N1_GPS_RX, N1_GPS_TX);

    // Radio LoRa
    LoRa.setPins(N1_LORA_SS, N1_LORA_RST, N1_LORA_DIO0);
    if (!LoRa.begin(LORA_FREQ)) {
        dbg.logError("Falha ao iniciar o LoRa");
    } else {
        LoRa.setSpreadingFactor(LORA_SF);
        LoRa.setSignalBandwidth(LORA_BW);
        LoRa.setTxPower(LORA_TX_POWER);
        LoRa.setSyncWord(0x12);   // canal privado
        LoRa.onReceive(onLoRaReceive);
    }

    // Beacon FM (Si4713)
    Wire.begin(N1_FM_I2C_SDA, N1_FM_I2C_SCL);
    if (fmTx.begin()) {
        fmTx.powerUp();
        fmTune();
        dbg.log("Beacon FM pronto");
    } else {
        dbg.logWarning("Si4713 nao detectado");
    }

    // Vault + chave
    vault.begin();
    nodeId = vault.nodeId();
    keyReady = applyKeyFromPsk();

    loadSequence();

    Serial.println();
    Serial.println("=================================================");
    Serial.println(" HEFESTOS SIGINT v5.0.0 - NODE 1 (EMISSOR)");
    Serial.println("=================================================");
    Serial.printf("node_id: %u\n", nodeId);
    Serial.printf("chave de link: %s\n", keyReady ? "OK" : "AUSENTE - defina o PSK ('psk <64 hex>')");
    Serial.println("=================================================");
    Serial.println();

    printHelp();
}

// ---------------------------------------------------------------------
// Loop
// ---------------------------------------------------------------------
void loop() {
    // Console
    static char cmd[80];
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

    // GPS
    while (gpsSerial.available() > 0) {
        gps.encode(gpsSerial.read());
    }
    if (gps.location.isValid() && gps.location.age() < GPS_FIX_MAX_AGE_MS) {
        gpsFixCount++;
    }

    // Transmissao periodica
    uint32_t now = millis();
    if (now - lastTxMs >= GPS_POLL_INTERVAL_MS) {
        lastTxMs = now;
        if (keyReady) {
            buildAndSendTrack(0);
        } else {
            dbg.logWarning("Transmissao suspensa: sem chave de link");
        }
    }

    // Beacon FM com expiracao
    if (fmBeaconEnabled && fmBeaconUntilMs > 0 && now > fmBeaconUntilMs) {
        fmBeaconUntilMs = 0;
    }
}
