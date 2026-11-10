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

#include <config.h>
#include <crypto_gcm.h>
#include <debug.h>
#include <hefestos_pins.h>
#include <link_protocol.h>
#include <provisioning.h>
#include <secure_protocol.h>
#include <link_budget.h>
#include <band_plan.h>
#include <tx_policy.h>

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
static bool     gpsValid       = false;
static uint32_t txDenied       = 0;   // transmissoes negadas pelo duty budget
static uint32_t txEvents       = 0;   // eventos de movimento
static uint32_t txHeartbeats   = 0;   // heartbeats (alvo parado)
static uint32_t txSuppressed   = 0;   // eventos de movimento sem frame no ar
static uint8_t  lastAckFlags   = 0;   // flags do ultimo ACK recebido
static int16_t  lastAckRssi    = 0;   // RSSI reportado pela base no ACK

// ---------------------------------------------------------------------
// Orcamento de RF (v5.1.0)
// ---------------------------------------------------------------------
// O perfil regional define o limite de duty cycle. O firmware NAO pode
// ultrapassar esse limite: antes de cada transmissao o guard verifica o
// orcamento da janela deslizante de 1 h e, se violar, a transmissao e'
// suspensa (o operador ve o motivo no console).
//
// Alem disso, o intervalo entre ciclos e' derivdo do proprio limite: se
// o perfil exigir (por exemplo, ETSI a 1%), o intervalo e' alongado
// automaticamente ate caber no orcamento.
static const HefBandProfile* band = HefBandPlan::active();
static HefDutyGuard dutyGuard;

// Politica de TX adaptativa (v5.1.0): por EVENTO (movimento) ou por
// HEARTBEAT, sempre respeitando o piso de intervalo e o duty cycle.
static HefTxPolicy txPolicy;

// Politica do beacon FM: duty cycle PROPRIO e corte automatico por
// bateria. O beacon e' um transmissor independente do link LoRa.
static HefBeaconPolicy beaconPolicy;

static HefLinkParams linkParams() {
    HefLinkParams p;
    p.sf = LORA_SF;
    p.bwKHz = 125;
    p.crNum = 4;
    return p;
}

// Tempo no ar do frame de telemetria (ms).
static uint32_t trackAirtimeMs() {
    return HefLinkBudget::airtimeMs(HEF_TRACK_FRAME_LEN, linkParams());
}

// Intervalo efetivo entre ciclos: o maior entre o configurado, o minimo
// do perfil e o intervalo que o duty cycle exige.
static uint32_t effectiveIntervalMs() {
    uint32_t cycle = trackAirtimeMs()
                   + HefLinkBudget::airtimeMs(HEF_ACK_FRAME_LEN, linkParams());
    uint32_t base = LORA_TX_INTERVAL_MIN_MS;
    uint32_t need = HefLinkBudget::minIntervalForDuty(band->dutyLimitPercent, cycle);
    if (need > base) base = need;
    if (base < band->minIntervalMs) base = band->minIntervalMs;
    return base;
}

// Jitter de +/- LORA_TX_JITTER_PCT: dessincroniza a frota (varias
// unidades acordando juntas colidiria no mesmo instante).
//
// Apolitica de TX sorteia o jitter internamente (HefTxPolicy), com a
// fonte de aleatoriedade injetada. Aqui esta' apenas o adaptador para
// o RNG do ESP32.
static uint32_t espRand32() { return (uint32_t)esp_random(); }

// Beacon FM
static bool     fmBeaconEnabled = false;
static uint32_t fmFreqKHz       = 100100;
static uint8_t  fmPower         = 100;  // dBuV (88..115 no Si4713)

// ---------------------------------------------------------------
// Recepcao do ACK do Node2
//
// NOTA: a lib LoRa (Sandeep Mistry) expoe onReceive(void(*)(int)) e
// invoca o callback dentro de parsePacket() (contexto de task, nao ISR).
// A leitura do payload e' feita explicitamente com readBytes().
// ---------------------------------------------------------------
static volatile uint32_t gAckCounter = 0xFFFFFFFFUL;
static volatile bool      gGotAck    = false;

static void processAck(const uint8_t* payload, size_t length) {
    if (length < HEF_HEADER_LEN + HEF_TAG_LEN) return;
    if (payload[0] != HEF_LINK_MAGIC) return;
    if (payload[1] != HEF_LINK_VERSION) return;
    if (payload[2] != HEF_MSG_TRACK_ACK) return;

    uint16_t ackEpoch = (uint16_t)((payload[7] << 8) | payload[8]);
    uint32_t ackCtr   = ((uint32_t)payload[9] << 24) | ((uint32_t)payload[10] << 16) |
                        ((uint32_t)payload[11] << 8)  | payload[12];
    if (ackEpoch != txSeq.epoch()) return;
    if (ackCtr != txSeq.counter()) return;

    // O ACK e' autenticado: so conta se a tag GCM (com a chave do no)
    // for valida. Sem isso, um atacante poderia suprimir retransmissoes.
    if (!keyReady) return;
    uint8_t plain[HEF_ACK_PAYLOAD_LEN];
    AeadGcm ackGcm;
    ackGcm.setKey(linkKey, sizeof(linkKey));
    int pt = ackGcm.decrypt(payload + HEF_HEADER_LEN,
                            length - HEF_HEADER_LEN, plain, sizeof(plain),
                            (uint32_t)nodeId, ackCtr, payload, HEF_HEADER_LEN);
    if (pt < (int)HEF_ACK_PAYLOAD_LEN) return;

    // Payload curto (v5.1.0): flags + RSSI quantizado (-130..-3 dBm).
    lastAckFlags = plain[0];
    int32_t rssi = (int32_t)plain[1] / 2 - 130;
    lastAckRssi  = (int16_t)rssi;

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

    // O epoch e' SEMPRE novo a cada boot (mesmo no primeiro): e' assim que
    // o receptor distingue uma nova sessao do emissor de um replay.
    epoch = deriveEpoch(nodeId, (uint32_t)millis());
    txSeq.begin(epoch, counter);
    seqPrefs.putBytes("epoch", &epoch, sizeof(epoch));
    seqPrefs.putBytes("ctr", &counter, sizeof(counter));
    seqPrefs.end();
    dbg.logf("TX sequence: epoch=%u counter=%u", epoch, counter);
}

// O contador NAO precisa ser persistido a cada frame: o epoch muda a cada
// boot e o receptor reinicia a janela ao ver um epoch novo. Gravar NVS a
// 1 Hz desgastaria a flash sem ganho de seguranca.

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
// Conversao civil -> epoch UTC (sem depender de timegm, que nao existe
// no newlib do ESP32-Arduino 2.0.x).
// Algoritmo de Howard Hinnant (days_from_civil).
// ---------------------------------------------------------------
static uint32_t utcFromCivil(int year, int month, int day,
                             int hour, int minute, int second) {
    if (year < 2024 || month < 1 || month > 12 || day < 1 || day > 31) return 0;

    int y = year - (month <= 2 ? 1 : 0);
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long days = (long)era * 146097L + (long)doe - 719468L;

    long secs = days * 86400L + hour * 3600L + minute * 60L + second;
    if (secs < 1704067200L) return 0;
    return (uint32_t)secs;
}

// ---------------------------------------------------------------
// Construcao e envio do frame de tracking
// ---------------------------------------------------------------
// `counter` e' ALOCADO pelo chamador (uma vez por evento) e REUTILIZADO
// nas retentativas: a retransmissao leva o MESMO (epoch, counter), que
// o receptor reconhece como duplicata. Isso e' seguro e e' o que
// permite o anti-replay estrito do lado da base.
//
// Retentativas: LORA_TX_MAX_RETRIES (1) -> no maximo 2 frames por
// evento. A v5.0.0 fazia ate 3.
//
// `gTxFrameSent` e' zerado pelo chamador antes da chamada e posto em
// `true` no instante em que um frame realmente SAI no ar. E' o que
// permite distinguir "a transmissao foi negada" de "o frame saiu, mas
// o ACK nao chegou" — distincao essencial para contar corretamente
// os eventos de movimento perdidos (ver `txSuppressed`).
//
// `gTxLat`/`gTxLon`/`gTxFixValid` guardam a posicao EXATA que foi
// reportada no frame que saiu. A politica e' atualizada uma unica vez
// por evento, pelo chamador, com esses valores.
static bool     gTxFrameSent = false;
static double   gTxLat       = 0.0;
static double   gTxLon       = 0.0;
static bool     gTxFixValid  = false;
static uint32_t gTxSentMs    = 0;

static bool buildAndSendTrack(uint8_t retry, uint32_t counter) {
    if (!keyReady) return false;

    // --- Orcamento de duty cycle ---
    // A transmissao e' recusada ANTES de gastar energia se violar o
    // limite do perfil regional. Falha fechada: em caso de duvida, nao
    // transmite.
    uint32_t airtime = trackAirtimeMs();
    if (airtime == 0) {
        dbg.logError("Parametros de RF invalidos: transmissao suspensa");
        return false;
    }
    if (!dutyGuard.allows((uint32_t)millis(), airtime, band->dutyLimitPercent)) {
        txDenied++;
        dbg.logf("TX suspensa: duty cycle do perfil %s seria violado (%.2f%%)",
                 band->name, dutyGuard.dutyCyclePercent((uint32_t)millis()));
        return false;
    }

    uint32_t sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
    gpsValid = gps.location.isValid() && sats >= GPS_MIN_SATS &&
               gps.location.age() < GPS_FIX_MAX_AGE_MS;

    uint8_t payload[HEF_TRACK_PAYLOAD_LEN];
    uint8_t statusFlags = 0;
    if (gpsValid) statusFlags |= HEF_TRACK_GPS_VALID;
    uint8_t batt = readBatteryPct();
    if (batt != 255 && batt < 20) statusFlags |= HEF_TRACK_LOW_BATTERY;

    uint32_t epochUtc = 0;
    if (gpsValid && gps.time.isValid() && gps.date.isValid()) {
        // Sem NTP no emissor: usa a hora do GNSS quando disponivel.
        epochUtc = utcFromCivil((int)gps.date.year(), (int)gps.date.month(),
                                (int)gps.date.day(), (int)gps.time.hour(),
                                (int)gps.time.minute(), (int)gps.time.second());
    }

    linkPackTrack(payload, epochUtc,
                  gpsValid ? gps.location.lat() : 0.0,
                  gpsValid ? gps.location.lng() : 0.0,
                  (int16_t)(gpsValid ? (int16_t)gps.altitude.meters() : 0),
                  (uint16_t)(gpsValid ? (uint16_t)(gps.speed.mps() * 100.0f) : 0),
                  (uint16_t)(gpsValid ? (uint16_t)gps.course.deg() : 0),
                  (uint8_t)(gpsValid ? (uint8_t)(gps.hdop.hdop() * 10.0f) : 0),
                  (uint8_t)sats,
                  (uint8_t)(gpsValid ? 1 : 0),
                  batt,
                  statusFlags);

    uint8_t hdr[HEF_HEADER_LEN];
    if (!linkBuildHeader(hdr, HEF_MSG_TRACK, statusFlags, keyId,
                         nodeId, txSeq.epoch(), counter, HEF_TRACK_PAYLOAD_LEN)) {
        return false;
    }

    uint8_t out[HEF_MAX_FRAME];
    memcpy(out, hdr, HEF_HEADER_LEN);
    int ctLen = gcm.encrypt(payload, HEF_TRACK_PAYLOAD_LEN,
                            out + HEF_HEADER_LEN, sizeof(out) - HEF_HEADER_LEN,
                            (uint32_t)nodeId, counter,
                            hdr, HEF_HEADER_LEN);
    if (ctLen < 0) {
        dbg.logError("AEAD encrypt falhou");
        // NAO desfaz a alocacao do contador.
        //
        // O contador e' alocado pelo CHAMADOR e reutilizado nas
        // retentativas. Se uma retentativa falhasse na cifragem e
        // desfizesse a alocacao, o proximo evento reutilizaria um
        // contador que a base JA TINHA ACEITO -> a base rejeitaria um
        // frame legitimo como REPLAY, matando o enlace.
        //
        // A sequencia de contadores deve ser estritamente monotonica.
        // Uma alocacao desperdicada apenas abre uma LACUNA, que o
        // receptor trata normalmente (janela de lacunas + reancoragem
        // por salto acima de HEF_COUNTER_MAX_GAP).
        return false;
    }
    uint16_t frameLen = (uint16_t)(HEF_HEADER_LEN + ctLen);

    // Entra em RX antes de transmitir: habilita o energy sense (RSSI) e
    // permite detectar o ACK imediatamente apos a transmissao.
    LoRa.receive();
    delay(2);

    // Energy sense (aproximado): o registrador RSSI do SX1276 e' valido em
    // modo RX e reflete o ultimo sinal recebido ou o piso de ruido.
    int busy = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        int r = LoRa.rssi();
        if (r <= LORA_CCA_RSSI_DBM) break;
        busy++;
        delay(20 + (esp_random() % 120));
    }

    LoRa.beginPacket();
    LoRa.write(out, frameLen);
    LoRa.endPacket();

    // O airtime e' registrado no orcamento assim que o frame parte.
    dutyGuard.record((uint32_t)millis(), airtime);
    gTxFrameSent = true;
    // A posicao EXATA reportada neste frame (pode diferir da observada
    // no loop, se o GNSS atualizou entre a avaliacao e o envio).
    gTxLat      = gpsValid ? gps.location.lat() : 0.0;
    gTxLon      = gpsValid ? gps.location.lng() : 0.0;
    gTxFixValid = gpsValid;
    gTxSentMs   = (uint32_t)millis();

    // Retoma a recepcao para pegar o ACK.
    LoRa.receive();

    txCount++;
    lastTxMs = millis();
    gGotAck = false;

    // NOTA: a politica de TX NAO e' atualizada aqui. Ela e' atualizada
    // uma unica vez por EVENTO, pelo chamador, depois que a cadeia de
    // retentativas termina. Atualizar aqui re-sortearia o jitter a cada
    // tentativa e marcaria o movimento como reportado mesmo que a
    // retentativa fosse a unica a sair.

    // Espera ACK (se o Node2 estiver no alcance). Janela curta e limitada:
    // o Node1 e' um beacon, nao um servidor.
    uint32_t waitStart = millis();
    while (!gGotAck && (millis() - waitStart) < 150) {
        int ps = LoRa.parsePacket();
        if (ps > 0) {
            uint8_t ackBuf[64];
            int ackLen = LoRa.readBytes(ackBuf, sizeof(ackBuf));
            if (ackLen > 0) processAck(ackBuf, (size_t)ackLen);
        }
        delay(2);
    }
    if (gGotAck) {
        ackCount++;
    } else if (retry < LORA_TX_MAX_RETRIES) {
        retryCount++;
        uint32_t backoff = (1UL << retry) * 200UL + (esp_random() % 150UL);
        delay(backoff);
        // Reutiliza o MESMO counter: a retransmissao e' segura porque o
        // receptor detecta a duplicidade pelo contador e reenvia o ACK
        // sem reprocessar o track.
        return buildAndSendTrack(retry + 1, counter);
    }
    return true;
}

// ---------------------------------------------------------------
// Beacon FM (Si4713)
// ---------------------------------------------------------------
// Propriedades do Si4713 (datasheet). A biblioteca Adafruit expoe
// `setProperty()` (usado com sucesso no powerUp), mas nao define
// estas constantes.
#define SI4713_PROP_TX_ENABLE 0x3E06   // 0 = TX desligado, 1 = ligado

// Liga/desliga a radiacao do beacon. O duty cycle do beacon e' um
// orcamento de ENERGIA (e de espectro): o Si4713 consome dezenas de mA
// enquanto transmite.
static void fmSetRadiating(bool on) {
    fmTx.setProperty(SI4713_PROP_TX_ENABLE, on ? 1 : 0);
}

static void fmTune() {
    if (!fmBeaconEnabled) return;
    fmTx.setTXpower(fmPower);
    fmTx.tuneFM((uint16_t)(fmFreqKHz / 10));   // API em unidades de 10 kHz
}

// Aplica a politica do beacon: duty cycle proprio + corte por bateria.
// Retorna true se o estado de radiacao mudou.
static bool fmApplyPolicy(uint8_t batteryPct) {
    HefBeaconAction action = beaconPolicy.evaluate((uint32_t)millis(),
                                                    fmBeaconEnabled, batteryPct);
    switch (action) {
        case HEF_BEACON_ON:
            fmSetRadiating(true);
            dbg.logf("Beacon FM ligado (fase ON, %u ms)", FM_BEACON_ON_MS);
            return true;
        case HEF_BEACON_OFF:
            fmSetRadiating(false);
            if (beaconPolicy.isPoweredOff()) {
                dbg.logWarning("Beacon FM desligado: bateria abaixo do limite");
            }
            return true;
        default:
            return false;
    }
}

// ---------------------------------------------------------------
// Console serial (provisionamento e diagnostico)
// ---------------------------------------------------------------
static void printHelp() {
    Serial.println();
    Serial.println("=== HEFESTOS SIGINT v5 - Node1 (Emissor) ===");
    Serial.println("help              esta ajuda");
    Serial.println("status            estado do link");
    Serial.println("policy            politica de TX adaptativa e beacon FM");
    Serial.println("budget            orcamento de RF (duty cycle, airtime, perfil)");
    Serial.println("id                node_id deste no");
    Serial.println("psk <64 hex>     define o PSK de deploy (32 bytes hex)");
    Serial.println("psk show          mostra se o PSK esta configurado");
    Serial.println("fm on|off        liga/desliga o beacon FM");
    Serial.println("fm rearm         rearma o corte por bateria do beacon");
    Serial.println("fm freq <kHz>    sintonia do beacon FM");
    Serial.println("fm power <88-115> potencia do beacon FM (dBuV)");
}

static void handleConsole(char* line) {
    if (strncmp(line, "help", 4) == 0) {
        printHelp();
    } else if (strncmp(line, "status", 6) == 0) {
        Serial.printf("node_id: %u | key: %s\n", nodeId, keyReady ? "OK" : "AUSENTE");
        Serial.printf("epoch: %u | counter: %u\n", txSeq.epoch(), txSeq.counter());
        Serial.printf("TX: %u | ACK: %u | retry: %u | negadas: %u\n",
                      txCount, ackCount, retryCount, txDenied);
        Serial.printf("eventos: %u | heartbeats: %u | sem frame no ar: %u\n",
                      txEvents, txHeartbeats, txSuppressed);
        Serial.printf("GPS fix: %u | sats: %u | hdop: %.1f\n",
                      gpsFixCount, (int)(gps.satellites.isValid() ? gps.satellites.value() : 0),
                      gps.hdop.hdop());
        Serial.printf("ACK: flags=0x%02X | rssi base=%d dBm\n",
                      lastAckFlags, (int)lastAckRssi);
    } else if (strncmp(line, "policy", 6) == 0) {
        Serial.printf("TX: movimento > %.0f m OU heartbeat %u s | piso %u s +/- %u%%\n",
                      (double)txPolicy.minMoveM(), txPolicy.heartbeatMs() / 1000,
                      txPolicy.minIntervalMs() / 1000, txPolicy.jitterPct());
        Serial.printf("   ultimo: %u ms | proximo permitido: %u ms | distancia: %.1f m\n",
                      (unsigned)txPolicy.lastTxMs(), (unsigned)txPolicy.nextAllowedMs(),
                      (double)txPolicy.lastDistanceM());
        Serial.printf("beacon FM: %s | duty %.1f%% (%u s on / %u s off) | min bateria %u%%\n",
                      fmBeaconEnabled ? "ligado" : "desligado",
                      (double)beaconPolicy.dutyPercent(),
                      beaconPolicy.onMs() / 1000, beaconPolicy.offMs() / 1000,
                      beaconPolicy.minBatteryPct());
        if (beaconPolicy.isPoweredOff()) {
            Serial.println("   beacon: CORTADO por bateria (use 'fm rearm')");
        }
    } else if (strncmp(line, "budget", 6) == 0) {
        uint32_t track = trackAirtimeMs();
        uint32_t ack   = HefLinkBudget::airtimeMs(HEF_ACK_FRAME_LEN, linkParams());
        uint32_t cycle = track + ack;
        uint32_t iv    = effectiveIntervalMs();
        Serial.printf("perfil: %s (%s)\n", band->name, band->region);
        Serial.printf("faixa: %.3f-%.3f MHz | SF%d BW%u CR%u/%u | EIRP<=%d dBm\n",
                      band->freqMinKHz / 1000.0, band->freqMaxKHz / 1000.0,
                      LORA_SF, linkParams().bwKHz, band->crNum, band->crNum + 1,
                      band->eirpDbmMax);
        Serial.printf("airtime: track=%u ms ack=%u ms ciclo=%u ms\n",
                      track, ack, cycle);
        Serial.printf("intervalo: %u ms | duty: %.3f%% (limite %.1f%%)\n",
                      iv, HefLinkBudget::dutyCyclePercent(cycle, iv),
                      band->dutyLimitPercent);
        float mahCycle = HefLinkBudget::txEnergyMah(cycle, LORA_TX_CURRENT_MA);
        float mahDay   = mahCycle * (86400000.0f / (float)iv);
        Serial.printf("energia TX: %.4f mAh/ciclo | %.3f mAh/dia (%.0f mA)\n",
                      (double)mahCycle, (double)mahDay, (double)LORA_TX_CURRENT_MA);
        Serial.printf("duty na janela de 1h: %.3f%% | transmissoes negadas: %u\n",
                      dutyGuard.dutyCyclePercent((uint32_t)millis()), txDenied);
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
        // Rearma o corte por bateria: o operador pode ter recarregado a
        // unidade. Se a bateria seguir baixa, o corte sera reaplicado
        // na proxima avaliacao.
        beaconPolicy.rearm();
        fmApplyPolicy(readBatteryPct());
        Serial.println("OK: beacon FM ligado (duty cycle proprio aplica-se)");
    } else if (strncmp(line, "fm off", 6) == 0) {
        fmBeaconEnabled = false;
        fmApplyPolicy(readBatteryPct());
        Serial.println("OK: beacon FM desligado");
    } else if (strncmp(line, "fm rearm", 8) == 0) {
        beaconPolicy.rearm();
        fmApplyPolicy(readBatteryPct());
        Serial.println("OK: corte por bateria rearmado");
    } else if (strncmp(line, "fm freq", 7) == 0) {
        long f = atol(line + 8);
        if (f >= 87500 && f <= 108000) {
            fmFreqKHz = (uint32_t)f;
            fmTune();
            Serial.printf("OK: FM %.1f MHz\n", fmFreqKHz / 1000.0f);
        } else {
            Serial.println("ERRO: faixa FM invalida (87500..108000 kHz)");
        }
    } else if (strncmp(line, "fm power", 8) == 0) {
        long p = atol(line + 9);
        if (p >= 88 && p <= 115) {
            fmPower = (uint8_t)p;
            fmTune();
            Serial.printf("OK: potencia FM %u dBuV\n", fmPower);
        } else {
            Serial.println("ERRO: potencia fora de 88..115 dBuV");
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

    dbg.log("Node1 v5.1.0: inicializando");

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

    // Politica de TX adaptativa (v5.1.0):
    //   - dispara por MOVIMENTO acima de LORA_MIN_MOVE_M;
    //   - dispara por HEARTBEAT a cada LORA_HEARTBEAT_TX_MS;
    //   - piso entre transmissoes = intervalo efetivo do duty cycle,
    //     com jitter de +/- LORA_TX_JITTER_PCT (anti-sincronismo).
    txPolicy.configure(LORA_MIN_MOVE_M, LORA_HEARTBEAT_TX_MS,
                       effectiveIntervalMs());
    txPolicy.setJitterPct(LORA_TX_JITTER_PCT);
    txPolicy.setRandomSource(espRand32);

    // Politica do beacon FM: duty cycle PROPRIO e corte por bateria.
    beaconPolicy.configure(FM_BEACON_ON_MS, FM_BEACON_OFF_MS,
                           FM_BEACON_MIN_BATTERY_PCT);

    Serial.println();
    Serial.println("=================================================");
    Serial.println(" HEFESTOS SIGINT v5.1.0 - NODE 1 (EMISSOR)");
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

    // ACK que tenha chegado fora da janela de espera
    int ps = LoRa.parsePacket();
    if (ps > 0) {
        uint8_t ackBuf[64];
        int ackLen = LoRa.readBytes(ackBuf, sizeof(ackBuf));
        if (ackLen > 0) processAck(ackBuf, (size_t)ackLen);
    }

    // GPS
    while (gpsSerial.available() > 0) {
        gps.encode(gpsSerial.read());
    }
    if (gps.location.isValid() && gps.location.age() < GPS_FIX_MAX_AGE_MS) {
        gpsFixCount++;
    }

    uint32_t now = millis();

    // --- Beacon FM: duty cycle PROPRIO + corte automatico por bateria ---
    // O beacon e' um transmissor independente do link LoRa: tem o proprio
    // orcamento de energia e de espectro.
    static uint32_t lastBeaconCheck = 0;
    if (now - lastBeaconCheck >= 1000UL) {
        lastBeaconCheck = now;
        fmApplyPolicy(readBatteryPct());
    }

    // --- Transmissao ADAPTATIVA (v5.1.0) ---
    // Transmite por EVENTO: a posicao alterou mais que LORA_MIN_MOVE_M
    // ou passou LORA_HEARTBEAT_TX_MS. O piso de intervalo (derivado do
    // duty cycle do perfil) e' respeitado pela propria politica.
    uint32_t sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
    bool fixNow = gps.location.isValid() && sats >= GPS_MIN_SATS &&
                  gps.location.age() < GPS_FIX_MAX_AGE_MS;
    double latNow = fixNow ? gps.location.lat() : 0.0;
    double lonNow = fixNow ? gps.location.lng() : 0.0;

    HefTxTrigger trig = txPolicy.evaluate(now, fixNow, latNow, lonNow);
    if (trig == HEF_TX_TRIGGER_MOVE) {
        txEvents++;
        txPolicy.noteTrigger(trig);
        dbg.logf("Evento: alvo se moveu %.1f m", txPolicy.lastDistanceM());
    } else if (trig == HEF_TX_TRIGGER_HEARTBEAT) {
        txHeartbeats++;
        txPolicy.noteTrigger(trig);
    }

    if (trig != HEF_TX_TRIGGER_NONE) {
        if (keyReady) {
            // O contador e' alocado UMA VEZ por evento e reutilizado nas
            // retentativas.
            uint32_t counter = txSeq.next();
            gTxFrameSent = false;
            buildAndSendTrack(0, counter);

            if (gTxFrameSent) {
                // A politica e' atualizada UMA VEZ por evento, com a
                // posicao EXATA que foi reportada no frame que saiu e o
                // instante real do envio (nao o de agora: a cadeia de
                // retentativas pode ter demorado).
                txPolicy.onTransmitted(gTxSentMs, gTxFixValid, gTxLat, gTxLon);
            } else {
                txSuppressed++;
                // O movimento PENDENTE e' preservado pela politica: ele
                // sera reportado na proxima oportunidade. O piso de
                // intervalo e' reprogramado para que a proxima tentativa
                // nao vire um flood de log.
                txPolicy.onTxFailed((uint32_t)millis());
                dbg.logWarning("Evento sem frame no ar: posicao nao reportada");
            }
        } else {
            // Sem chave: avisa, mas nao a cada iteracao do loop.
            static uint32_t lastNoKeyWarn = 0;
            if (now - lastNoKeyWarn >= 5000UL) {
                lastNoKeyWarn = now;
                dbg.logWarning("Transmissao suspensa: sem chave de link");
            }
        }
    }
}
