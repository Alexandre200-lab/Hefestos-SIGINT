// =====================================================================
// Node 2 - Base / Posto de Sensores (ESP32-WROOM-32) - v5.0.0
//
// Funcoes:
//   - Recebe os frames de tracking do Node1 por LoRa (AES-256-GCM).
//   - Mantem estado por par (node_id -> chave derivada por HKDF).
//   - Responde TRACK_ACK autenticado (o Node1 retransmite sem ACK).
//   - Sincroniza o relogio UTC pelo epoch GNSS recebido (TOTP depende disso).
//   - Encaminha cada track para o Node3 (Caixa Preta) por UART2.
//   - Controla o receptor Si4735 (FM/AM/SW) e a varredura de espectro.
//   - Detecta interferencia/jamming por metricas reais de RF.
//   - Serve dashboard/API autenticado (usuario + senha + TOTP).
//
// v5.0.0 - Correcoes em relacao a v4.x:
//   - UART0 reservada ao console; Node3 passou para UART2 (a v4 usava
//     UART0 para o Node3, matando o console e o log de debug).
//   - Telnet removido (texto claro em rede de campo).
//   - Dashboard sem injecao de HTML (a v4 montava String com dados de RF).
//   - Sessoes com expiracao idle/absoluta e binding por IP.
//   - Rate limit por IP e por operacao (login x comandos).
//   - Encaminhamento ao Node3 no loop principal (a v4 nunca enviava).
//   - Varredura de espectro nao-bloqueante com RSSI real do Si4735.
//   - Jamming com estado real (RSSI/SNR/perda de enlace), nao constante.
// =====================================================================
#include <WiFi.h>
#include <sys/time.h>
#include <time.h>
#include <esp_random.h>
#include <esp_efuse.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LoRa.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <SI4735.h>
#include <HardwareSerial.h>
#include <Preferences.h>

#include <hefestos_pins.h>
#include <config.h>
#include <crypto_gcm.h>
#include <debug.h>
#include <link_protocol.h>
#include <provisioning.h>
#include <secure_protocol.h>
#include <peer_state.h>
#include <rate_limiter.h>
#include <totp_auth.h>
#include <radio_si4735.h>
#include <spectrum.h>
#include <jamming_detector.h>
#include <serial_protocol.h>

// =====================================================================
// Objetos globais
// =====================================================================
static ConfigVault  vault;
static DebugLogger  dbg;
static TotpAuth     totp;

static SI4735       si4735;
static HefRadio     radio(si4735);
static SpectrumScanner scanner(radio);
static JammingDetector jam;

static HardwareSerial node3Serial(2);   // UART2 -> Node3
static HefSerialTx    serTx;
static HefSerialRx    serRx;

static AsyncWebServer server(80);

// Prototipos usados antes da definicao (link serial com o Node3).
void hefSendSer(uint8_t type, const uint8_t* data, uint16_t len);
void hefSendTimeToNode3(uint32_t utc);

static RateLimiter loginLimiter(RATE_LOGIN_BUCKET, RATE_LOGIN_WINDOW_MS);
static RateLimiter cmdLimiter(RATE_CMD_BUCKET, RATE_CMD_WINDOW_MS, RATE_CMD_COOLDOWN_MS);

static uint16_t nodeId = 0;
static bool     keyReady = false;
static bool     clockSynced = false;
static bool     autoSweep = false;

// =====================================================================
// Estado por par (node_id remoto)
// =====================================================================
struct PeerState {
    bool      used;
    uint16_t  nodeId;
    uint8_t   keyId;
    uint8_t   key[HEF_KEY_LEN];
    PeerReplayGuard rx;
    HefTrack  last;
    bool      haveTrack;
    uint32_t  lastSeenMs;
    uint32_t  framesOk;
    uint32_t  framesBad;
    uint32_t  replays;
    uint32_t  staleEpochs;
    uint32_t  resyncs;
    int16_t   lastRssi;
    float     lastSnr;
};

static PeerState peers[HEF_MAX_ENROLLMENTS];
static uint32_t loraFramesOk = 0;
static uint32_t loraFramesBad = 0;
static uint32_t loraReplays = 0;
static uint32_t acksSent = 0;

// =====================================================================
// Cache de respostas do Node3 (nao-bloqueante)
// =====================================================================
struct RespCache {
    uint8_t  req;
    bool     valid;
    uint32_t ms;
    char     json[640];
};
static RespCache respCache[4];

static uint32_t serFramesOk = 0;
static uint32_t serDrops = 0;
static uint32_t serLastMs = 0;

// =====================================================================
// Sessoes HTTP
// =====================================================================
struct Session {
    bool     active;
    uint32_t ip;
    char     token[HTTP_TOKEN_HEX_LEN + 1];
    uint32_t createdMs;
    uint32_t lastMs;
};
static Session sessions[HTTP_SESSION_SLOTS];

// Falhas de login por IP
struct LoginFail {
    uint32_t ip;
    uint8_t  count;
    bool     used;
};
static LoginFail loginFails[8];

// =====================================================================
// Utilitarios
// =====================================================================
static uint32_t nowMs() { return (uint32_t)millis(); }

static uint32_t currentUtc() { return (uint32_t)time(nullptr); }

static bool timeLooksValid() { return TotpAuth::clockLooksValid(currentUtc()); }

static void randomHex(char* out, size_t bytes) {
    uint8_t raw[32];
    if (bytes > sizeof(raw)) bytes = sizeof(raw);
    esp_fill_random(raw, bytes);
    bytesToHex(raw, bytes, out, bytes * 2 + 1);
    memset(raw, 0, sizeof(raw));
}

static bool constantTimeStringEq(const char* a, const char* b) {
    if (!a || !b) return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    return hefConstantTimeEq((const uint8_t*)a, (const uint8_t*)b, la);
}

// =====================================================================
// Pares
// =====================================================================
static PeerState* peerByNodeId(uint16_t id) {
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
        if (peers[i].used && peers[i].nodeId == id) return &peers[i];
    }
    return nullptr;
}

static PeerState* peerCreate(uint16_t id, uint8_t keyId,
                             const uint8_t* key, size_t keyLen) {
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
        if (!peers[i].used) {
            memset(&peers[i], 0, sizeof(PeerState));
            peers[i].used = true;
            peers[i].nodeId = id;
            peers[i].keyId = keyId;
            memcpy(peers[i].key, key, keyLen);
            return &peers[i];
        }
    }
    return nullptr;
}

static uint8_t peerCount() {
    uint8_t n = 0;
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) if (peers[i].used) n++;
    return n;
}

static void wipePeers() {
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
        volatile uint8_t* p = peers[i].key;
        for (size_t k = 0; k < sizeof(peers[i].key); k++) p[k] = 0;
        memset(&peers[i], 0, sizeof(PeerState));
    }
}

// Chamada no factory reset: zera as chaves derivadas dos pares em RAM.
static void resetPeers() {
    wipePeers();
    loraFramesOk = loraFramesBad = loraReplays = acksSent = 0;
}

// =====================================================================
// Rehidratacao do estado anti-replay (boot do receptor)
// =====================================================================
// Sem isto, um frame capturado por SDR antes de um reinicio do Node2 seria
// aceito como frame novo: a tabela de pares volta vazia, o par nao tem
// epoch/contador e o RxSequence fica inativo (accept = TOFU).
//
// Os pares sao reconstruidos a partir dos enrollments persistidos no vault
// (a chave de cada par e' derivada de forma DETERMINISTICA do PSK de
// deploy + node_id) e o estado anti-replay e' hidratado do vault cifrado.
static void restorePeerStates() {
    const uint8_t* psk = vault.getPsk();
    if (!psk) return;

    uint8_t n = vault.enrollmentCount();
    for (uint8_t i = 0; i < n; i++) {
        uint16_t nid = 0;
        uint8_t  kid = 0;
        if (!vault.getEnrollment(i, &nid, &kid)) continue;

        PeerState* p = peerByNodeId(nid);
        if (!p) {
            uint8_t key[HEF_KEY_LEN];
            if (!deriveNodeKey(psk, HEF_KEY_LEN, nid, key, sizeof(key))) continue;
            p = peerCreate(nid, kid, key, HEF_KEY_LEN);
            memset(key, 0, sizeof(key));
            if (!p) continue;
        }

        uint16_t epoch = 0;
        uint32_t ctr   = 0;
        if (vault.getPeerState(nid, &epoch, &ctr)) {
            p->rx.hydrate(epoch, ctr);
            dbg.logf("Par %u reidratado: epoch=%u counter=%u",
                     nid, epoch, (unsigned)ctr);
        } else {
            // Par enrolled sem estado anti-replay (migracao de um vault
            // v5.0.0). O primeiro frame valido sera aceito por TOFU e
            // persistido; a partir dai o replay pos-reboot e' bloqueado.
            dbg.logf("Par %u sem estado anti-replay (migracao)", nid);
        }
    }
}

// =====================================================================
// Persistencia do estado anti-replay
// =====================================================================
// Grava no vault (RAM + flash) o estado (epoch + high-water) de todos os
// pares que avancaram desde a ultima gravacao.
// Retorna true se houve gravacao e ela foi bem-sucedida.
static bool persistPeerStates() {
    bool dirty = false;
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
        if (!peers[i].used) continue;
        if (!peers[i].rx.isDirty()) continue;
        vault.putPeerState(peers[i].nodeId, peers[i].rx.epoch(),
                           peers[i].rx.highest());
        dirty = true;
    }
    if (!dirty) return false;

    if (!vault.save()) {
        dbg.logWarning("Falha ao gravar o estado anti-replay no vault");
        return false;   // as flags continuam sujas: tenta de novo
    }
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
        if (peers[i].used) peers[i].rx.clearPersistFlags();
    }
    return true;
}

// =====================================================================
// Link LoRa
// =====================================================================
static void sendAck(const PeerState* peer, uint16_t epoch, uint32_t counter) {
    if (!peer) return;

    uint8_t hdr[HEF_HEADER_LEN];
    uint8_t payload[4];
    putU32(payload, counter);

    if (!linkBuildHeader(hdr, HEF_MSG_TRACK_ACK, 0, peer->keyId,
                         nodeId, epoch, counter, sizeof(payload))) {
        return;
    }

    uint8_t out[HEF_MAX_FRAME];
    memcpy(out, hdr, HEF_HEADER_LEN);

    AeadGcm gcm;
    gcm.setKey(peer->key, HEF_KEY_LEN);
    int ctLen = gcm.encrypt(payload, sizeof(payload),
                            out + HEF_HEADER_LEN, sizeof(out) - HEF_HEADER_LEN,
                            (uint32_t)peer->nodeId, counter,
                            hdr, HEF_HEADER_LEN);
    if (ctLen < 0) return;

    LoRa.beginPacket();
    LoRa.write(out, (size_t)(HEF_HEADER_LEN + ctLen));
    LoRa.endPacket();
    LoRa.receive();
    acksSent++;
}

static void applyTrackTime(const HefTrack& t) {
    if (t.epochUtc < 1704067200UL) return;   // antes de 2024: invalido

    time_t sysNow = time(nullptr);
    long long delta = (long long)t.epochUtc - (long long)sysNow;
    if (delta < 0) delta = -delta;
    if (delta <= 2) { clockSynced = true; return; }

    struct timeval tv;
    tv.tv_sec  = (time_t)t.epochUtc;
    tv.tv_usec = 0;
    settimeofday(&tv, nullptr);
    clockSynced = true;

    // Propaga o tempo ao Node3 (log forense com UTC absoluto).
    hefSendTimeToNode3(t.epochUtc);
    dbg.logf("Relogio sincronizado pelo GNSS: utc=%u", t.epochUtc);
}

static void forwardTrackToNode3(const PeerState* peer, const HefTrack& t,
                                int16_t rssi, float snr) {
    char rec[192];
    snprintf(rec, sizeof(rec),
             "T,%u,%u,%.7f,%.7f,%d,%u,%u,%u,%u,%u,%u,%u,%d,%.1f",
             peer->nodeId, t.epochUtc,
             t.lat, t.lon, (int)t.altM,
             (unsigned)t.speedCms, (unsigned)t.courseDeg,
             (unsigned)t.hdopX10, (unsigned)t.sats,
             (unsigned)t.fixQuality, (unsigned)t.batteryPct,
             (unsigned)t.statusFlags, (int)rssi, (double)snr);
    hefSendSer(HEF_SER_DATA, (const uint8_t*)rec, (uint16_t)strlen(rec));
}

static void processTrack(const uint8_t* frame, uint16_t frameLen,
                         int16_t rssi, float snr) {
    if (frameLen < HEF_HEADER_LEN + HEF_TAG_LEN) { loraFramesBad++; return; }
    if (!linkHeaderValid(frame, frameLen)) { loraFramesBad++; return; }

    uint8_t  type   = frame[2];
    uint8_t  keyId  = frame[4];
    uint16_t src    = getU16(frame + 5);
    uint16_t epoch  = getU16(frame + 7);
    uint32_t ctr    = getU32(frame + 9);
    uint16_t plen   = getU16(frame + 13);

    if (type != HEF_MSG_TRACK) return;
    if (plen != HEF_TRACK_PAYLOAD_LEN) { loraFramesBad++; return; }
    if (src == 0 || src == nodeId) return;   // nao aceita eco do proprio no

    PeerState* peer = peerByNodeId(src);
    uint8_t derived[HEF_KEY_LEN];
    bool derivedOk = false;

    if (!peer) {
        const uint8_t* psk = vault.getPsk();
        if (!psk) { loraFramesBad++; return; }
        if (!deriveNodeKey(psk, HEF_KEY_LEN, src, derived, sizeof(derived))) {
            loraFramesBad++;
            return;
        }
        derivedOk = true;
    }

    AeadGcm gcm;
    gcm.setKey(peer ? peer->key : derived, HEF_KEY_LEN);

    uint8_t plain[HEF_MAX_PAYLOAD];
    int ptLen = gcm.decrypt(frame + HEF_HEADER_LEN, frameLen - HEF_HEADER_LEN,
                            plain, sizeof(plain), (uint32_t)src, ctr,
                            frame, HEF_HEADER_LEN);

    if (ptLen != HEF_TRACK_PAYLOAD_LEN) {
        if (derivedOk) memset(derived, 0, sizeof(derived));
        if (peer) peer->framesBad++;
        loraFramesBad++;
        return;
    }

    // Autenticado: cria o par (TOFU com prova de posse do PSK de deploy).
    if (!peer) {
        peer = peerCreate(src, keyId, derived, HEF_KEY_LEN);
        memset(derived, 0, sizeof(derived));
        if (!peer) { loraFramesBad++; return; }
        vault.enrollNode(src, keyId);
    }

    uint32_t lost = 0;
    uint32_t resyncsBefore = peer->rx.resyncs();
    LinkRxResult res = peer->rx.accept(epoch, ctr, &lost);
    if (res != LINK_RX_ACCEPT) {
        // Duplicata da ULTIMA transmissao: o Node1 reenvia com o MESMO
        // contador quando o ACK se perde. Reenviamos o ACK, mas NAO
        // reprocessamos o track (anti-replay preservado).
        if (res == LINK_RX_REPLAY && ctr == peer->rx.highest()) {
            sendAck(peer, epoch, ctr);
            return;
        }
        peer->replays++;
        loraReplays++;
        if (res == LINK_RX_STALE_EPOCH) {
            // Epoch anterior ao estado conhecido: e' o replay pos-reboot
            // (o frame capturado antes do reinicio do receptor).
            peer->staleEpochs++;
            dbg.logf("REPLAY pos-reboot bloqueado: node=%u epoch=%u (conhecido %u)",
                     src, epoch, peer->rx.epoch());
        }
        return;
    }

    if (peer->rx.resyncs() != resyncsBefore) {
        // Salto grande do contador dentro da mesma epoch: o enlace havia
        // ficado sem receptionar frames. Evento de seguranca relevante
        // (pode indicar captura/replay de um frame distante).
        peer->resyncs++;
        dbg.logf("Reancoragem de sequencia: node=%u epoch=%u counter=%u",
                 src, epoch, (unsigned)ctr);
    }

    HefTrack t;
    linkUnpackTrack(plain, &t);

    peer->last = t;
    peer->haveTrack = true;
    peer->lastSeenMs = nowMs();
    peer->lastRssi = rssi;
    peer->lastSnr = snr;
    peer->framesOk++;
    loraFramesOk++;

    jam.onPacket(rssi, snr, nowMs());
    applyTrackTime(t);
    forwardTrackToNode3(peer, t, rssi, snr);
    sendAck(peer, epoch, ctr);

    // --- Estado anti-replay: persistencia ---
    // O estado (epoch + high-water) e' a defesa contra replay pos-reboot.
    // Mudanca de epoch (novo boot do emissor) e' gravada IMEDIATAMENTE;
    // o contador avanca e' gravado no flush periodico.
    vault.putPeerState(src, peer->rx.epoch(), peer->rx.highest());
    if (peer->rx.needsImmediatePersist()) {
        persistPeerStates();
    }

    dbg.logf("TRACK node=%u ctr=%u lost=%u rssi=%d snr=%.1f",
             src, (unsigned)ctr, (unsigned)lost, (int)rssi, (double)snr);
}

// =====================================================================
// Fila de TX serial (Node2 -> Node3), nao-bloqueante
// =====================================================================
class SerQueue {
private:
    static const uint16_t CAP = 2048;
    uint8_t  buf_[CAP];
    uint16_t head_;
    uint16_t tail_;
    uint16_t count_;

public:
    SerQueue() : head_(0), tail_(0), count_(0) {}

    bool push(const uint8_t* d, uint16_t n) {
        if (!d || n == 0) return true;
        if (n > (uint16_t)(CAP - count_)) return false;
        for (uint16_t i = 0; i < n; i++) {
            buf_[tail_] = d[i];
            tail_ = (uint16_t)((tail_ + 1) % CAP);
        }
        count_ = (uint16_t)(count_ + n);
        return true;
    }

    void pump(Stream& s) {
        while (count_ > 0) {
            int space = s.availableForWrite();
            if (space <= 0) break;
            s.write(buf_[head_]);
            head_ = (uint16_t)((head_ + 1) % CAP);
            count_--;
        }
    }

    uint16_t pending() const { return count_; }
};

static SerQueue serQueue;

void hefSendSer(uint8_t type, const uint8_t* data, uint16_t len) {
    uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
    int n = serTx.encode(type, serTx.nextSeq(), data, len, frame);
    if (n <= 0 || !serQueue.push(frame, (uint16_t)n)) serDrops++;
}

void hefSendTimeToNode3(uint32_t utc) {
    uint8_t tb[4];
    putU32(tb, utc);
    hefSendSer(HEF_SER_TIME, tb, sizeof(tb));
}

// Resposta do Node3 -> cache
static void onNode3Frame(const HefSerFrame& f, void*) {
    serLastMs = nowMs();
    serFramesOk++;

    if (f.type != HEF_SER_RESPONSE || f.len < 1) return;

    uint8_t req = f.payload[0];
    RespCache* slot = nullptr;
    for (uint8_t i = 0; i < 4; i++) {
        if (respCache[i].valid && respCache[i].req == req) { slot = &respCache[i]; break; }
    }
    if (!slot) {
        for (uint8_t i = 0; i < 4; i++) {
            if (!respCache[i].valid) { slot = &respCache[i]; break; }
        }
    }
    if (!slot) slot = &respCache[0];

    slot->req = req;
    slot->valid = true;
    slot->ms = nowMs();
    uint16_t n = (uint16_t)(f.len - 1);
    if (n > sizeof(slot->json) - 1) n = sizeof(slot->json) - 1;
    memcpy(slot->json, f.payload + 1, n);
    slot->json[n] = 0;
}

static void requestNode3(uint8_t req) {
    uint8_t b = req;
    hefSendSer(HEF_SER_REQUEST, &b, 1);
}

static const RespCache* cachedResponse(uint8_t req) {
    for (uint8_t i = 0; i < 4; i++) {
        if (respCache[i].valid && respCache[i].req == req) return &respCache[i];
    }
    return nullptr;
}

// =====================================================================
// Sessoes / autenticacao
// =====================================================================
static Session* sessionByToken(const char* token) {
    if (!token || !token[0]) return nullptr;
    uint32_t now = nowMs();
    for (uint8_t i = 0; i < HTTP_SESSION_SLOTS; i++) {
        Session& s = sessions[i];
        if (!s.active) continue;
        if ((now - s.lastMs) > HTTP_SESSION_IDLE_MS ||
            (now - s.createdMs) > HTTP_SESSION_ABSOLUTE_MS) {
            memset(&s, 0, sizeof(s));
            continue;
        }
        if (constantTimeStringEq(s.token, token)) return &s;
    }
    return nullptr;
}

static Session* createSession(uint32_t ip) {
    uint32_t now = nowMs();
    Session* slot = nullptr;
    for (uint8_t i = 0; i < HTTP_SESSION_SLOTS; i++) {
        if (!sessions[i].active) { slot = &sessions[i]; break; }
    }
    if (!slot) {
        // Substitui a sessao mais antiga (menor lastMs).
        slot = &sessions[0];
        for (uint8_t i = 1; i < HTTP_SESSION_SLOTS; i++) {
            if (sessions[i].lastMs < slot->lastMs) slot = &sessions[i];
        }
    }
    memset(slot, 0, sizeof(Session));
    slot->active = true;
    slot->ip = ip;
    slot->createdMs = now;
    slot->lastMs = now;
    randomHex(slot->token, HTTP_TOKEN_HEX_LEN / 2);
    return slot;
}

static void destroySession(const char* token) {
    for (uint8_t i = 0; i < HTTP_SESSION_SLOTS; i++) {
        if (sessions[i].active && constantTimeStringEq(sessions[i].token, token)) {
            memset(&sessions[i], 0, sizeof(sessions[i]));
        }
    }
}

static bool getCookie(AsyncWebServerRequest* r, const char* name,
                      char* out, size_t cap) {
    if (!r || !r->hasHeader("Cookie")) return false;
    const AsyncWebHeader* h = r->getHeader("Cookie");
    if (!h) return false;
    String v = h->value();
    String key = String(name) + "=";
    int idx = v.indexOf(key);
    // O nome do cookie precisa comecar um "campo" do cabecalho Cookie,
    // senao "XHEF_SID=" casaria com "HEF_SID=".
    while (idx >= 0) {
        if (idx == 0 || v[idx - 1] == ';' || v[idx - 1] == ' ' ||
            v[idx - 1] == '\t') break;
        idx = v.indexOf(key, idx + 1);
    }
    if (idx < 0) return false;
    int start = idx + key.length();
    int end = v.indexOf(';', start);
    if (end < 0) end = v.length();
    String tok = v.substring(start, end);
    tok.trim();
    if (tok.length() == 0 || tok.length() >= cap) return false;
    strncpy(out, tok.c_str(), cap - 1);
    out[cap - 1] = 0;
    return true;
}

static Session* authedSession(AsyncWebServerRequest* r) {
    char token[HTTP_TOKEN_HEX_LEN + 1];
    if (!getCookie(r, "HEF_SID", token, sizeof(token))) return nullptr;
    Session* s = sessionByToken(token);
    if (!s) return nullptr;
    if (s->ip != ipToKey(r->client()->remoteIP())) return nullptr;
    s->lastMs = nowMs();
    return s;
}

static void sendUnauthorized(AsyncWebServerRequest* r) {
    r->send(401, "application/json", "{\"error\":\"nao autenticado\"}");
}

static void sendJson(AsyncWebServerRequest* r, int code, const String& body) {
    r->send(code, "application/json", body);
}

// =====================================================================
// Rate limit de login
// =====================================================================
static uint8_t registerLoginFailure(uint32_t ip) {
    for (uint8_t i = 0; i < 8; i++) {
        if (loginFails[i].used && loginFails[i].ip == ip) {
            if (loginFails[i].count < 255) loginFails[i].count++;
            return loginFails[i].count;
        }
    }
    for (uint8_t i = 0; i < 8; i++) {
        if (!loginFails[i].used) {
            loginFails[i].used = true;
            loginFails[i].ip = ip;
            loginFails[i].count = 1;
            return 1;
        }
    }
    return MAX_AUTH_ATTEMPTS;
}

static void clearLoginFailures(uint32_t ip) {
    for (uint8_t i = 0; i < 8; i++) {
        if (loginFails[i].used && loginFails[i].ip == ip) {
            loginFails[i].used = false;
            loginFails[i].count = 0;
        }
    }
}

// =====================================================================
// Provisionamento inicial de credenciais (console)
// =====================================================================
static void ensureCredentials() {
    char buf[64];

    if (!vault.getCliUsername(buf, sizeof(buf))) {
        vault.setCliUsername("admin");
        dbg.log("Usuario CLI/HTTP criado: admin");
    }

    if (!vault.getCliPassword(buf, sizeof(buf))) {
        char pass[33];
        randomHex(pass, 12);
        vault.setCliPassword(pass);
        Serial.println();
        Serial.println("=================================================");
        Serial.println(" CREDENCIAL INICIAL GERADA (anote e troque)");
        Serial.print("   usuario: admin");
        Serial.print("   senha:   "); Serial.println(pass);
        Serial.println("=================================================");
        memset(pass, 0, sizeof(pass));
    }

    size_t tlen = HEF_TOTP_SECRET_MAX;
    uint8_t tsec[HEF_TOTP_SECRET_MAX];
    if (vault.getTotpSecret(tsec, &tlen)) {
        // Segredo persistido como base32 textual.
        char b32[HEF_TOTP_SECRET_MAX + 1];
        size_t cp = tlen < sizeof(b32) - 1 ? tlen : sizeof(b32) - 1;
        memcpy(b32, tsec, cp);
        b32[cp] = 0;
        totp.setSecretBase32(b32);
        memset(tsec, 0, sizeof(tsec));
        memset(b32, 0, sizeof(b32));
    }

    if (!totp.hasSecret()) {
        // Fallback: gera e persiste em base32.
        totp.generateRandomSecret(20);
        char b32[64];
        totp.exportBase32(b32, sizeof(b32));
        vault.setTotpSecret((const uint8_t*)b32, strlen(b32));
        char uri[192];
        totp.buildOtpAuthUri(uri, sizeof(uri), "Hefestos", "admin");
        Serial.println();
        Serial.println("=================================================");
        Serial.println(" 2FA TOTP - cadastre no autenticador AGORA");
        Serial.print("   segredo base32: "); Serial.println(b32);
        Serial.print("   URI otpauth:    "); Serial.println(uri);
        Serial.println("=================================================");
        memset(b32, 0, sizeof(b32));
    }
}

// =====================================================================
// WiFi
// =====================================================================
static void deriveApPassword(char* out, size_t cap) {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    const uint8_t info[] = "hefestos-v5/ap/wpa2";
    uint8_t okm[16];
    hefHkdfSha256(mac, sizeof(mac), nullptr, 0, info, sizeof(info) - 1,
                  okm, sizeof(okm));
    bytesToHex(okm, 8, out, cap);   // 16 hex chars
    memset(okm, 0, sizeof(okm));
}

static bool startNetwork() {
    char ssid[33], pass[33];
    bool haveSta = vault.getWifiSsid(ssid, sizeof(ssid)) &&
                   vault.getWifiPassword(pass, sizeof(pass));

    if (haveSta) {
        WiFi.mode(WIFI_STA);
        WiFi.setSleep(false);
        WiFi.begin(ssid, pass);
        uint32_t start = nowMs();
        while (WiFi.status() != WL_CONNECTED && (nowMs() - start) < 15000UL) {
            delay(200);
        }
        memset(pass, 0, sizeof(pass));
        if (WiFi.status() == WL_CONNECTED) {
            Serial.print("WiFi STA conectado. IP: ");
            Serial.println(WiFi.localIP());
            return true;
        }
        Serial.println("WiFi STA falhou; caindo para SoftAP.");
    }

    char apPass[33];
    deriveApPassword(apPass, sizeof(apPass));
    char apSsid[33];
    snprintf(apSsid, sizeof(apSsid), "HEFESTOS-%u", (unsigned)nodeId);

    WiFi.mode(WIFI_AP);
    WiFi.setSleep(false);
    bool ok = WiFi.softAP(apSsid, apPass);
    memset(apPass, 0, sizeof(apPass));

    Serial.println();
    Serial.println("=================================================");
    Serial.println(" REDE DE CAMPO (SoftAP WPA2)");
    Serial.print("   SSID: "); Serial.println(apSsid);
    deriveApPassword(apPass, sizeof(apPass));
    Serial.print("   senha: "); Serial.println(apPass);
    memset(apPass, 0, sizeof(apPass));
    Serial.print("   IP:    "); Serial.println(WiFi.softAPIP());
    Serial.println("=================================================");
    return ok;
}

// =====================================================================
// JSON
// =====================================================================
static const char* wifiModeName() {
    wifi_mode_t m = WiFi.getMode();
    if (m == WIFI_AP) return "AP";
    if (m == WIFI_STA) return "STA";
    return "MISTO";
}

static String jsonStatus() {
    DynamicJsonDocument doc(2048);
    doc["node_id"] = nodeId;
    doc["fw"] = HEF_FW_VERSION_STR;
    doc["uptime_s"] = (uint32_t)(nowMs() / 1000UL);

    JsonObject w = doc.createNestedObject("wifi");
    w["mode"] = wifiModeName();
    w["ip"] = (WiFi.getMode() == WIFI_AP) ? WiFi.softAPIP().toString()
                                          : WiFi.localIP().toString();
    w["rssi"] = WiFi.RSSI();

    JsonObject t = doc.createNestedObject("time");
    t["utc"] = currentUtc();
    t["synced"] = clockSynced && timeLooksValid();

    JsonObject l = doc.createNestedObject("lora");
    l["frames_ok"] = loraFramesOk;
    l["frames_bad"] = loraFramesBad;
    l["replays"] = loraReplays;
    l["acks_sent"] = acksSent;
    l["peers"] = peerCount();
    l["key"] = keyReady ? "ok" : "ausente";

    JsonObject r = doc.createNestedObject("radio");
    r["band"] = HefRadio::bandName(radio.band());
    r["freq_khz"] = radio.freqKHz();
    r["initialized"] = radio.isInitialized();

    JsonObject j = doc.createNestedObject("jamming");
    uint32_t now = nowMs();
    j["state"] = JammingDetector::stateName(jam.state(now));
    j["median_snr"] = jam.medianSnr();
    j["median_rssi_dbm"] = jam.medianRssiDbm();
    j["noise_floor_dbuV"] = jam.noiseFloorDbuV();
    j["last_packet_age_ms"] = jam.lastPacketAgeMs(now);

    JsonObject s = doc.createNestedObject("spectrum");
    s["running"] = scanner.isRunning();
    s["samples"] = scanner.sampleCount();
    s["last_sweep_ms"] = scanner.lastSweepMs();
    s["auto"] = autoSweep;

    JsonObject n3 = doc.createNestedObject("node3");
    n3["frames_ok"] = serFramesOk;
    n3["crc_errors"] = serRx.crcErrors();
    n3["drops"] = serDrops;
    n3["queue"] = serQueue.pending();
    n3["last_age_ms"] = serLastMs ? (now - serLastMs) : 0;

    uint8_t activeSessions = 0;
    for (uint8_t i = 0; i < HTTP_SESSION_SLOTS; i++) if (sessions[i].active) activeSessions++;
    doc["sessions"] = activeSessions;

    String out;
    serializeJson(doc, out);
    return out;
}

static String jsonPeers() {
    DynamicJsonDocument doc(4096);
    JsonArray arr = doc.createNestedArray("peers");
    uint32_t now = nowMs();
    for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
        if (!peers[i].used) continue;
        PeerState& p = peers[i];
        JsonObject o = arr.createNestedObject();
        o["node_id"] = p.nodeId;
        o["key_id"] = p.keyId;
        o["rssi"] = p.lastRssi;
        o["snr"] = p.lastSnr;
        o["age_ms"] = p.lastSeenMs ? (now - p.lastSeenMs) : 0;
        o["frames_ok"] = p.framesOk;
        o["frames_bad"] = p.framesBad;
        o["replays"] = p.replays;
        o["stale_epoch"] = p.staleEpochs;
        o["resyncs"] = p.resyncs;
        o["gaps"] = p.rx.gaps();
        o["epoch"] = p.rx.epoch();
        o["counter"] = p.rx.highest();
        o["state_persisted"] = vault.getPeerState(p.nodeId, nullptr, nullptr);
        o["have_track"] = p.haveTrack;
        if (p.haveTrack) {
            o["utc"] = p.last.epochUtc;
            o["lat"] = p.last.lat;
            o["lon"] = p.last.lon;
            o["alt_m"] = p.last.altM;
            o["speed_cms"] = p.last.speedCms;
            o["course_deg"] = p.last.courseDeg;
            o["hdop_x10"] = p.last.hdopX10;
            o["sats"] = p.last.sats;
            o["fix"] = p.last.fixQuality;
            o["battery"] = p.last.batteryPct;
            o["flags"] = p.last.statusFlags;
        }
    }
    String out;
    serializeJson(doc, out);
    return out;
}

static String jsonSpectrum() {
    DynamicJsonDocument doc(8192);
    doc["running"] = scanner.isRunning();
    doc["samples"] = scanner.sampleCount();
    doc["last_sweep_ms"] = scanner.lastSweepMs();
    doc["dwell_ms"] = SWEEP_DWELL_MS;

    JsonArray arr = doc.createNestedArray("points");
    uint16_t count = scanner.sampleCount();
    if (count > 96) count = 96;   // janela das 96 amostras mais recentes
    for (uint16_t i = count; i > 0; i--) {
        SpectrumPoint pt;
        if (!scanner.atAge((uint16_t)(i - 1), &pt)) continue;
        JsonObject o = arr.createNestedObject();
        o["band"] = HefRadio::bandName((HefBand)pt.band);
        o["freq_khz"] = pt.freqKHz;
        o["rssi_dbuV"] = pt.rssiDBuV;
        o["snr_db"] = pt.snrDb;
        o["valid"] = pt.valid;
        o["age_ms"] = nowMs() - pt.timestampMs;
    }
    String out;
    serializeJson(doc, out);
    return out;
}

static String jsonHealth() {
    DynamicJsonDocument doc(1536);
    doc["heap_free"] = ESP.getFreeHeap();
    doc["heap_min"] = ESP.getMinFreeHeap();
    doc["uptime_s"] = (uint32_t)(nowMs() / 1000UL);
    doc["node_id"] = nodeId;
    doc["clock_utc"] = currentUtc();
    doc["clock_valid"] = timeLooksValid();
    doc["enrollments"] = vault.enrollmentCount();
    doc["ser_crc_errors"] = serRx.crcErrors();
    doc["ser_overflows"] = serRx.overflows();
    doc["ser_drops"] = serDrops;
    uint8_t fails = 0;
    for (uint8_t i = 0; i < 8; i++) if (loginFails[i].used) fails++;
    doc["login_fails"] = fails;
    String out;
    serializeJson(doc, out);
    return out;
}

// =====================================================================
// Handlers HTTP
// =====================================================================
static void handleLoginPage(AsyncWebServerRequest* r) {
    static const char LOGIN_HTML[] PROGMEM = R"HTML(<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hefestos SIGINT - Login</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0f14;color:#d7e2ee;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
form{background:#141b24;border:1px solid #22303f;border-radius:8px;padding:22px;width:320px}
h1{font-size:15px;margin:0 0 14px;color:#3fa9f5}
label{display:block;margin:10px 0 4px;color:#7f93a8;font-size:12px}
input{width:100%;box-sizing:border-box;background:#0d141c;color:#d7e2ee;border:1px solid #2b3a4a;border-radius:4px;padding:8px;font:inherit}
button{width:100%;margin-top:16px;padding:9px;background:#1b4f7a;color:#eaf4ff;border:1px solid #3fa9f5;border-radius:4px;font:inherit;cursor:pointer}
.msg{margin-top:10px;font-size:12px;color:#e05252;min-height:16px}
</style></head><body>
<form method="POST" action="/login">
<h1>HEFESTOS SIGINT v5</h1>
<label for="u">Usuario</label><input id="u" name="user" autocomplete="username" required>
<label for="p">Senha</label><input id="p" name="pass" type="password" autocomplete="current-password" required>
<label for="t">Codigo TOTP (6 digitos)</label><input id="t" name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>
<button type="submit">Entrar</button>
<div class="msg" id="m"></div>
</form>
<script>
const q=new URLSearchParams(location.search);
if(q.get('e')==='1')document.getElementById('m').textContent='Credenciais ou TOTP invalidos.';
if(q.get('e')==='2')document.getElementById('m').textContent='Relogio nao sincronizado. Use o console serial: settime <unix>.';
if(q.get('e')==='3')document.getElementById('m').textContent='Muitas tentativas. Aguarde.';
</script></body></html>)HTML";
    r->send(200, "text/html", LOGIN_HTML);
}

static void handleLogin(AsyncWebServerRequest* r) {
    uint32_t ip = ipToKey(r->client()->remoteIP());

    if (!loginLimiter.allow(ip)) {
        r->redirect("/login?e=3");
        return;
    }

    String user = r->arg("user");
    String pass = r->arg("pass");
    String code = r->arg("totp");

    char vUser[17], vPass[33];
    bool haveUser = vault.getCliUsername(vUser, sizeof(vUser));
    bool havePass = vault.getCliPassword(vPass, sizeof(vPass));

    bool ok = haveUser && havePass &&
              constantTimeStringEq(user.c_str(), vUser) &&
              constantTimeStringEq(pass.c_str(), vPass);

    memset(vPass, 0, sizeof(vPass));

    if (!ok) {
        if (registerLoginFailure(ip) >= MAX_AUTH_ATTEMPTS) {
            loginLimiter.block(ip, BLOCK_DURATION_MS);
        }
        r->redirect("/login?e=1");
        return;
    }

    if (!timeLooksValid()) {
        r->redirect("/login?e=2");
        return;
    }

    if (!totp.verify(code.c_str(), currentUtc())) {
        if (registerLoginFailure(ip) >= MAX_AUTH_ATTEMPTS) {
            loginLimiter.block(ip, BLOCK_DURATION_MS);
        }
        r->redirect("/login?e=1");
        return;
    }

    clearLoginFailures(ip);
    Session* s = createSession(ip);
    if (!s) {
        r->send(503, "text/plain", "sem slots de sessao");
        return;
    }

    AsyncWebServerResponse* resp = r->beginResponse(302, "text/plain", "");
    resp->addHeader("Location", "/");
    String cookie = String("HEF_SID=") + s->token + "; Path=/; HttpOnly; SameSite=Strict";
    resp->addHeader("Set-Cookie", cookie);
    r->send(resp);
}

static void handleLogout(AsyncWebServerRequest* r) {
    char token[HTTP_TOKEN_HEX_LEN + 1];
    if (getCookie(r, "HEF_SID", token, sizeof(token))) destroySession(token);
    AsyncWebServerResponse* resp = r->beginResponse(302, "text/plain", "");
    resp->addHeader("Location", "/login");
    resp->addHeader("Set-Cookie", "HEF_SID=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
    r->send(resp);
}

static void handleRoot(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { r->redirect("/login"); return; }

    static const char DASH[] PROGMEM = R"HTML(<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hefestos SIGINT - Node2</title>
<style>
:root{--bg:#0b0f14;--fg:#d7e2ee;--acc:#3fa9f5;--card:#141b24}
*{box-sizing:border-box}
body{margin:0;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--fg)}
header{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 16px;background:#101720;border-bottom:1px solid #22303f;position:sticky;top:0;z-index:2}
h1{font-size:15px;margin:0;color:var(--acc)}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:12px;padding:12px}
section{background:var(--card);border:1px solid #22303f;border-radius:6px;padding:10px;min-width:0}
h2{font-size:12px;margin:0 0 8px;color:var(--acc);text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:2px 4px;text-align:left;border-bottom:1px solid #1d2833;vertical-align:top}
th{color:#7f93a8;font-weight:400}
td:first-child{color:#7f93a8;white-space:nowrap}
input,select,button{font:inherit;background:#0d141c;color:var(--fg);border:1px solid #2b3a4a;border-radius:4px;padding:4px 6px}
button{cursor:pointer}button:hover{border-color:var(--acc)}
pre{white-space:pre-wrap;word-break:break-word;font-size:11px;max-height:240px;overflow:auto;margin:0}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.muted{color:#7f93a8}.ok{color:#7fe08a}.bad{color:#f08a8a}.warn{color:#f0cf8a}
.scroll{overflow:auto;max-height:300px}
</style></head><body>
<header><h1>HEFESTOS SIGINT v5 &middot; Node2</h1>
<div class="row" style="margin:0"><span id="jid" class="muted"></span><button id="logout">Sair</button></div></header>
<main>
<section><h2>Estado</h2><table id="status"></table></section>
<section><h2>Pares (rastreadores)</h2><div class="scroll"><table id="peers"><thead><tr><th>no</th><th>rssi</th><th>snr</th><th>idade</th><th>lat</th><th>lon</th><th>sat</th><th>bat</th><th>ok/erro</th></tr></thead><tbody></tbody></table></div></section>
<section><h2>Receptor / Espectro</h2>
<div class="row"><select id="band"><option>FM</option><option>AM</option><option>SW</option></select>
<input id="freq" type="number" min="0" step="1" value="100100" style="width:110px">
<button id="tune">Sintonizar</button><button id="sweep">Varredura</button></div>
<table id="radio"></table><pre id="spec">-</pre></section>
<section><h2>Interferencia / Link</h2><table id="jam"></table></section>
<section><h2>Saude</h2><table id="health"></table></section>
<section><h2>Node3 &middot; Capturas</h2><pre id="caps">-</pre></section>
<section><h2>Node3 &middot; Log forense</h2><pre id="logs">-</pre></section>
</main>
<script>
const $=s=>document.querySelector(s);
async function api(p,o){
  const r=await fetch(p,o);
  if(r.status===401){location.href='/login';return null;}
  if(!r.ok)throw new Error('HTTP '+r.status);
  return r.json();
}
function kv(id,rows){
  const t=$(id);t.replaceChildren();
  for(const it of rows){
    const tr=document.createElement('tr');
    const a=document.createElement('td');a.textContent=it[0];
    const b=document.createElement('td');
    b.textContent=(it[1]===null||it[1]===undefined)?'-':String(it[1]);
    if(it[2])b.className=it[2];
    tr.append(a,b);t.append(tr);
  }
}
function cls(v){return v==='NORMAL'?'ok':(v==='LINK_LOSS'?'bad':'warn');}
async function refresh(){
  try{
    const [s,p,r,h]=await Promise.all([api('/api/status'),api('/api/peers'),api('/api/radio'),api('/api/health')]);
    if(!s)return;
    $('#jid').textContent='node '+s.node_id+' | '+s.wifi.mode+' '+s.wifi.ip;
    kv('#status',[
      ['firmware',s.fw],['uptime',s.uptime_s+' s'],
      ['UTC',s.time.utc?(new Date(s.time.utc*1000).toISOString()):'-'],
      ['relogio',s.time.synced?'sincronizado':'NAO sincronizado',s.time.synced?'ok':'bad'],
      ['chave link',s.lora.key,s.lora.key==='ok'?'ok':'bad'],
      ['pares',s.lora.peers],['frames ok',s.lora.frames_ok],
      ['frames ruins',s.lora.frames_bad],['replays',s.lora.replays],['ACKs',s.lora.acks_sent],
      ['sessoes',s.sessions]
    ]);
    kv('#radio',[['banda',s.radio.band],['frequencia',s.radio.freq_khz+' kHz'],
      ['inicializado',s.radio.initialized?'sim':'nao'],
      ['varredura',s.spectrum.running?'em curso':'parada'],
      ['amostras',s.spectrum.samples],['auto',s.spectrum.auto?'ligado':'desligado']]);
    kv('#jam',[['estado',s.jamming.state,cls(s.jamming.state)],
      ['SNR mediana',s.jamming.median_snr+' dB'],
      ['RSSI mediana',s.jamming.median_rssi_dbm+' dBm'],
      ['piso de ruido',s.jamming.noise_floor_dbuV+' dBuV'],
      ['ultimo pacote',s.jamming.last_packet_age_ms+' ms']]);
    kv('#health',[['heap livre',h.heap_free+' B'],['heap minimo',h.heap_min+' B'],
      ['enrollments',h.enrollments],['CRC erros Node3',h.ser_crc_errors],
      ['overflows Node3',h.ser_overflows],['drops TX Node3',h.ser_drops],
      ['fila Node3',h.ser_queue+' B']]);
    const tb=$('#peers tbody');tb.replaceChildren();
    for(const q of p.peers){
      const tr=document.createElement('tr');
      const vals=[q.node_id,q.rssi,q.snr,q.age_ms+' ms',
        q.have_track?q.lat.toFixed(6):'-',q.have_track?q.lon.toFixed(6):'-',
        q.have_track?q.sats:'-',q.have_track?q.battery:'-',
        q.frames_ok+'/'+q.frames_bad];
      for(const v of vals){const td=document.createElement('td');td.textContent=String(v);tr.append(td);}
      tb.append(tr);
    }
    if(p.peers.length===0){
      const tr=document.createElement('tr');
      const td=document.createElement('td');td.colSpan=9;td.className='muted';
      td.textContent='nenhum par autenticado ainda';
      tr.append(td);tb.append(tr);
    }
    const sp=await api('/api/spectrum');
    if(sp){
      const pts=sp.points||[];
      $('#spec').textContent=pts.length?pts.map(x=>x.band+' '+x.freq_khz+' kHz  '+x.rssi_dbuV+' dBuV  SNR '+x.snr_db+' dB').join('\n'):'sem amostras';
    }
  }catch(e){$('#jid').textContent='erro: '+e.message;}
}
async function refreshNode3(){
  try{
    const c=await api('/api/captures');if(c)$('#caps').textContent=JSON.stringify(c.data,null,1);
    const l=await api('/api/logs');if(l)$('#logs').textContent=JSON.stringify(l.data,null,1);
  }catch(e){}
}
$('#logout').onclick=async()=>{await fetch('/logout',{method:'POST'});location.href='/login';};
$('#tune').onclick=async()=>{
  const b=$('#band').value,f=$('#freq').value;
  await api('/api/radio?band='+encodeURIComponent(b)+'&freq='+encodeURIComponent(f),{method:'POST'});
  refresh();
};
$('#sweep').onclick=async()=>{await api('/api/sweep',{method:'POST'});refresh();};
refresh();refreshNode3();
setInterval(refresh,2000);
setInterval(refreshNode3,5000);
</script></body></html>)HTML";

    r->send(200, "text/html", DASH);
}

static void handleStatus(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    sendJson(r, 200, jsonStatus());
}

static void handlePeers(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    sendJson(r, 200, jsonPeers());
}

static void handleRadioGet(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    DynamicJsonDocument doc(512);
    doc["band"] = HefRadio::bandName(radio.band());
    doc["freq_khz"] = radio.freqKHz();
    doc["initialized"] = radio.isInitialized();
    HefSignalQuality q = radio.readQuality();
    doc["rssi_dbuV"] = q.rssiDBuV;
    doc["snr_db"] = q.snrDb;
    doc["valid"] = q.valid;
    String out; serializeJson(doc, out);
    sendJson(r, 200, out);
}

static void handleRadioPost(AsyncWebServerRequest* r) {
    Session* s = authedSession(r);
    if (!s) { sendUnauthorized(r); return; }
    if (!cmdLimiter.allowWithCooldown(ipToKey(r->client()->remoteIP()))) {
        sendJson(r, 429, "{\"error\":\"rate limit\"}");
        return;
    }
    if (!r->hasParam("band") || !r->hasParam("freq")) {
        sendJson(r, 400, "{\"error\":\"band e freq obrigatorios\"}");
        return;
    }
    String band = r->arg("band");
    long freq = r->arg("freq").toInt();
    if (freq <= 0) { sendJson(r, 400, "{\"error\":\"freq invalida\"}"); return; }

    // Sintonia manual cancela a varredura (evita disputa pelo receptor).
    if (scanner.isRunning()) scanner.stop();
    bool ok = radio.tuneByName(band.c_str(), (uint32_t)freq);
    DynamicJsonDocument doc(256);
    doc["ok"] = ok;
    doc["band"] = HefRadio::bandName(radio.band());
    doc["freq_khz"] = radio.freqKHz();
    String out; serializeJson(doc, out);
    sendJson(r, ok ? 200 : 400, out);
}

static void handleSpectrum(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    sendJson(r, 200, jsonSpectrum());
}

static void handleSweep(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    if (!cmdLimiter.allowWithCooldown(ipToKey(r->client()->remoteIP()))) {
        sendJson(r, 429, "{\"error\":\"rate limit\"}");
        return;
    }
    if (r->hasParam("auto")) {
        String a = r->arg("auto");
        autoSweep = (a == "1" || a == "on" || a == "true");
    }
    if (r->hasParam("dwell")) {
        long d = r->arg("dwell").toInt();
        if (d >= 20 && d <= 5000) scanner.setDwell((uint32_t)d);
    }
    if (!scanner.isRunning()) scanner.start();
    DynamicJsonDocument doc(256);
    doc["running"] = scanner.isRunning();
    doc["auto"] = autoSweep;
    doc["samples"] = scanner.sampleCount();
    String out; serializeJson(doc, out);
    sendJson(r, 200, out);
}

static void handleHealth(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    sendJson(r, 200, jsonHealth());
}

static String wrapNode3(uint8_t req) {
    const RespCache* c = cachedResponse(req);
    String out = "{\"stale\":";
    out += (c && (nowMs() - c->ms) < 5000UL) ? "false" : "true";
    out += ",\"data\":";
    out += (c && c->valid) ? c->json : "null";
    out += "}";
    return out;
}

static void handleCaptures(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    const RespCache* c = cachedResponse(HEF_REQ_CAPTURE_LIST);
    if (!c || (nowMs() - c->ms) > 5000UL) requestNode3(HEF_REQ_CAPTURE_LIST);
    sendJson(r, 200, wrapNode3(HEF_REQ_CAPTURE_LIST));
}

static void handleLogs(AsyncWebServerRequest* r) {
    if (!authedSession(r)) { sendUnauthorized(r); return; }
    const RespCache* c = cachedResponse(HEF_REQ_LOG_INFO);
    if (!c || (nowMs() - c->ms) > 10000UL) requestNode3(HEF_REQ_LOG_INFO);
    sendJson(r, 200, wrapNode3(HEF_REQ_LOG_INFO));
}

static void handleNotFound(AsyncWebServerRequest* r) {
    r->send(404, "application/json", "{\"error\":\"nao encontrado\"}");
}

// =====================================================================
// Console serial (UART0)
// =====================================================================
static void printHelp() {
    Serial.println();
    Serial.println("=== HEFESTOS SIGINT v5 - Node2 (Base) ===");
    Serial.println("help                     esta ajuda");
    Serial.println("status                   estado resumido");
    Serial.println("id                       node_id deste no");
    Serial.println("psk <64 hex>             define o PSK de deploy");
    Serial.println("psk show                 informa se ha PSK");
    Serial.println("user <nome>              troca o usuario HTTP");
    Serial.println("pass <senha>             troca a senha HTTP (>=10)");
    Serial.println("totp                     mostra o segredo TOTP atual");
    Serial.println("wifi <ssid> <senha>      configura STA (senha >=8)");
    Serial.println("settime <unix>           acerta o relogio UTC");
    Serial.println("time                     mostra o relogio UTC");
    Serial.println("enroll <node> <keyid>    registra um par manualmente");
    Serial.println("peers                    lista pares");
    Serial.println("sweep on|off|now         varredura automatica/agora");
    Serial.println("radio <FM|AM|SW> <kHz>   sintoniza o receptor");
    Serial.println("reboot                   reinicia");
    Serial.println("factory                  apaga o vault e reinicia");
}

static void handleConsole(char* line) {
    if (strncmp(line, "help", 4) == 0) {
        printHelp();
    } else if (strncmp(line, "status", 6) == 0) {
        Serial.printf("node_id=%u chave=%s clock=%s\n", nodeId,
                      keyReady ? "ok" : "ausente",
                      timeLooksValid() ? "ok" : "invalido");
        Serial.printf("pares=%u frames_ok=%u ruins=%u replays=%u\n",
                      peerCount(), loraFramesOk, loraFramesBad, loraReplays);
        Serial.printf("Node3: ok=%u crc=%u drops=%u fila=%u\n",
                      serFramesOk, serRx.crcErrors(), serDrops, serQueue.pending());
    } else if (strncmp(line, "id", 2) == 0) {
        Serial.printf("node_id=%u\n", nodeId);
    } else if (strncmp(line, "psk show", 8) == 0) {
        Serial.println(vault.hasPsk() ? "PSK: configurado" : "PSK: ausente");
    } else if (strncmp(line, "psk ", 4) == 0) {
        uint8_t psk[HEF_KEY_LEN];
        int n = hexToBytes(line + 4, psk, sizeof(psk));
        if (n != (int)HEF_KEY_LEN) {
            Serial.println("ERRO: esperado PSK de 64 caracteres hex");
        } else if (!vault.setDeploymentPsk(psk, HEF_KEY_LEN)) {
            Serial.println("ERRO: falha ao gravar o vault");
        } else {
            Serial.println("OK: PSK gravado. Re-provisione os nos e reinicie.");
        }
        memset(psk, 0, sizeof(psk));
    } else if (strncmp(line, "user ", 5) == 0) {
        if (vault.setCliUsername(line + 5)) Serial.println("OK: usuario atualizado");
        else Serial.println("ERRO: usuario invalido (3..16)");
    } else if (strncmp(line, "pass ", 5) == 0) {
        if (vault.setCliPassword(line + 5)) Serial.println("OK: senha atualizada");
        else Serial.println("ERRO: senha invalida (>=10)");
    } else if (strncmp(line, "totp", 4) == 0) {
        char b32[64];
        totp.exportBase32(b32, sizeof(b32));
        char uri[192];
        totp.buildOtpAuthUri(uri, sizeof(uri), "Hefestos", "admin");
        Serial.print("TOTP base32: "); Serial.println(b32);
        Serial.print("URI:         "); Serial.println(uri);
    } else if (strncmp(line, "wifi ", 5) == 0) {
        char* sp = strchr(line + 5, ' ');
        if (!sp) {
            Serial.println("ERRO: use 'wifi <ssid> <senha>'");
        } else {
            *sp = 0;
            const char* ssid = line + 5;
            const char* pass = sp + 1;
            if (!vault.setWifiSsid(ssid) || !vault.setWifiPassword(pass)) {
                Serial.println("ERRO: ssid 1..32 / senha >=8");
            } else {
                Serial.println("OK: WiFi gravado. Reinicie para conectar.");
            }
        }
    } else if (strncmp(line, "settime ", 8) == 0) {
        uint32_t u = (uint32_t)strtoul(line + 8, nullptr, 10);
        if (u < 1704067200UL) {
            Serial.println("ERRO: epoch invalido");
        } else {
            struct timeval tv;
            tv.tv_sec = (time_t)u;
            tv.tv_usec = 0;
            settimeofday(&tv, nullptr);
            clockSynced = true;
            hefSendTimeToNode3(u);
            Serial.println("OK: relogio ajustado");
        }
    } else if (strncmp(line, "time", 4) == 0) {
        Serial.printf("UTC: %u (%s)\n", currentUtc(),
                      timeLooksValid() ? "valido" : "invalido");
    } else if (strncmp(line, "enroll ", 7) == 0) {
        char* sp = strchr(line + 7, ' ');
        if (!sp) {
            Serial.println("ERRO: use 'enroll <node_id> <key_id>'");
        } else {
            uint16_t nid = (uint16_t)atoi(line + 7);
            uint8_t kid = (uint8_t)atoi(sp + 1);
            if (nid == 0) Serial.println("ERRO: node_id invalido");
            else if (vault.enrollNode(nid, kid)) Serial.println("OK: par registrado");
            else Serial.println("ERRO: limite de enrollments");
        }
    } else if (strncmp(line, "peers", 5) == 0) {
        for (uint8_t i = 0; i < HEF_MAX_ENROLLMENTS; i++) {
            if (!peers[i].used) continue;
            Serial.printf("node=%u keyId=%u rssi=%d snr=%.1f ok=%u err=%u replay=%u\n",
                          peers[i].nodeId, peers[i].keyId, peers[i].lastRssi,
                          (double)peers[i].lastSnr, peers[i].framesOk,
                          peers[i].framesBad, peers[i].replays);
            Serial.printf("   epoch=%u counter=%u stale=%u resync=%u persistido=%s\n",
                          peers[i].rx.epoch(), (unsigned)peers[i].rx.highest(),
                          peers[i].staleEpochs, peers[i].resyncs,
                          vault.getPeerState(peers[i].nodeId, nullptr, nullptr)
                              ? "sim" : "nao");
        }
    } else if (strncmp(line, "sweep on", 8) == 0) {
        autoSweep = true;
        if (!scanner.isRunning()) scanner.start();
        Serial.println("OK: varredura automatica ligada");
    } else if (strncmp(line, "sweep off", 9) == 0) {
        autoSweep = false;
        Serial.println("OK: varredura automatica desligada");
    } else if (strncmp(line, "sweep now", 9) == 0) {
        scanner.start();
        Serial.println("OK: varredura iniciada");
    } else if (strncmp(line, "radio ", 6) == 0) {
        char band[8];
        unsigned freq = 0;
        if (sscanf(line + 6, "%7s %u", band, &freq) == 2) {
            bool ok = radio.tuneByName(band, freq);
            Serial.printf("%s: %s %.3f MHz\n", ok ? "OK" : "ERRO",
                          HefRadio::bandName(radio.band()),
                          radio.freqKHz() / 1000.0f);
        } else {
            Serial.println("ERRO: use 'radio <FM|AM|SW> <kHz>'");
        }
    } else if (strncmp(line, "reboot", 6) == 0) {
        Serial.println("Reiniciando...");
        delay(100);
        ESP.restart();
    } else if (strncmp(line, "factory", 7) == 0) {
        vault.factoryReset();
        resetPeers();
        Serial.println("Vault apagado. Reiniciando...");
        delay(200);
        ESP.restart();
    } else {
        Serial.println("Comando desconhecido. Use 'help'.");
    }
}

// =====================================================================
// Setup
// =====================================================================
static void setupRadio() {
    Wire.begin(N2_I2C_SDA, N2_I2C_SCL);
    if (radio.begin(N2_RX_RST)) {
        radio.tune(HEF_BAND_FM, 100100);
        scanner.setDefaultPlan();
        dbg.log("Si4735 pronto");
    } else {
        dbg.logWarning("Si4735 nao detectado");
    }
}

static void setupLoRa() {
    LoRa.setPins(N2_LORA_SS, N2_LORA_RST, N2_LORA_DIO0);
    if (!LoRa.begin(LORA_FREQ)) {
        dbg.logError("Falha ao iniciar o LoRa");
        return;
    }
    LoRa.setSpreadingFactor(LORA_SF);
    LoRa.setSignalBandwidth(LORA_BW);
    LoRa.setTxPower(LORA_TX_POWER);
    LoRa.setSyncWord(0x12);
    LoRa.receive();
    dbg.log("LoRa em RX");
}

void setup() {
    Serial.begin(115200);
    dbg.begin(115200);

    dbg.log("Node2 v5.1.0: inicializando");

    // Node3 em UART2 (UART0 fica para o console).
    node3Serial.begin(115200, SERIAL_8N1, N2_UART_RX, N2_UART_TX);

    // Vault + identidade + chave de link
    vault.begin();
    nodeId = vault.nodeId();
    keyReady = (vault.getPsk() != nullptr);

    // Reidrata o estado anti-replay dos pares conhecidos (fecha o replay
    // pos-reboot: um frame capturado antes de um reinicio e' rejeitado).
    restorePeerStates();

    ensureCredentials();
    setupRadio();
    setupLoRa();
    startNetwork();

    // Servidor HTTP
    DefaultHeaders::Instance().addHeader("X-Content-Type-Options", "nosniff");
    DefaultHeaders::Instance().addHeader("X-Frame-Options", "DENY");
    DefaultHeaders::Instance().addHeader("Referrer-Policy", "no-referrer");

    server.on("/login", HTTP_GET, handleLoginPage);
    server.on("/login", HTTP_POST, handleLogin);
    server.on("/logout", HTTP_POST, handleLogout);
    server.on("/", HTTP_GET, handleRoot);

    server.on("/api/status", HTTP_GET, handleStatus);
    server.on("/api/peers", HTTP_GET, handlePeers);
    server.on("/api/radio", HTTP_GET, handleRadioGet);
    server.on("/api/radio", HTTP_POST, handleRadioPost);
    server.on("/api/spectrum", HTTP_GET, handleSpectrum);
    server.on("/api/sweep", HTTP_POST, handleSweep);
    server.on("/api/health", HTTP_GET, handleHealth);
    server.on("/api/captures", HTTP_GET, handleCaptures);
    server.on("/api/logs", HTTP_GET, handleLogs);

    server.onNotFound(handleNotFound);
    server.begin();

    Serial.println();
    Serial.println("=================================================");
    Serial.println(" HEFESTOS SIGINT v5.1.0 - NODE 2 (BASE)");
    Serial.println("=================================================");
    Serial.printf("node_id: %u\n", nodeId);
    Serial.printf("chave de link: %s\n", keyReady ? "OK" : "AUSENTE - 'psk <64 hex>'");
    Serial.printf("HTTP: http://%s/\n",
                  (WiFi.getMode() == WIFI_AP) ? WiFi.softAPIP().toString().c_str()
                                              : WiFi.localIP().toString().c_str());
    Serial.println("=================================================");
    printHelp();
}

// =====================================================================
// Loop
// =====================================================================
void loop() {
    uint32_t now = nowMs();

    // --- Console ---
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

    // --- LoRa RX ---
    int packetSize = LoRa.parsePacket();
    if (packetSize > 0) {
        uint8_t frame[HEF_MAX_FRAME + 8];
        int n = LoRa.readBytes(frame, sizeof(frame));
        int16_t rssi = (int16_t)LoRa.packetRssi();
        float snr = LoRa.packetSnr();
        if (n > 0) processTrack(frame, (uint16_t)n, rssi, snr);
    }

    // --- Link serial com o Node3 ---
    serQueue.pump(node3Serial);
    serRx.feed(node3Serial, onNode3Frame, nullptr);

    // Heartbeat para o Node3 (5 s) + tempo UTC (30 s). O reenvio periodico
    // garante que um Node3 reiniciado recupere o relogio sem esperar por
    // uma mudanca de hora.
    static uint32_t lastHeartbeat = 0;
    if (now - lastHeartbeat >= 5000UL) {
        lastHeartbeat = now;
        uint8_t hb[4];
        putU32(hb, (uint32_t)(now / 1000UL));
        hefSendSer(HEF_SER_HEARTBEAT, hb, sizeof(hb));
        if (timeLooksValid()) hefSendTimeToNode3(currentUtc());
    }

    // --- Espectro ---
    if (scanner.isRunning()) {
        if (scanner.tick(now)) {
            SpectrumPoint pt;
            if (scanner.latest(&pt)) {
                jam.onNoiseFloor((float)pt.rssiDBuV, now);
            }
            if (!scanner.isRunning() && autoSweep) {
                scanner.start();
            }
        }
    }

    // --- Expiracao de sessoes ---
    static uint32_t lastSessionSweep = 0;
    if (now - lastSessionSweep >= 10000UL) {
        lastSessionSweep = now;
        for (uint8_t i = 0; i < HTTP_SESSION_SLOTS; i++) {
            Session& s = sessions[i];
            if (!s.active) continue;
            if ((now - s.lastMs) > HTTP_SESSION_IDLE_MS ||
                (now - s.createdMs) > HTTP_SESSION_ABSOLUTE_MS) {
                memset(&s, 0, sizeof(s));
            }
        }
    }

    // --- Persistencia periodica do estado anti-replay ---
    // O epoch novo e' gravado IMEDIATAMENTE (no processTrack). Aqui o
    // high-water do contador e' gravado no maximo a cada
    // HEF_PEER_STATE_FLUSH_MS. Intervalo maior = menos desgaste de flash;
    // intervalo menor = janela menor de replay intra-epoch pos-reboot.
    static uint32_t lastPeerFlush = 0;
    if (now - lastPeerFlush >= HEF_PEER_STATE_FLUSH_MS) {
        lastPeerFlush = now;
        persistPeerStates();
    }

    // --- Watchdog de memoria (reinicio controlado se o heap colapsar) ---
    static uint32_t lastHeapCheck = 0;
    if (now - lastHeapCheck >= 30000UL) {
        lastHeapCheck = now;
        if (ESP.getFreeHeap() < 12000) {
            dbg.logError("Heap critico: reiniciando");
            delay(100);
            ESP.restart();
        }
    }

    delay(1);
}
