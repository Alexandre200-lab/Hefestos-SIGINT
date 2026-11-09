// link_protocol.h - Protocolo de link LoRa binario e versionado - v5.0.0
//
// SUBSTITUI o payload textual da v4.x ("ALVO_01|-23.5505|-46.6333") que:
//   - nao era auto-descritivo (sem epoch, HDOP, altitude, velocidade, curso,
//     satelites, id do no, sequencia ou unidade)
//   - nao permitia ao receptor envelhecer o fix nem julgar a qualidade
//   - desperdicava airtime (payload decimal em ASCII)
//
// FORMATO DO FRAME (todos os campos big-endian):
//
//   offset  tam  campo
//   ------  ---  -------------------------------------------------------
//    0       1   magic      0xA5
//    1       1   version    5
//    2       1   type       (ver HefMsgType)
//    3       1   flags
//    4       1   keyId      (slot de chave do emissor)
//    5       2   epoch      (muda a cada boot do emissor)
//    7       4   counter    (monotonico estrito por (epoch, node))
//   11       2   payloadLen
//   13     N     payload
//   13+N   16   tag GCM
//
// O cabecalho (bytes 0..12) e' usado como AAD do AES-256-GCM: alterar
// node_id, epoch, counter ou tipo invalida a tag.
//
// NONCE: prefixo de 4 bytes (keyId ^ nodeId) || contador de 8 bytes.
// Deterministico e unico por (chave, emissor, contador).
#ifndef HEF_LINK_PROTOCOL_H
#define HEF_LINK_PROTOCOL_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"

enum HefMsgType {
    HEF_MSG_TRACK        = 0x01,
    HEF_MSG_TRACK_ACK    = 0x02,
    HEF_MSG_PROVISION_REQ= 0x03,
    HEF_MSG_PROVISION_RESP=0x04,
    HEF_MSG_HEARTBEAT    = 0x05,
    HEF_MSG_NACK         = 0x06
};

enum HefTrackStatus {
    HEF_TRACK_GPS_VALID   = 0x01,
    HEF_TRACK_LOW_BATTERY = 0x02,
    HEF_TRACK_DEGRADED    = 0x04
};

// --- Payload de tracking (23 bytes) ---
#define HEF_TRACK_PAYLOAD_LEN 23

// --- Serializacao (big-endian, sem depender de struct packing) ---
inline void putU16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
inline void putU32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
inline void putI32(uint8_t* p, int32_t v)  { putU32(p, (uint32_t)v); }
inline void putU64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
inline uint16_t getU16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
inline uint32_t getU32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
inline int32_t  getI32(const uint8_t* p) { return (int32_t)getU32(p); }
inline uint64_t getU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

// Preenche o cabecalho (13 bytes). Retorna false se os parametros sao invalidos.
inline bool linkBuildHeader(uint8_t* hdr,
                            uint8_t type, uint8_t flags, uint8_t keyId,
                            uint16_t epoch, uint32_t counter,
                            uint16_t payloadLen) {
    if (!hdr) return false;
    if (payloadLen > HEF_MAX_PAYLOAD) return false;
    hdr[0] = HEF_LINK_MAGIC;
    hdr[1] = HEF_LINK_VERSION;
    hdr[2] = type;
    hdr[3] = flags;
    hdr[4] = keyId;
    putU16(hdr + 5, epoch);
    putU32(hdr + 7, counter);
    putU16(hdr + 11, payloadLen);
    return true;
}

// Valida o cabecalho recebido (antes de tentar decifrar).
inline bool linkHeaderValid(const uint8_t* hdr, uint16_t frameLen) {
    if (!hdr) return false;
    if (hdr[0] != HEF_LINK_MAGIC) return false;
    if (hdr[1] != HEF_LINK_VERSION) return false;
    uint16_t plen = getU16(hdr + 11);
    if (plen > HEF_MAX_PAYLOAD) return false;
    if ((uint32_t)HEF_HEADER_LEN + plen + HEF_TAG_LEN != frameLen) return false;
    return true;
}

// Monta o payload de tracking.
inline void linkPackTrack(uint8_t* p,
                          uint32_t epochUtc,
                          double lat, double lon,
                          int16_t altM, uint16_t speedCms, uint16_t courseDeg,
                          uint8_t hdopX10, uint8_t sats, uint8_t fixQuality,
                          uint8_t batteryPct, uint8_t statusFlags) {
    if (!p) return;
    int32_t la = (int32_t)(lat  * 10000000.0);
    int32_t lo = (int32_t)(lon  * 10000000.0);
    putU32(p + 0,  epochUtc);
    putI32(p + 4,  la);
    putI32(p + 8,  lo);
    putU16(p + 12, (uint16_t)altM);
    putU16(p + 14, speedCms);
    putU16(p + 16, courseDeg);
    p[18] = hdopX10;
    p[19] = sats;
    p[20] = fixQuality;
    p[21] = batteryPct;
    p[22] = statusFlags;
}

struct HefTrack {
    uint32_t epochUtc;
    double   lat;
    double   lon;
    int16_t  altM;
    uint16_t speedCms;
    uint16_t courseDeg;
    uint8_t  hdopX10;
    uint8_t  sats;
    uint8_t  fixQuality;
    uint8_t  batteryPct;
    uint8_t  statusFlags;
};

inline void linkUnpackTrack(const uint8_t* p, HefTrack* t) {
    if (!p || !t) return;
    t->epochUtc    = getU32(p + 0);
    t->lat         = (double)getI32(p + 4) / 10000000.0;
    t->lon         = (double)getI32(p + 8) / 10000000.0;
    t->altM        = (int16_t)getU16(p + 12);
    t->speedCms    = getU16(p + 14);
    t->courseDeg   = getU16(p + 16);
    t->hdopX10     = p[18];
    t->sats        = p[19];
    t->fixQuality  = p[20];
    t->batteryPct  = p[21];
    t->statusFlags = p[22];
}

// Converte o epoch do payload para data/hora UTC (epoch unix).
inline void epochUtcToDate(uint32_t epochUtc, int* year, int* month, int* day,
                           int* hour, int* minute, int* second) {
    // Implementacao civil (Howard Hinnant) - sem dependencia de timezone
    // e com regras de ano bissexto do calendario gregoriano.
    uint32_t z = epochUtc + 2208988800UL; // epoch -> dia civil
    uint32_t era = z / 146097UL;
    uint32_t doe = z - era * 146097UL;
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp  = (5 * doy + 2) / 153;
    uint32_t d   = doy - (153 * mp + 2) / 5 + 1;
    uint32_t m   = mp < 10 ? mp + 3 : mp - 9;
    uint32_t y   = yoe + era * 400 + (m <= 2 ? 1 : 0);
    if (year)   *year   = (int)y;
    if (month)  *month  = (int)m;
    if (day)    *day    = (int)d;
    if (hour)   *hour   = (int)((z % 86400UL) / 3600UL);
    if (minute) *minute = (int)(((z % 3600UL) / 60UL));
    if (second) *second = (int)(z % 60UL);
}

#endif // HEF_LINK_PROTOCOL_H
