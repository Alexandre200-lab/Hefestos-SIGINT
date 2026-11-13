// field_log.h - Log forense append-only com cadeia de hash, em LOTES
//                (v5.1.0, item 1.6 do plano de escala)
//
// PROBLEMA DA v5.0.0/v5.1.0 (medido no plano de escala)
//   `append()` abria o arquivo no SD, gravava UM registro e fechava o
//   arquivo — para CADA registro. A 1 registro/s isso significa ~86 mil
//   escritas/dia. Num cartao FAT cada open/write/close atualiza dados,
//   tabela FAT e diretorio: o desgaste e' a principal causa de perda de
//   evidencia em campo.
//
// O QUE MUDOU (item 1.6)
//   - A DECISAO (o que entra no buffer, quando gravar, quando rotacionar,
//     quando emitir checkpoint) vive em `field_log_buffer.h` — puro e
//     testavel no host. Este arquivo e' a OPERACAO: I/O no SD.
//   - Os registros sao encadeados NA CHEGADA (hash calculado no buffer
//     RAM) e gravados em lotes de ate 4 KB, com flush() (fflush + fsync
//     no core ESP32) apos cada lote. A ~1 registro/s e ~143 B/registro,
//     o resultado e' ~3,0 mil escritas/dia — 28x menos.
//   - GRAVACAO PARCIAL: se a escrita devolver menos bytes que o lote, o
//     arquivo e' truncado de volta ao tamanho anterior (`truncate()` do
//     newlib/IDF, disponivel no FATFS via VFS) e o MESMO lote (mesmos
//     hashes) e' retentado. Se o truncate falhar, o log e' marcado como
//     corrompido e RECUSA novas escritas (fail closed): uma cadeia
//     truncada e' indistinguivel de uma cadeia manipulada.
//   - ROTACAO: ao atingir HEF_LOG_MAX_BYTES (64 MB), HEFLOG.BIN e'
//     renomeado para HEFLOGnnn.BIN e um arquivo novo e' aberto com o
//     header HLG6, que semeia a cadeia a partir da cabeca do anterior
//     (a cadeia continua entre arquivos). Cada rotacao acrescenta uma
//     linha JSON ao manifesto HEFLOG.MAN (append-only).
//   - SAUDE DO CARTAO: teste de escrita/leitura + SD.totalBytes()/
//     SD.usedBytes(). Cartao cheio = FAIL CLOSED: para de aceitar e
//     reporta. NUNCA apaga automaticamente (evidencia).
//   - CHECKPOINTS: a cada HEF_LOG_CHECKPOINT_RECORDS registros, grava em
//     HEFCHK.BIN o ponto de ancoragem `seq + cabeca da cadeia`. Na
//     v5.1.0 SEM assinatura (Ed25519 nao existe no core Arduino 2.0.17;
//     a assinatura fica para as fases 2/3.3 do plano). O verificador
//     offline (tools/verify_log.py) distingue explicitamente checkpoint
//     sem assinatura de checkpoint assinado.
//
// FORMATO DOS ARQUIVOS
//   HEFLOG.BIN (atual) e HEFLOGnnn.BIN (arquivados):
//     HLG5 (legado, 38 B): "HLG5" | nodeId(2 BE) | chainSeed(32)
//     HLG6 (novo,   70 B): "HLG6" | nodeId(2 BE) | chainSeed(32)
//                          | prevHead(32)
//   Registro (INALTERADO desde a v5.0.0 — compatibilidade obrigatoria):
//     seq(4 BE) | utc(4 BE) | type(1) | len(2 BE) | data[len] | hash(32)
//     hash = SHA256( cadeia_anterior || registro_sem_o_proprio_hash )
//
#ifndef HEF_FIELD_LOG_H
#define HEF_FIELD_LOG_H

#include <Arduino.h>
#include <SD.h>
#include <unistd.h>
#include <mbedtls/md.h>

#include <string.h>

#include "hefestos_pins.h"
#include "field_log_buffer.h"

struct FieldRecord {
    uint32_t seq;
    uint32_t utc;
    uint8_t  type;
    uint16_t len;
    uint8_t  data[192];
};

// Header legado e novo.
#define HEF_LOG_HDR5_LEN   38
#define HEF_LOG_HDR6_LEN   70

// Arquivos auxiliares.
#define HEF_LOG_MANIFEST   "HEFLOG.MAN"
#define HEF_LOG_CHECKPOINTS "HEFCHK.BIN"
#define HEF_LOG_HEALTH_FILE  "HEFHLTH.TMP"

// Checkpoint (HEFCHK.BIN), um append por ponto de ancoragem:
//   "HCP1"(4) | fileIndex(2 BE) | seq(4 BE) | head(32)
//   | signerId(8) | sigLen(2 BE) | sig[sigLen] | crc16(2 BE)
// A parte fixa antes da assinatura tem 52 bytes; o crc16 cobre TUDO
// que o precede (detecta append parcial).
#define HEF_LOG_CHK_MAGIC  "HCP1"
#define HEF_LOG_CHK_FIXED  52

// ---------------------------------------------------------------------
// Callback de progresso de operacoes longas
// ---------------------------------------------------------------------
// A releitura da cadeia (no boot) e a exportacao JSONL podem processar
// dezenas de milhares de registros. Num SD lento, isso pode levar
// MINUTOS. O callback e' chamado apenas em pontos de avanco REAL: um SD
// que trava para de chama-lo e o watchdog expira normalmente (item 1.4).
typedef void (*FieldLogProgressCb)(void* ctx, uint32_t records);

// ---------------------------------------------------------------------
// Saude do cartao
// ---------------------------------------------------------------------
struct HefSdHealth {
    bool     mounted;
    bool     writable;
    uint32_t totalBytes;
    uint32_t usedBytes;
    uint32_t freeBytes;
    uint32_t checkedMs;
    char     note[32];
};

class FieldLog {
private:
    // --- I/O ---
    File     cur_;                 // HEFLOG.BIN aberto em FILE_APPEND
    char     path_[32];            // "HEFLOG.BIN"

    // --- Estado da cadeia (delegado ao buffer puro) ---
    HefLogBatch batch_;
    uint32_t utc_;
    uint16_t nodeId_;

    // --- Arquivos e rotacao ---
    uint16_t nextIndex_;           // indice do PROXIMO arquivo arquivado
    uint32_t priorRecords_;        // registros nos arquivos arquivados
    uint16_t archiveCount_;        // quantas rotacoes registrou
    uint32_t checkpointCount_;     // checkpoints em HEFCHK.BIN
    uint8_t  fileBase_[HEF_HASH_LEN]; // base da cadeia do arquivo atual

    // --- Flags de operacao ---
    bool     open_;
    bool     corrupt_;             // truncate falhou: recusar escritas
    bool     refusing_;            // fail closed (cartao cheio/insalubre)
    bool     cardFull_;

    // --- Saude ---
    HefSdHealth health_;

    FieldLogProgressCb progressCb_;
    void*         progressCtx_;

    // -----------------------------------------------------------------
    // SHA-256 (mbedtls)
    // -----------------------------------------------------------------
    static void sha256(const uint8_t* data, size_t len, uint8_t* out) {
        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, md, 0);
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, data, len);
        mbedtls_md_finish(&ctx, out);
        mbedtls_md_free(&ctx);
    }

    // CRC16 igual ao do protocolo serial (0xA001) — reutilizar o mesmo
    // polinomio evita duas implementacoes no repo.
    static uint16_t crc16(const uint8_t* data, size_t len) {
        uint16_t crc = 0xFFFF;
        for (size_t i = 0; i < len; i++) {
            crc ^= data[i];
            for (int j = 0; j < 8; j++) {
                crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001)
                                : (uint16_t)(crc >> 1);
            }
        }
        return crc;
    }

    static uint32_t getU32be(const uint8_t* p) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
    }
    static uint16_t getU16be(const uint8_t* p) {
        return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    }
    static void putU32be(uint8_t* p, uint32_t v) {
        p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
    }
    static void putU16be(uint8_t* p, uint16_t v) {
        p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
    }

    void reportProgress(uint32_t records) {
        if (progressCb_) progressCb_(progressCtx_, records);
    }

    // -----------------------------------------------------------------
    // Header
    // -----------------------------------------------------------------
    // Semente da cadeia: depende do node_id, de modo que dois
    // gravadores nunca produzem a mesma cadeia.
    static void chainSeedFor(uint16_t nodeId, const char* magic,
                             uint8_t* outSeed) {
        uint8_t in[6];
        memcpy(in, magic, 4);
        in[4] = (uint8_t)(nodeId >> 8);
        in[5] = (uint8_t)(nodeId & 0xFF);
        sha256(in, sizeof(in), outSeed);
    }

    // Cria (ou trunca) o arquivo atual com o header HLG6. A cadeia do
    // arquivo novo comeca em `prevHead`: no primeiro arquivo, prevHead
    // e' a propria semente (semantica igual a do HLG5); apos uma
    // rotacao, e' a cabeca confirmada do arquivo anterior — a cadeia
    // continua entre arquivos.
    bool writeHeader6(const uint8_t* prevHead) {
        uint8_t hdr[HEF_LOG_HDR6_LEN];
        uint8_t seed[HEF_HASH_LEN];
        chainSeedFor(nodeId_, "HLG6", seed);

        memcpy(hdr, "HLG6", 4);
        putU16be(hdr + 4, nodeId_);
        memcpy(hdr + 6, seed, HEF_HASH_LEN);
        memcpy(hdr + 6 + HEF_HASH_LEN, prevHead, HEF_HASH_LEN);

        File f = SD.open(path_, FILE_WRITE);
        if (!f) return false;
        size_t w = f.write(hdr, sizeof(hdr));
        f.close();
        return w == sizeof(hdr);
    }

    // -----------------------------------------------------------------
    // Leitura do header (HLG5 legado e HLG6)
    // -----------------------------------------------------------------
    // Retorna a base da cadeia do arquivo (seed no HLG5, prevHead no
    // HLG6) ou false se o header for invalido.
    static bool readHeader(File& f, uint16_t* nodeId, uint8_t* chainBase,
                           uint32_t* hdrLen) {
        uint8_t hdr[HEF_LOG_HDR6_LEN];
        if (f.read(hdr, 4) != 4) return false;
        if (memcmp(hdr, "HLG5", 4) == 0) {
            if (f.read(hdr + 4, HEF_LOG_HDR5_LEN - 4) != HEF_LOG_HDR5_LEN - 4)
                return false;
            if (nodeId) *nodeId = getU16be(hdr + 4);
            if (chainBase) memcpy(chainBase, hdr + 6, HEF_HASH_LEN);
            if (hdrLen) *hdrLen = HEF_LOG_HDR5_LEN;
            return true;
        }
        if (memcmp(hdr, "HLG6", 4) == 0) {
            if (f.read(hdr + 4, HEF_LOG_HDR6_LEN - 4) != HEF_LOG_HDR6_LEN - 4)
                return false;
            if (nodeId) *nodeId = getU16be(hdr + 4);
            // HLG6: a cadeia continua a partir do arquivo anterior.
            if (chainBase) memcpy(chainBase, hdr + 6 + HEF_HASH_LEN, HEF_HASH_LEN);
            if (hdrLen) *hdrLen = HEF_LOG_HDR6_LEN;
            return true;
        }
        return false;
    }

    // -----------------------------------------------------------------
    // Varredura de um arquivo de log
    // -----------------------------------------------------------------
    // Recupera seq/registros/cabeca sem reiniciar a numeracao (boot) e
    // sem quebrar a cadeia apos um reboot. NAO revalida os hashes (isso
    // e' feito no `export` e pelo verificador offline): a varredura de
    // boot acontece a cada reinicio e nao pode custar minutos.
    bool scanFile(const char* filePath, uint8_t* outHead, uint32_t* outSeq,
                  uint32_t* outRecords, uint32_t* outBytes, uint32_t* outFirstSeq,
                  uint8_t* outBase = nullptr,
                  uint32_t* outValidBytes = nullptr) {
        File f = SD.open(filePath, FILE_READ);
        if (!f) return false;

        uint16_t nodeId = 0;
        uint8_t  base[HEF_HASH_LEN];
        uint32_t hdrLen = 0;
        if (!readHeader(f, &nodeId, base, &hdrLen)) { f.close(); return false; }
        if (nodeId != nodeId_) { f.close(); return false; }
        if (outBase) memcpy(outBase, base, HEF_HASH_LEN);

        uint32_t seq = 0, records = 0, firstSeq = 0;
        uint32_t validBytes = hdrLen;   // fim do ultimo registro COMPLETO
        uint8_t  head[HEF_HASH_LEN];
        memcpy(head, base, HEF_HASH_LEN);

        while (true) {
            uint8_t fixed[HEF_LOG_REC_FIXED];
            if (f.read(fixed, sizeof(fixed)) != sizeof(fixed)) break;
            uint16_t len = getU16be(fixed + 9);
            if (len > HEF_LOG_MAX_DATA) break;
            uint8_t body[HEF_LOG_MAX_DATA];
            if (len && f.read(body, len) != len) break;
            uint8_t h[HEF_HASH_LEN];
            if (f.read(h, HEF_HASH_LEN) != HEF_HASH_LEN) break;

            seq = getU32be(fixed);
            if (records == 0) firstSeq = seq;
            records++;
            memcpy(head, h, HEF_HASH_LEN);
            validBytes = (uint32_t)f.position();
            reportProgress(records);
        }
        uint32_t size = (uint32_t)f.size();
        f.close();

        if (outHead) memcpy(outHead, head, HEF_HASH_LEN);
        if (outSeq) *outSeq = seq;
        if (outRecords) *outRecords = records;
        if (outBytes) *outBytes = size;
        if (outFirstSeq) *outFirstSeq = firstSeq;
        if (outValidBytes) *outValidBytes = validBytes;
        return true;
    }

    // -----------------------------------------------------------------
    // Manifesto de rotacao (HEFLOG.MAN, append-only, 1 JSON por linha)
    // -----------------------------------------------------------------
    void appendManifest(uint16_t index, const char* name,
                        uint32_t records, uint32_t firstSeq, uint32_t lastSeq,
                        uint32_t bytes, const uint8_t* prevHead,
                        const uint8_t* head) {
        char phex[HEF_HASH_LEN * 2 + 1];
        char hex[HEF_HASH_LEN * 2 + 1];
        bytesToHexLocal(prevHead, HEF_HASH_LEN, phex, sizeof(phex));
        bytesToHexLocal(head, HEF_HASH_LEN, hex, sizeof(hex));

        File m = SD.open(HEF_LOG_MANIFEST, FILE_APPEND);
        if (!m) return;
        m.print("{\"v\":1,\"node\":"); m.print(nodeId_);
        m.print(",\"event\":\"rotate\",\"index\":"); m.print(index);
        m.print(",\"name\":\"");  m.print(name);
        m.print("\",\"records\":"); m.print(records);
        m.print(",\"first_seq\":"); m.print(firstSeq);
        m.print(",\"last_seq\":");  m.print(lastSeq);
        m.print(",\"bytes\":");     m.print(bytes);
        m.print(",\"prev_head\":\""); m.print(phex);
        m.print("\",\"head\":\"");    m.print(hex);
        m.print("\",\"utc\":");       m.print(utc_);
        m.println("}");
        m.flush();
        m.close();
    }

    // Le o manifesto e recupera: proximo indice, total de registros
    // arquivados e a cabeca do ULTIMO arquivo fechado.
    bool readManifest(uint16_t* nextIndex, uint32_t* priorRecords,
                      uint8_t* lastHead, uint32_t* lastSeq) {
        File m = SD.open(HEF_LOG_MANIFEST, FILE_READ);
        if (!m) return false;

        uint16_t idx = 0;
        uint32_t tot = 0;
        bool     any = false;
        uint8_t  head[HEF_HASH_LEN];
        uint32_t seq = 0;
        char     line[512];

        while (m.available()) {
            int n = m.readBytesUntil('\n', line, sizeof(line) - 1);
            if (n <= 0) break;
            line[n] = 0;
            if (!strstr(line, "\"event\":\"rotate\"")) continue;

            char* pi = strstr(line, "\"index\":");
            char* pr = strstr(line, "\"records\":");
            char* ps = strstr(line, "\"last_seq\":");
            char* ph = strstr(line, "\"head\":\"");
            if (!pi || !pr || !ps || !ph) continue;

            idx = (uint16_t)strtoul(pi + 8, nullptr, 10);
            uint32_t rec = strtoul(pr + 10, nullptr, 10);
            seq = strtoul(ps + 11, nullptr, 10);
            // Converte o head (hex de 64 caracteres) para bytes.
            bool hok = strlen(ph + 8) >= HEF_HASH_LEN * 2;
            if (hok) {
                for (int i = 0; i < (int)HEF_HASH_LEN; i++) {
                    uint8_t hi = hexVal(ph[8 + i * 2]);
                    uint8_t lo = hexVal(ph[9 + i * 2]);
                    if (hi > 15 || lo > 15) { hok = false; break; }
                    head[i] = (uint8_t)((hi << 4) | lo);
                }
            }
            if (!hok) continue;

            tot += rec;
            any = true;
        }
        m.close();

        if (!any) return false;
        if (nextIndex) *nextIndex = (uint16_t)(idx + 1);
        if (priorRecords) *priorRecords = tot;
        if (lastHead) memcpy(lastHead, head, HEF_HASH_LEN);
        if (lastSeq) *lastSeq = seq;
        return true;
    }

    static uint8_t hexVal(char c) {
        if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
        if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
        if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
        return 0xFF;
    }

    // Procura o proximo indice livre (quando o manifesto nao existe).
    uint16_t probeNextIndex() {
        for (uint16_t i = 0; i < HEF_LOG_MAX_FILES; i++) {
            char name[24];
            archiveName(name, sizeof(name), i);
            if (!SD.exists(name)) return i;
        }
        return HEF_LOG_MAX_FILES;
    }

    static void archiveName(char* out, size_t cap, uint16_t index) {
        snprintf(out, cap, "HEFLOG%03u.BIN", (unsigned)index);
    }

    // -----------------------------------------------------------------
    // Checkpoints (HEFCHK.BIN)
    // -----------------------------------------------------------------
    // Na v5.1.0 o checkpoint e' gravado SEM assinatura: sigLen = 0 e
    // signerId zerado. O formato ja reserva os campos — quando a
    // identidade Ed25519 por dispositivo chegar (fases 2/3.3), os
    // mesmos bytes passam a carregar a assinatura, sem quebra de
    // compatibilidade. O verificador offline distingue os dois casos.
    bool writeCheckpoint(uint16_t fileIndex, uint32_t seq,
                         const uint8_t* head) {
        // O registro tem DUAS partes: a fixa (52 B, sem CRC) e o CRC16
        // (2 B) que a SEGUE. O CRC cobre tudo o que o precede — no
        // caso sem assinatura, os 52 B fixos. Gravar o CRC por cima do
        // campo sigLen (que fica nos bytes 50..51) produzia um
        // "sigLen" igual ao CRC e um checkpoint que nenhum leitor
        // (nem o verify_log.py) conseguia interpretar.
        uint8_t rec[HEF_LOG_CHK_FIXED + 2];
        memcpy(rec, HEF_LOG_CHK_MAGIC, 4);
        putU16be(rec + 4, fileIndex);
        putU32be(rec + 6, seq);
        memcpy(rec + 10, head, HEF_HASH_LEN);
        memset(rec + 10 + HEF_HASH_LEN, 0, 8);    // signerId: sem assinatura
        putU16be(rec + 10 + HEF_HASH_LEN + 8, 0); // sigLen = 0

        // Sem assinatura, o CRC cobre exatamente a parte fixa.
        uint16_t crc = crc16(rec, HEF_LOG_CHK_FIXED);
        putU16be(rec + HEF_LOG_CHK_FIXED, crc);

        File f = SD.open(HEF_LOG_CHECKPOINTS, FILE_APPEND);
        if (!f) return false;
        size_t w = f.write(rec, sizeof(rec));
        f.flush();
        f.close();
        if (w != sizeof(rec)) return false;
        checkpointCount_++;
        return true;
    }

    // Conta os checkpoints existentes no boot (barato: um append por
    // 256 registros, com tamanho fixo por linha).
    void scanCheckpoints() {
        checkpointCount_ = 0;
        File f = SD.open(HEF_LOG_CHECKPOINTS, FILE_READ);
        if (!f) return;
        while (f.available()) {
            uint8_t rec[HEF_LOG_CHK_FIXED];
            if (f.read(rec, HEF_LOG_CHK_FIXED) != HEF_LOG_CHK_FIXED) break;
            if (memcmp(rec, HEF_LOG_CHK_MAGIC, 4) != 0) break;
            uint16_t sigLen = getU16be(rec + 10 + HEF_HASH_LEN + 8);
            if (sigLen > 512) break;
            if (sigLen && f.seek(f.position() + sigLen) != true) break;
            uint8_t crcb[2];
            if (f.read(crcb, 2) != 2) break;
            if (sigLen == 0) {
                // Mesmo CRC do gravador: 52 B fixos (sem assinatura).
                uint16_t crc = crc16(rec, HEF_LOG_CHK_FIXED);
                if (crc != getU16be(crcb)) break;
            }
            checkpointCount_++;
        }
        f.close();
    }

    // -----------------------------------------------------------------
    // Abertura do arquivo atual em append
    // -----------------------------------------------------------------
    bool openAppend() {
        cur_ = SD.open(path_, FILE_APPEND);
        return (bool)cur_;
    }

public:
    FieldLog() : utc_(0), nodeId_(0), nextIndex_(0), priorRecords_(0),
                  archiveCount_(0), checkpointCount_(0), open_(false),
                  corrupt_(false), refusing_(false), cardFull_(false),
                  progressCb_(nullptr), progressCtx_(nullptr) {
        memset(&health_, 0, sizeof(health_));
        strncpy(path_, "HEFLOG.BIN", sizeof(path_) - 1);
    }

    // Registra o callback de progresso das operacoes longas (releitura
    // da cadeia no boot e exportacao JSONL). Passar nullptr desliga.
    void setProgressCallback(FieldLogProgressCb cb, void* ctx) {
        progressCb_  = cb;
        progressCtx_ = ctx;
    }

    // -----------------------------------------------------------------
    // begin: abre (ou cria) o log, recuperando a cadeia existente
    // -----------------------------------------------------------------
    bool begin(uint16_t nodeId, const char* filePath = "HEFLOG.BIN") {
        // Reabrir (retentativa de SD, `format`/`purge`) nao pode deixar
        // um handle antigo aberto: no FATFS cada handle e' um FILE* e
        // o truncate/rename abaixo precisa do arquivo fechado.
        cur_.close();
        nodeId_ = nodeId;
        strncpy(path_, filePath, sizeof(path_) - 1);
        path_[sizeof(path_) - 1] = 0;
        corrupt_  = false;
        refusing_ = false;
        cardFull_ = false;

        batch_.configure(FieldLog::sha256, HEF_LOG_FLUSH_BYTES,
                         HEF_LOG_FLUSH_MS);

        // Indices e totais historicos: do manifesto quando existe.
        uint8_t  lastHead[HEF_HASH_LEN];
        uint32_t lastSeq = 0;
        bool     haveMan = readManifest(&nextIndex_, &priorRecords_,
                                        lastHead, &lastSeq);
        if (!haveMan) nextIndex_ = probeNextIndex();
        if (nextIndex_ >= HEF_LOG_MAX_FILES) nextIndex_ = HEF_LOG_MAX_FILES;
        archiveCount_ = nextIndex_;

        if (SD.exists(path_)) {
            // Arquivo atual existe: recupera a cadeia e o estado para
            // continuar sem reiniciar a numeracao.
            uint8_t  head[HEF_HASH_LEN];
            uint32_t seq = 0, records = 0, bytes = 0, validBytes = 0;
            if (!scanFile(path_, head, &seq, &records, &bytes, nullptr,
                          fileBase_, &validBytes)) {
                // Header invalido/ilegivel: NAO sobrescreve a evidencia
                // e NAO finge que esta gravando. Fail closed visivel
                // (isCorrupt()/isRefusing() aparecem em info/status).
                corrupt_  = true;
                refusing_ = true;
                open_ = false;
                return false;
            }
            if (validBytes < bytes) {
                // Escrita interrompida (brownout/WDT no meio do lote):
                // o arquivo termina com um registro INCOMPLETO. Sem
                // reparar, o proximo append entraria DEPOIS do lixo e
                // o verificador acusaria a cadeia inteira. Os bytes
                // descartados nunca foram confirmados (o commit nao
                // aconteceu), entao trunca-los e' seguro.
                if (truncate(path_, (off_t)validBytes) != 0) {
                    corrupt_  = true;
                    refusing_ = true;
                    open_ = false;
                    return false;
                }
                bytes = validBytes;
            }
            batch_.setChain(head, seq, records);
            batch_.setFileBytes(bytes);
        } else {
            // Arquivo novo: semeia a cadeia a partir do ultimo arquivo
            // fechado (manifesto) ou do ultimo arquivamento (scan).
            uint8_t  prevHead[HEF_HASH_LEN];
            uint32_t startSeq = 0;
            if (haveMan) {
                memcpy(prevHead, lastHead, HEF_HASH_LEN);
                startSeq = lastSeq;
            } else if (archiveCount_ > 0) {
                // Sem manifesto (crash entre rename e manifesto): varre
                // o arquivado mais recente. Operacao longa possivel —
                // o callback de progresso alimenta o watchdog.
                char name[24];
                archiveName(name, sizeof(name), (uint16_t)(archiveCount_ - 1));
                uint32_t seq = 0, records = 0, bytes = 0;
                if (!scanFile(name, prevHead, &seq, &records, &bytes,
                              nullptr)) {
                    chainSeedFor(nodeId_, "HLG6", prevHead);
                    startSeq = 0;
                } else {
                    startSeq = seq;
                    priorRecords_ += records;
                }
            } else {
                chainSeedFor(nodeId_, "HLG6", prevHead);
                startSeq = 0;
            }
            if (!writeHeader6(prevHead)) { open_ = false; return false; }
            memcpy(fileBase_, prevHead, HEF_HASH_LEN);
            batch_.setChain(prevHead, startSeq, 0);
            batch_.setFileBytes(0);
        }

        scanCheckpoints();
        if (!openAppend()) { open_ = false; return false; }
        open_ = true;
        return true;
    }

    bool isOpen() const { return open_; }

    // -----------------------------------------------------------------
    // Estado
    // -----------------------------------------------------------------
    void setTime(uint32_t utc) { utc_ = utc; }
    uint32_t time() const { return utc_; }
    uint32_t recordCount() const { return batch_.recordCount(); }
    uint32_t totalRecordCount() const { return priorRecords_ + batch_.recordCount(); }
    uint32_t seq() const { return batch_.seq(); }
    const uint8_t* chainHead() const { return batch_.chainHead(); }
    uint16_t nextFileIndex() const { return nextIndex_; }
    uint16_t archiveCount() const { return archiveCount_; }
    uint32_t priorRecords() const { return priorRecords_; }
    uint32_t checkpointCount() const { return checkpointCount_; }
    uint32_t fileBytes() const { return batch_.fileBytes(); }
    size_t   pendingBytes() const { return batch_.pendingBytes(); }
    uint32_t pendingRecordCount() const { return batch_.pendingRecordCount(); }
    uint32_t flushCount() const { return batch_.flushCount(); }
    uint32_t writeErrorCount() const { return batch_.writeErrorCount(); }
    uint32_t droppedCount() const { return batch_.droppedCount(); }
    uint32_t retryCount() const { return batch_.retryCount(); }
    bool     isCorrupt() const { return corrupt_; }
    bool     isRefusing() const { return refusing_; }
    bool     isCardFull() const { return cardFull_; }
    const HefSdHealth& health() const { return health_; }

    // -----------------------------------------------------------------
    // append: entra no buffer (a escrita acontece no flush)
    // -----------------------------------------------------------------
    bool append(uint8_t type, const uint8_t* data, uint16_t len) {
        return append(type, data, len, (uint32_t)millis());
    }

    bool append(uint8_t type, const uint8_t* data, uint16_t len,
                uint32_t nowMs) {
        if (!open_ || corrupt_ || refusing_) return false;

        if (!batch_.append(type, utc_, data, len, nowMs)) {
            // Nao coube no buffer: grava o lote e tenta uma vez. Se
            // falhar de novo, o registro e' contabilizado como perdido
            // (dentro do buffer) — nunca descartado silenciosamente.
            flush(nowMs, true);
            if (!batch_.append(type, utc_, data, len, nowMs)) return false;
        }
        return true;
    }

    bool appendText(uint8_t type, const char* text) {
        return append(type, (const uint8_t*)text, (uint16_t)strlen(text));
    }

    // -----------------------------------------------------------------
    // flush: grava o lote pendente (com fsync)
    // -----------------------------------------------------------------
    // Gatilhos (decididos pelo buffer): lote >= HEF_LOG_FLUSH_BYTES ou
    // pendente ha >= HEF_LOG_FLUSH_MS. `force` grava qualquer pendencia
    // (antes de export/reboot/rotacao).
    bool flush(uint32_t nowMs, bool force = false) {
        if (!open_ || corrupt_ || refusing_) return false;
        if (batch_.pendingBytes() == 0) {
            // Sem dado: ainda assim honra um checkpoint vencido.
            return maybeCheckpoint();
        }
        if (!force && !batch_.readyToFlush(nowMs)) {
            return maybeCheckpoint();
        }
        return flushPending();
    }
    bool flush() { return flush((uint32_t)millis(), false); }

    // -----------------------------------------------------------------
    // Saude do cartao
    // -----------------------------------------------------------------
    // Teste de escrita/leitura + espaco livre. Cartao cheio = fail
    // closed: para de aceitar e reporta. NUNCA apaga automaticamente.
    bool healthCheck() {
        health_.mounted = (SD.cardType() != CARD_NONE);
        if (!health_.mounted) {
            health_.writable = false;
            snprintf(health_.note, sizeof(health_.note), "cartao ausente");
            return false;
        }

        uint64_t total = SD.totalBytes();
        uint64_t used  = SD.usedBytes();
        health_.totalBytes = total > 0xFFFFFFFFULL ? 0xFFFFFFFFUL : (uint32_t)total;
        health_.usedBytes  = used  > 0xFFFFFFFFULL ? 0xFFFFFFFFUL : (uint32_t)used;
        health_.freeBytes  = (total > used) ? (uint32_t)(total - used) : 0;

        // Teste de escrita/leitura: 64 bytes com padrao conhecido.
        uint8_t pattern[64];
        for (int i = 0; i < 64; i++) pattern[i] = (uint8_t)(0xA0 + i);
        bool ok = false;
        File f = SD.open(HEF_LOG_HEALTH_FILE, FILE_WRITE);
        if (f) {
            if (f.write(pattern, sizeof(pattern)) == sizeof(pattern)) {
                f.flush();
                f.close();
                File r = SD.open(HEF_LOG_HEALTH_FILE, FILE_READ);
                if (r) {
                    uint8_t back[64];
                    ok = (r.size() == sizeof(pattern));
                    if (ok && r.read(back, sizeof(back)) == sizeof(back)) {
                        ok = (memcmp(back, pattern, sizeof(back)) == 0);
                    } else {
                        ok = false;
                    }
                    r.close();
                }
            } else {
                f.close();
            }
            SD.remove(HEF_LOG_HEALTH_FILE);
        }

        health_.writable = ok;
        health_.checkedMs = (uint32_t)millis();
        if (!ok) {
            snprintf(health_.note, sizeof(health_.note), "teste escrita falhou");
        } else if (health_.freeBytes < HEF_LOG_MIN_FREE_BYTES) {
            snprintf(health_.note, sizeof(health_.note), "cartao cheio");
            cardFull_ = true;
            refusing_ = true;   // fail closed: para de aceitar, nao apaga
        } else {
            snprintf(health_.note, sizeof(health_.note), "ok");
            // Recupera um fail closed anterior quando o cartao voltou a
            // ficar saudavel (troca de cartao, espaco liberado).
            if (refusing_ && !corrupt_) {
                refusing_ = false;
                cardFull_ = false;
            }
        }
        return ok;
    }

    // -----------------------------------------------------------------
    // Rotacao
    // -----------------------------------------------------------------
    // Fecha o arquivo atual, arquiva como HEFLOGnnn.BIN, registra no
    // manifesto e abre um novo com a cadeia continuando da cabeca
    // confirmada. Os registros pendentes (se houver) vao para o novo
    // arquivo: eles ainda nao estao no fechado.
    bool rotate() {
        if (!open_ || corrupt_) return false;

        // Um checkpoint pendente cuja ancora JA esta confirmada no
        // arquivo atual tem de ser gravado ANTES da rotacao: depois
        // dela, o mesmo ponto pertenceria ao arquivo anterior mas o
        // checkpoint carregaria o indice do novo. Uma ancora que ainda
        // esta no buffer fica pendente para o arquivo novo (onde os
        // registros pendentes vao ser gravados).
        if (batch_.checkpointDue() &&
            batch_.checkpointSeq() <= batch_.committedSeq()) {
            if (writeCheckpoint(nextIndex_, batch_.checkpointSeq(),
                                batch_.checkpointHead())) {
                batch_.markCheckpointWritten();
            }
        }

        // O estado CONFIRMADO define o fim do arquivo fechado.
        uint32_t closedRecords = batch_.committedRecords();
        uint32_t closedSeq     = batch_.committedSeq();
        uint32_t closedBytes   = batch_.fileBytes();
        uint8_t  closedHead[HEF_HASH_LEN];
        memcpy(closedHead, batch_.committedHead(), HEF_HASH_LEN);

        // Sem indice livre nao ha rotacao: NAO fecha o arquivo atual
        // (isso deixaria o log sem handle e o lote pendente sem destino)
        // e falha de forma VISIVEL. O operador precisa exportar/purgar.
        if (nextIndex_ >= HEF_LOG_MAX_FILES) {
            refusing_ = true;
            return false;
        }

        cur_.close();

        char name[24];
        archiveName(name, sizeof(name), nextIndex_);
        if (!SD.rename(path_, name)) {
            // Reabre o atual: a rotacao falhou, mas o log continua.
            openAppend();
            return false;
        }

        uint32_t firstSeq = closedSeq ? (closedSeq - closedRecords + 1) : 0;
        // `prev_head` e' a base da cadeia DO ARQUIVO FECHADO (nao a
        // cabeca dele): e' o prevHead do header HLG6 desse arquivo.
        appendManifest(nextIndex_, name, closedRecords, firstSeq, closedSeq,
                       closedBytes, fileBase_, closedHead);

        if (!writeHeader6(closedHead)) {
            open_ = false;
            return false;
        }
        if (!openAppend()) { open_ = false; return false; }

        // O arquivo NOVO comeca exatamente na cabeca confirmada do
        // anterior; os registros pendentes passam a pertencer a ele.
        memcpy(fileBase_, closedHead, HEF_HASH_LEN);
        priorRecords_ += closedRecords;
        archiveCount_++;
        nextIndex_++;
        batch_.beginNewFile();
        return true;
    }

    // Rotacao explicita pedida pelo operador (console `archive`):
    // grava o pendente no arquivo atual ANTES de girar, para que o
    // arquivo arquivado contenha tudo que chegou ate o comando.
    bool archive(uint32_t nowMs) {
        if (!open_ || corrupt_) return false;
        flush(nowMs, true);
        return rotate();
    }

    // -----------------------------------------------------------------
    // purge: exclusao EXPLICITA de toda a evidencia (console)
    // -----------------------------------------------------------------
    // O log NUNCA e' apagado automaticamente. Este metodo existe para o
    // comando `purge confirm` do console — e ele apaga TUDO (arquivos,
    // manifesto e checkpoints), recriando um log vazio.
    bool purgeAll() {
        if (!SD.cardType() || SD.cardType() == CARD_NONE) return false;
        cur_.close();

        // Arquivo atual + arquivados.
        if (SD.exists(path_)) SD.remove(path_);
        File root = SD.open("/");
        if (root) {
            File f = root.openNextFile();
            while (f) {
                const char* nm = f.name();
                if (strncmp(nm, "HEFLOG", 6) == 0 &&
                    strlen(nm) > 6 && strstr(nm + 6, ".BIN") != nullptr) {
                    char name[32];
                    strncpy(name, nm, sizeof(name) - 1);
                    name[sizeof(name) - 1] = 0;
                    f.close();
                    SD.remove(name);
                    f = root.openNextFile();
                    continue;
                }
                f.close();
                f = root.openNextFile();
            }
            root.close();
        }
        SD.remove(HEF_LOG_MANIFEST);
        SD.remove(HEF_LOG_CHECKPOINTS);
        SD.remove("HEFLOG.JSONL");
        SD.remove("HEFLOG.HASH");

        nextIndex_     = 0;
        priorRecords_  = 0;
        archiveCount_  = 0;
        checkpointCount_ = 0;
        corrupt_  = false;
        refusing_ = false;
        cardFull_ = false;

        uint8_t seed[HEF_HASH_LEN];
        chainSeedFor(nodeId_, "HLG6", seed);
        if (!writeHeader6(seed)) { open_ = false; return false; }
        memcpy(fileBase_, seed, HEF_HASH_LEN);
        batch_.setChain(seed, 0, 0);
        batch_.setFileBytes(0);
        if (!openAppend()) { open_ = false; return false; }
        open_ = true;
        return true;
    }

    // -----------------------------------------------------------------
    // Export JSONL (compativel com a v5.0.0, agora com flush antes)
    // -----------------------------------------------------------------
    // Exporta a serie INTEIRA — arquivados (HEFLOGnnn.BIN) na ordem e
    // depois o atual — e nao apenas o arquivo corrente. A v5.0.0
    // exportava so o atual: num cartao com rotacao, o HEFLOG.JSONL
    // omitia tudo o que ja tinha sido arquivado, enquanto o
    // HEFLOG.HASH declarava a integridade do CONJUNTO. O verificador
    // offline agora recusa essa exportacao parcial; aqui ela deixa de
    // existir.
    bool exportJsonl(const char* jsonlPath, const char* hashPath,
                     bool* integrityOk) {
        if (!open_) return false;
        // Tudo que chegou precisa estar no arquivo antes de exporta-lo.
        flush((uint32_t)millis(), true);

        File out = SD.open(jsonlPath, FILE_WRITE);
        if (!out) return false;

        bool     ok = true;
        bool     first = true;
        uint32_t count = 0;
        uint32_t hdrLen = 0;
        uint8_t  prev[HEF_HASH_LEN];
        memset(prev, 0, sizeof(prev));

        // Arquivados em ordem de indice; o atual por ultimo.
        for (uint16_t i = 0; i < nextIndex_; i++) {
            char name[24];
            archiveName(name, sizeof(name), i);
            if (!exportOneJsonl(name, out, &count, prev, first,
                                &hdrLen, &ok)) {
                // Evidencia que o manifesto declara e que nao esta no
                // cartao: exporta o resto, mas nunca como "integro".
                ok = false;
            }
            first = false;
        }
        if (!exportOneJsonl(path_, out, &count, prev, first,
                            &hdrLen, &ok)) {
            ok = false;
        }

        out.close();

        File hf = SD.open(hashPath, FILE_WRITE);
        if (hf) {
            char hex[HEF_HASH_LEN * 2 + 1];
            bytesToHexLocal(prev, HEF_HASH_LEN, hex, sizeof(hex));
            hf.print("{\"records\":"); hf.print(count);
            hf.print(",\"node_id\":");  hf.print(nodeId_);
            hf.print(",\"header\":\""); hf.print(hdrLen == HEF_LOG_HDR6_LEN ? "HLG6" : "HLG5");
            hf.print("\",\"chain_head\":\""); hf.print(hex);
            hf.print("\",\"integrity\":"); hf.print(ok ? "true" : "false");
            hf.println("}");
            hf.close();
        }
        if (integrityOk) *integrityOk = ok;
        return ok;
    }

    // -----------------------------------------------------------------
    // Internos
    // -----------------------------------------------------------------
private:
    // Exporta UM arquivo (arquivado ou atual) para o JSONL ja aberto.
    // `prev` carrega a cabeca do ultimo registro exportado e e'
    // atualizado a cada registro: a cadeia continua entre arquivos.
    // Retorna false se o arquivo nao abriu/nao tem header valido;
    // `ok` vira false em hash incoerente, no de outro no' ou em
    // descontinuidade entre arquivos (a exportacao segue, para nao
    // perder o que ainda existe, mas o HASH final dira integrity:false).
    bool exportOneJsonl(const char* fileName, File& out, uint32_t* count,
                        uint8_t* prev, bool firstFile, uint32_t* hdrLenOut,
                        bool* ok) {
        File in = SD.open(fileName, FILE_READ);
        if (!in) return false;

        // O header diz a base da cadeia: semente no HLG5, prevHead no
        // HLG6. Guarda o magic para so exigir continuidade no HLG6
        // (series HLG5 legadas nao tem encadeamento entre arquivos).
        uint8_t magic[4];
        if (in.read(magic, 4) != 4) { in.close(); return false; }
        in.seek(0);

        uint16_t nodeId = 0;
        uint8_t  base[HEF_HASH_LEN];
        uint32_t hdrLen = 0;
        if (!readHeader(in, &nodeId, base, &hdrLen)) {
            in.close();
            return false;
        }
        if (nodeId != nodeId_) { in.close(); return false; }

        if (firstFile) {
            memcpy(prev, base, HEF_HASH_LEN);
        } else if (memcmp(magic, "HLG6", 4) == 0 &&
                   memcmp(base, prev, HEF_HASH_LEN) != 0) {
            // Este arquivo nao continua a cabeca do anterior: falta
            // evidencia (ou a ordem esta errada). Continua exportando.
            *ok = false;
        }
        *hdrLenOut = hdrLen;

        while (true) {
            uint8_t fixed[HEF_LOG_REC_FIXED];
            if (in.read(fixed, sizeof(fixed)) != sizeof(fixed)) break;
            uint16_t len = getU16be(fixed + 9);
            if (len > HEF_LOG_MAX_DATA) { *ok = false; break; }
            uint8_t body[HEF_LOG_MAX_DATA + HEF_HASH_LEN];
            if (len && in.read(body, len) != len) { *ok = false; break; }
            if (in.read(body + len, HEF_HASH_LEN) != HEF_HASH_LEN) {
                *ok = false; break;
            }

            uint8_t digest[HEF_HASH_LEN];
            uint8_t tmp[HEF_HASH_LEN + HEF_LOG_REC_FIXED + HEF_LOG_MAX_DATA];
            memcpy(tmp, prev, HEF_HASH_LEN);
            memcpy(tmp + HEF_HASH_LEN, fixed, HEF_LOG_REC_FIXED);
            memcpy(tmp + HEF_HASH_LEN + HEF_LOG_REC_FIXED, body, len);
            sha256(tmp, (size_t)(HEF_HASH_LEN + HEF_LOG_REC_FIXED + len), digest);

            if (memcmp(digest, body + len, HEF_HASH_LEN) != 0) *ok = false;

            uint32_t recSeq = getU32be(fixed);
            uint32_t recUtc = getU32be(fixed + 4);
            uint8_t  recType = fixed[8];

            char hex[HEF_HASH_LEN * 2 + 1];
            bytesToHexLocal(body + len, HEF_HASH_LEN, hex, sizeof(hex));

            out.print("{\"seq\":"); out.print(recSeq);
            out.print(",\"utc\":");  out.print(recUtc);
            out.print(",\"type\":"); out.print(recType);
            out.print(",\"data\":\"");
            for (uint16_t i = 0; i < len; i++) {
                uint8_t c = body[i];
                if (c == '"' || c == '\\') out.write('\\');
                if (c >= 32 && c < 127) out.write(c);
                else out.print('?');
            }
            out.print("\",\"hash\":\""); out.print(hex); out.print("\"}");
            out.println();

            memcpy(prev, body + len, HEF_HASH_LEN);
            (*count)++;
            // Progresso: a exportacao pode levar minutos num log
            // grande; o callback e' chamado em pontos de avanco real.
            reportProgress(*count);
        }

        in.close();
        return true;
    }

    // Emite o checkpoint vencido, se houver. Falha em grava-lo NAO e'
    // fatal: o checkpoint continua pendente e e' retentado no proximo
    // flush (o buffer guarda o ponto).
    bool maybeCheckpoint() {
        if (!open_ || corrupt_ || refusing_) return false;
        if (!batch_.checkpointDue()) return true;
        if (writeCheckpoint(nextIndex_, batch_.checkpointSeq(),
                            batch_.checkpointHead())) {
            batch_.markCheckpointWritten();
        }
        return true;
    }

    bool flushPending() {
        // Rotacao ANTES da escrita: o lote pendente ainda nao esta no
        // arquivo atual, e o limite deve valer para o arquivo novo.
        if (batch_.shouldRotate(HEF_LOG_MAX_BYTES)) {
            if (!rotate()) {
                batch_.noteWriteError();
                return false;
            }
        }

        size_t n = batch_.pendingBytes();
        if (n == 0) return maybeCheckpoint();
        if (!cur_) {
            if (!openAppend()) { batch_.noteWriteError(); return false; }
        }

        // Guarda o tamanho do arquivo: se a gravacao for parcial, e'
        // para este tamanho que o arquivo volta (truncate).
        uint32_t prevSize = batch_.fileBytes();
        size_t w = cur_.write(batch_.pendingData(), n);
        if (w == n) cur_.flush();

        // `File::getWriteError()` e' o flag do Print e NAO e' atualizado
        // pelo VFSFileImpl::write: ele nunca acusa erro aqui. O sinal
        // confiavel e' o tamanho do arquivo depois do flush() (que faz
        // fflush + fsync): o fwrite pode aceitar os bytes no buffer
        // stdio e so o fflush falhar (cartao cheio). Gravar o lote e
        // "confirmar" sem que ele esteja no cartao avancaria a cadeia
        // sobre bytes que nao existem.
        bool shortWrite = (w != n) ||
                          (cur_.size() != (size_t)prevSize + w);
        if (shortWrite) {
            // Gravacao parcial/failed: recua o arquivo para o tamanho
            // confirmado anterior e retenta no proximo flush com o
            // MESMO lote (mesmos hashes — a cadeia nao muda).
            cur_.close();
            if (truncate(path_, (off_t)prevSize) != 0) {
                // Sem truncate nao ha como garantir a cauda do arquivo:
                // fail closed (uma cadeia truncada e' indistinguivel de
                // uma manipulada).
                corrupt_ = true;
                refusing_ = true;
                batch_.noteWriteError();
                return false;
            }
            if (!openAppend()) {
                batch_.noteWriteError();
                return false;
            }
            batch_.noteWriteError();
            // Detecta cartao cheio (a causa mais comum de escrita
            // parcial) sem gastar uma escrita extra por lote.
            uint64_t total = SD.totalBytes();
            uint64_t used  = SD.usedBytes();
            uint64_t freeB = (total > used) ? (total - used) : 0;
            if (freeB < HEF_LOG_MIN_FREE_BYTES) {
                cardFull_ = true;
                refusing_ = true;   // fail closed, nunca apaga
            }
            return false;
        }

        if (!batch_.commit((uint32_t)w)) return false;
        return maybeCheckpoint();
    }

public:
    static void bytesToHexLocal(const uint8_t* in, size_t len, char* out, size_t outCap) {
        static const char* hexd = "0123456789ABCDEF";
        if (!in || !out || outCap < len * 2 + 1) return;
        for (size_t i = 0; i < len; i++) {
            out[i * 2]     = hexd[(in[i] >> 4) & 0x0F];
            out[i * 2 + 1] = hexd[in[i] & 0x0F];
        }
        out[len * 2] = 0;
    }
};

#endif // HEF_FIELD_LOG_H
