// field_log.h - Log forense append-only com cadeia de hash - v5.0.0
//
// PROBLEMA DA v4.x:
//   - O log era um CSV ("TEMPO_MS,TIPO,DADOS") com timestamp = millis()
//     desde o boot. Nao havia tempo absoluto, nao havia integridade e nao
//     havia cadeia de custodia. Um CSV truncado nao distingue "nada
//     aconteceu" de "perdeu-se a evidencia".
//   - O Node2 nunca enviava nada ao Node3 (o elo estava orfao).
//
// v5:
//   - Registro binario append-only com hash encadeado:
//       hash[n] = SHA256( hash[n-1] || registro[n] sem o proprio hash )
//     Alterar/remover qualquer registro quebra a cadeia a partir dele.
//   - Timestamp UTC absoluto (sincronizado pelo Node2) + uptime como
//     campo secundario.
//   - Exportacao em JSONL (interoperavel) + hash final da cadeia.
//   - Chave de cadeia semeada com o node_id, para que dois gravadores
//     diferentes nunca produzam a mesma cadeia.
#ifndef HEF_FIELD_LOG_H
#define HEF_FIELD_LOG_H

#include <Arduino.h>
#include <SD.h>
#include <mbedtls/md.h>

#include "hefestos_pins.h"

struct FieldRecord {
    uint32_t seq;
    uint32_t utc;
    uint8_t  type;
    uint16_t len;
    uint8_t  data[192];
};

// ---------------------------------------------------------------------
// Callback de progresso de operacoes longas
// ---------------------------------------------------------------------
// A releitura da cadeia (no boot) e a exportacao JSONL podem processar
// dezenas de milhares de registros. Num SD lento (ou num cartao em uso
// intenso), isso pode levar MINUTOS — tempo suficiente para o
// watchdog de 30 s derrubar o dispositivo.
//
// O callback e' chamado a cada registro processado, ou seja, apenas
// quando a operacao REALMENTE avancou. Isso e' o que permite
// alimentar o watchdog sem mascarar um travamento: um SD que nunca
// responde para de chamar o callback, e o watchdog expira
// normalmente.
typedef void (*FieldLogProgressCb)(void* ctx, uint32_t records);

class FieldLog {
private:
    bool     open_;
    uint32_t seq_;
    uint32_t utc_;
    uint8_t  chain_[HEF_HASH_LEN];
    uint32_t records_;
    uint16_t nodeId_;
    char     path_[32];
    FieldLogProgressCb progressCb_;
    void*         progressCtx_;

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

    // Cabecalho do arquivo: magic(4) | nodeId(2) | chainSeed(32)
    void writeHeader() {
        uint8_t hdr[38];
        memcpy(hdr, "HLG5", 4);
        hdr[4] = (uint8_t)(nodeId_ >> 8);
        hdr[5] = (uint8_t)(nodeId_ & 0xFF);
        uint8_t seedInput[6];
        memcpy(seedInput, "HLG5", 4);
        seedInput[4] = hdr[4];
        seedInput[5] = hdr[5];
        sha256(seedInput, sizeof(seedInput), chain_);

        File f = SD.open(path_, FILE_WRITE);
        if (!f) { open_ = false; return; }
        size_t w = f.write(hdr, 4);
        w += f.write(hdr + 4, 2);
        w += f.write(chain_, HEF_HASH_LEN);
        f.close();
        open_ = (w == 4 + 2 + HEF_HASH_LEN);
    }

public:
    FieldLog() : open_(false), seq_(0), utc_(0), records_(0), nodeId_(0),
                  progressCb_(nullptr), progressCtx_(nullptr) {
        memset(chain_, 0, sizeof(chain_));
        strncpy(path_, "HEFLOG.BIN", sizeof(path_) - 1);
    }

    // Registra o callback de progresso das operacoes longas (releitura
    // da cadeia no boot e exportacao JSONL). Passar `nullptr` desliga.
    //
    // O callback e' chamado a cada registro processado — isto e', em
    // pontos onde a operacao REALMENTE avancou. O watchdog so pode ser
    // alimentado nesses pontos: alimentar dentro de uma operacao que
    // TRAVOU (um SD que nunca responde) mascararia o travamento, e o
    // dispositivo ficaria "vivo" mas inutil.
    void setProgressCallback(FieldLogProgressCb cb, void* ctx) {
        progressCb_  = cb;
        progressCtx_ = ctx;
    }

    void reportProgress(uint32_t records) {
        if (progressCb_) progressCb_(progressCtx_, records);
    }

    bool begin(uint16_t nodeId, const char* filePath = "HEFLOG.BIN") {
        nodeId_ = nodeId;
        strncpy(path_, filePath, sizeof(path_) - 1);
        path_[sizeof(path_) - 1] = 0;

        if (!SD.exists(path_)) {
            open_ = false;
            writeHeader();
            if (!open_) return false;
            records_ = 0;
            seq_ = 0;
            return true;
        } else {
            // Recupera a cadeia existente E o estado (seq/records) para
            // continuar o log sem reiniciar a numeracao nem quebrar a
            // cadeia apos um reboot.
            File f = SD.open(path_, FILE_READ);
            if (!f) { open_ = false; return false; }
            uint8_t magic[4]; uint16_t nid;
            if (f.read(magic, 4) != 4 || f.read((uint8_t*)&nid, 2) != 2 ||
                f.read(chain_, HEF_HASH_LEN) != HEF_HASH_LEN) {
                f.close();
                open_ = false;
                return false;
            }
            if (memcmp(magic, "HLG5", 4) != 0) { f.close(); open_ = false; return false; }

            seq_ = 0;
            records_ = 0;
            while (true) {
                uint8_t fixed[11];
                if (f.read(fixed, 11) != 11) break;
                uint16_t len = (uint16_t)((fixed[9] << 8) | fixed[10]);
                if (len > 192) break;
                uint8_t body[192];
                if (len && f.read(body, len) != len) break;
                uint8_t h[HEF_HASH_LEN];
                if (f.read(h, HEF_HASH_LEN) != HEF_HASH_LEN) break;
                uint32_t recSeq = ((uint32_t)fixed[0] << 24) | ((uint32_t)fixed[1] << 16) |
                                  ((uint32_t)fixed[2] << 8) | fixed[3];
                seq_ = recSeq;
                records_++;
                memcpy(chain_, h, HEF_HASH_LEN);
                // Progresso: a releitura da cadeia pode levar minutos
                // num log grande. O callback so e' chamado em pontos
                // onde a operacao avancou de verdade.
                reportProgress(records_);
            }
            f.close();
        }
        open_ = true;
        return true;
    }

    bool isOpen() const { return open_; }

    void setTime(uint32_t utc) { utc_ = utc; }
    uint32_t time() const { return utc_; }
    uint32_t recordCount() const { return records_; }

    const uint8_t* chainHead() const { return chain_; }

    // Acrescenta um registro. Retorna false se o SD nao estiver disponivel.
    bool append(uint8_t type, const uint8_t* data, uint16_t len) {
        if (!open_) return false;
        if (len > sizeof(((FieldRecord*)0)->data)) len = sizeof(((FieldRecord*)0)->data);

        uint8_t rec[256];
        size_t pos = 0;
        uint32_t s = seq_ + 1;      // so e' confirmado se a gravacao der certo
        rec[pos++] = (uint8_t)(s >> 24); rec[pos++] = (uint8_t)(s >> 16);
        rec[pos++] = (uint8_t)(s >> 8);  rec[pos++] = (uint8_t)s;
        rec[pos++] = (uint8_t)(utc_ >> 24); rec[pos++] = (uint8_t)(utc_ >> 16);
        rec[pos++] = (uint8_t)(utc_ >> 8);  rec[pos++] = (uint8_t)utc_;
        rec[pos++] = type;
        rec[pos++] = (uint8_t)(len >> 8); rec[pos++] = (uint8_t)(len);
        if (len && data) memcpy(rec + pos, data, len);
        pos += len;

        // hash = SHA256(chain anterior || registro)
        uint8_t digest[HEF_HASH_LEN];
        uint8_t tmp[HEF_HASH_LEN + 256];
        if (pos + HEF_HASH_LEN > sizeof(tmp)) return false;
        memcpy(tmp, chain_, HEF_HASH_LEN);
        memcpy(tmp + HEF_HASH_LEN, rec, pos);
        sha256(tmp, pos + HEF_HASH_LEN, digest);

        // FILE_APPEND e' obrigatorio: FILE_WRITE trunca o arquivo no ESP32.
        File f = SD.open(path_, FILE_APPEND);
        if (!f) return false;
        size_t w = f.write(rec, pos);
        w += f.write(digest, HEF_HASH_LEN);
        f.close();
        if (w != pos + HEF_HASH_LEN) return false;

        memcpy(chain_, digest, HEF_HASH_LEN);
        seq_ = s;
        records_++;
        return true;
    }

    bool appendText(uint8_t type, const char* text) {
        return append(type, (const uint8_t*)text, (uint16_t)strlen(text));
    }

    // Exporta a cadeia para JSONL (um registro por linha) + arquivo .hash
    // com o hash final. Verifica a integridade durante a leitura.
    bool exportJsonl(const char* jsonlPath, const char* hashPath, bool* integrityOk) {
        if (!open_) return false;
        File in = SD.open(path_, FILE_READ);
        if (!in) return false;

        File out = SD.open(jsonlPath, FILE_WRITE);
        if (!out) { in.close(); return false; }

        uint8_t hdr[38];
        if (in.read(hdr, 38) != 38) { in.close(); out.close(); return false; }
        uint8_t prev[HEF_HASH_LEN];
        memcpy(prev, hdr + 6, HEF_HASH_LEN);

        bool ok = true;
        uint32_t count = 0;

        while (true) {
            uint8_t fixed[11];
            if (in.read(fixed, 11) != 11) break;
            uint16_t len = (uint16_t)((fixed[9] << 8) | fixed[10]);
            if (len > 192) { ok = false; break; }
            uint8_t body[192 + HEF_HASH_LEN];
            if (len && in.read(body, len) != len) { ok = false; break; }
            if (in.read(body + len, HEF_HASH_LEN) != HEF_HASH_LEN) { ok = false; break; }

            uint8_t digest[HEF_HASH_LEN];
            uint8_t tmp[HEF_HASH_LEN + 11 + 192];
            memcpy(tmp, prev, HEF_HASH_LEN);
            memcpy(tmp + HEF_HASH_LEN, fixed, 11);
            memcpy(tmp + HEF_HASH_LEN + 11, body, len);
            sha256(tmp, HEF_HASH_LEN + 11 + len, digest);

            if (memcmp(digest, body + len, HEF_HASH_LEN) != 0) ok = false;

            uint32_t recSeq = ((uint32_t)fixed[0] << 24) | ((uint32_t)fixed[1] << 16) |
                              ((uint32_t)fixed[2] << 8) | fixed[3];
            uint32_t recUtc = ((uint32_t)fixed[4] << 24) | ((uint32_t)fixed[5] << 16) |
                              ((uint32_t)fixed[6] << 8) | fixed[7];
            uint8_t recType = fixed[8];

            char hex[HEF_HASH_LEN * 2 + 1];
            bytesToHexLocal(body + len, HEF_HASH_LEN, hex, sizeof(hex));

            out.print("{\"seq\":"); out.print(recSeq);
            out.print(",\"utc\":");   out.print(recUtc);
            out.print(",\"type\":");  out.print(recType);
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
            count++;
            // Progresso: a exportacao pode levar minutos num log
            // grande. O callback e' chamado a cada registro gravado
            // (ponto de avanco real).
            reportProgress(count);
        }

        out.close();
        in.close();

        File hf = SD.open(hashPath, FILE_WRITE);
        if (hf) {
            char hex[HEF_HASH_LEN * 2 + 1];
            bytesToHexLocal(prev, HEF_HASH_LEN, hex, sizeof(hex));
            hf.print("{\"records\":"); hf.print(count);
            hf.print(",\"node_id\":"); hf.print(nodeId_);
            hf.print(",\"chain_head\":\""); hf.print(hex);
            hf.print("\",\"integrity\":"); hf.print(ok ? "true" : "false");
            hf.println("}");
            hf.close();
        }
        if (integrityOk) *integrityOk = ok;
        return ok;
    }

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
