// field_log_buffer.h - Log forense em LOTES: buffer, cadeia e gatilhos
//                       (puro, testavel no host) - v5.1.0, item 1.6
//
// PROBLEMA DA v5.0.0/v5.1.0
//   O `FieldLog::append()` abria o arquivo no SD, escrevia UM registro
//   e fechava o arquivo — para CADA registro. O plano de escala mediu
//   isso como ~86 mil escritas por dia (1 registro/s) num cartao SD.
//
//   Cada `open/write/close` num cartao FAT nao e' apenas uma escrita
//   de dados: o `close()` atualiza a tabela FAT e o diretorio, o que
//   multiplica as escritas fisicas. O desgaste do cartao e' a principal
//   causa de perda de evidencia em campo: o cartao deixa de ser confiavel
//   no meio de uma operacao.
//
// O QUE ESTE MODULO FAZ
//   Ele separa a DECISAO (o que vai para o buffer, quando flushar,
//   quando rotacionar, quando emitir checkpoint) da OPERACAO (a I/O no
//   SD, que fica em `field_log.h`).
//
//   O buffer e' em RAM: os registros sao serializados e encadeados
//   (hash calculado) NA CHEGADA, e ficam pendentes ate o flush. Isso
//   garante duas propriedades:
//
//     1. A cadeia e' calculada na ordem de chegada. Um registro que
//        fica no buffer e' tao "encadeado" quanto um que ja foi
//        gravado: a ordem forense e' a ordem de chegada, nao a ordem
//        de escrita no disco.
//
//     2. Uma falha de escrita NAO quebra a cadeia. O buffer so e'
//        descartado depois que a gravacao foi confirmada; em caso de
//        falha, os mesmos bytes sao retentados (com o mesmo hash),
//        sem recalcular nada.
//
// FORMATO DO REGISTRO (inalterado desde a v5.0.0)
//
//   seq(4, big-endian) | utc(4, big-endian) | type(1) | len(2, big-endian)
//   | data[len] | hash(32)
//
//   hash = SHA256( chain_anterior || registro_sem_o_proprio_hash )
//
//   A compatibilidade com os logs ja gravados e' OBRIGATORIA (regra 7
//   do plano: "compatibilidade preservada dentro da serie"). Este
//   modulo produz bytes byte-a-byte identicos aos da v5.0.0.
//
// ESTE MODULO E' PURO
//   Nao conhece SD, Arduino nem ESP. A funcao de hash e' INJETADA
//   (o firmware usa mbedtls; o host usa a implementacao de referencia
//   em `tests/sha256_ref.h`). Isso permite testar no host a cadeia
//   completa, os gatilhos de flush, a rotacao e os checkpoints.
#ifndef HEF_FIELD_LOG_BUFFER_H
#define HEF_FIELD_LOG_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hefestos_pins.h"

// ---------------------------------------------------------------------
// Formato do registro
// ---------------------------------------------------------------------
// Cabecalho fixo do registro: seq(4) + utc(4) + type(1) + len(2).
#define HEF_LOG_REC_FIXED    11

// Payload maximo de um registro.
#define HEF_LOG_MAX_DATA     192

// Overhead por registro: cabecalho + hash.
#define HEF_LOG_REC_OVERHEAD (HEF_LOG_REC_FIXED + HEF_HASH_LEN)

// Tamanho maximo de um registro serializado.
#define HEF_LOG_REC_MAX      (HEF_LOG_REC_OVERHEAD + HEF_LOG_MAX_DATA)

// ---------------------------------------------------------------------
// Funcao de hash injetada
// ---------------------------------------------------------------------
// `out` recebe HEF_HASH_LEN bytes. O firmware injeta o SHA-256 do
// mbedtls; o host injeta a implementacao de referencia.
typedef void (*HefHashFn)(const uint8_t* data, size_t len, uint8_t* out);

// ---------------------------------------------------------------------
// Configuracao dos gatilhos
// ---------------------------------------------------------------------
// Tamanho do buffer em RAM (bytes). O plano pede 4 KB de LOTE; o
// buffer tem a margem de um registro maximo para que o gatilho de
// tamanho possa disparar (com cap == lote, o registro que cruzaria o
// limite nao caberia e o gatilho nunca dispararia).
#ifndef HEF_LOG_BUF_CAP
#define HEF_LOG_BUF_CAP     (HEF_LOG_FLUSH_BYTES + HEF_LOG_REC_MAX)
#endif

// Flush por TAMANHO: quando o buffer pendente atinge este valor, o
// firmware grava. E' o gatilho principal: ele limita o numero de
// escritas ao volume real de dados.
//
// O plano de escala pede "< 8 k escritas/dia" partindo de 86,4 k
// (1 escrita por registro a 1 registro/s). Com 4 KB e ~143 B por
// registro, saem ~3,0 k escritas/dia nessa taxa — 28x menos.
//
// Com 1 KB (como o texto do plano Sugere) e o gatilho de TEMPO de 5 s
// (tambem sugerido), o resultado seria 17,3 k escritas/dia: o gatilho
// de tempo dominaria e o numero de escritas SUBIRIA em relacao ao
// alvo. Os dois gatilhos do plano sao INCOMPATIVEIS entre si com o
// KPI de 8 k/dia. Ver README 10.3.
#ifndef HEF_LOG_FLUSH_BYTES
#define HEF_LOG_FLUSH_BYTES 4096
#endif

// Flush por TEMPO: rede de seguranca para nao deixar evidencia
// parada em RAM por muito tempo (limita a perda em caso de brownout).
// So dispara se houver algo pendente.
#ifndef HEF_LOG_FLUSH_MS
#define HEF_LOG_FLUSH_MS    30000UL
#endif

// Intervalo entre checkpoints da cadeia (registros).
#ifndef HEF_LOG_CHECKPOINT_RECORDS
#define HEF_LOG_CHECKPOINT_RECORDS 256UL
#endif

// ---------------------------------------------------------------------
// HefLogBatch
// ---------------------------------------------------------------------
class HefLogBatch {
private:
    HefHashFn hash_;

    uint8_t  buf_[HEF_LOG_BUF_CAP];
    size_t   len_;              // bytes pendentes no buffer
    uint32_t firstPendingMs_;   // instante do 1o registro pendente
    bool     havePending_;

    uint32_t seq_;              // ultimo seq atribuido
    uint32_t records_;          // total de registros encadeados
    uint32_t pendingRecords_;   // registros ainda no buffer (nao gravados)
    uint8_t  chain_[HEF_HASH_LEN];

    // Estado do ultimo lote CONFIRMADO no disco. E' o que define o
    // limite real do arquivo atual: os registros pendentes ainda nao
    // estao nele. Na rotacao, o arquivo fechado termina exatamente
    // neste ponto (seq + cabeca), e o arquivo novo comeca a partir
    // dele.
    uint8_t  committedHead_[HEF_HASH_LEN];
    uint32_t committedSeq_;
    uint32_t committedRecords_;

    uint32_t fileBytes_;        // bytes ja gravados no arquivo atual
    uint32_t flushBytes_;
    uint32_t flushMs_;

    uint32_t sinceCheckpoint_;  // registros desde o ultimo checkpoint
    uint32_t checkpointSeq_;    // seq no momento do checkpoint
    uint8_t  checkpointHead_[HEF_HASH_LEN];
    bool     checkpointPending_;

    // Estatisticas (diagnostico).
    uint32_t flushes_;
    uint32_t writeErrors_;
    uint32_t dropped_;
    uint32_t retries_;

public:
    HefLogBatch()
        : hash_(nullptr), len_(0), firstPendingMs_(0), havePending_(false),
          seq_(0), records_(0), pendingRecords_(0), committedSeq_(0),
          committedRecords_(0), fileBytes_(0),
          flushBytes_(HEF_LOG_FLUSH_BYTES), flushMs_(HEF_LOG_FLUSH_MS),
          sinceCheckpoint_(0), checkpointSeq_(0), checkpointPending_(false),
          flushes_(0), writeErrors_(0), dropped_(0), retries_(0) {
        memset(buf_, 0, sizeof(buf_));
        memset(chain_, 0, sizeof(chain_));
        memset(committedHead_, 0, sizeof(committedHead_));
        memset(checkpointHead_, 0, sizeof(checkpointHead_));
    }

    // -------------------------------------------------------------
    // configure
    // -------------------------------------------------------------
    void configure(HefHashFn hash, uint32_t flushBytes, uint32_t flushMs) {
        hash_ = hash;
        if (flushBytes > 0) flushBytes_ = flushBytes;
        if (flushBytes_ > HEF_LOG_BUF_CAP) flushBytes_ = HEF_LOG_BUF_CAP;
        flushMs_ = flushMs;
    }

    // Reidrata o estado da cadeia (boot / abertura de arquivo).
    void setChain(const uint8_t* head, uint32_t seq, uint32_t records) {
        if (head) memcpy(chain_, head, HEF_HASH_LEN);
        else      memset(chain_, 0, sizeof(chain_));
        seq_     = seq;
        records_ = records;
        pendingRecords_ = 0;
        memcpy(committedHead_, chain_, HEF_HASH_LEN);
        committedSeq_ = seq_;
        committedRecords_ = records_;
        len_ = 0;
        havePending_ = false;
        sinceCheckpoint_ = 0;
        checkpointPending_ = false;
    }

    // -------------------------------------------------------------
    // append: serializa e encadeia um registro no buffer.
    //
    // Retorna false se o registro nao cabe no buffer (o chamador deve
    // fazer flush e tentar de novo). NUNCA descarta silenciosamente:
    // o registro que nao coube e' contabilizado em `dropped()`.
    // -------------------------------------------------------------
    bool append(uint8_t type, uint32_t utc, const uint8_t* data,
                uint16_t len, uint32_t nowMs) {
        if (!hash_) return false;
        if (len > HEF_LOG_MAX_DATA) len = HEF_LOG_MAX_DATA;

        size_t need = HEF_LOG_REC_OVERHEAD + len;
        if (len_ + need > sizeof(buf_)) {
            dropped_++;
            return false;
        }

        size_t base = len_;          // os registros pendentes ficam em [0, len_)
        size_t pos = base;
        uint32_t s = seq_ + 1;

        buf_[pos++] = (uint8_t)(s >> 24); buf_[pos++] = (uint8_t)(s >> 16);
        buf_[pos++] = (uint8_t)(s >> 8);  buf_[pos++] = (uint8_t)s;
        buf_[pos++] = (uint8_t)(utc >> 24); buf_[pos++] = (uint8_t)(utc >> 16);
        buf_[pos++] = (uint8_t)(utc >> 8);  buf_[pos++] = (uint8_t)utc;
        buf_[pos++] = type;
        buf_[pos++] = (uint8_t)(len >> 8);  buf_[pos++] = (uint8_t)len;
        if (len && data) memcpy(buf_ + pos, data, len);
        pos += len;

        // hash = SHA256(chain anterior || registro sem o proprio hash)
        uint8_t tmp[HEF_HASH_LEN + HEF_LOG_REC_MAX];
        memcpy(tmp, chain_, HEF_HASH_LEN);
        memcpy(tmp + HEF_HASH_LEN, buf_ + base, pos - base);
        uint8_t digest[HEF_HASH_LEN];
        hash_(tmp, HEF_HASH_LEN + (pos - base), digest);

        memcpy(buf_ + pos, digest, HEF_HASH_LEN);
        pos += HEF_HASH_LEN;

        // A cadeia avanca AGORA (na chegada), nao na gravacao: a ordem
        // forense e' a ordem de chegada.
        memcpy(chain_, digest, HEF_HASH_LEN);
        seq_ = s;
        records_++;
        pendingRecords_++;
        sinceCheckpoint_++;

        len_ = pos;
        if (!havePending_) {
            firstPendingMs_ = nowMs;
            havePending_ = true;
        }

        if (sinceCheckpoint_ >= HEF_LOG_CHECKPOINT_RECORDS &&
            !checkpointPending_) {
            checkpointPending_ = true;
            checkpointSeq_ = seq_;
            memcpy(checkpointHead_, chain_, HEF_HASH_LEN);
        }
        return true;
    }

    // -------------------------------------------------------------
    // Pendencia
    // -------------------------------------------------------------
    size_t pendingBytes() const { return len_; }
    uint32_t pendingRecordCount() const { return pendingRecords_; }
    size_t spaceLeft() const { return sizeof(buf_) - len_; }
    const uint8_t* pendingData() const { return buf_; }
    uint32_t pendingSinceMs(uint32_t nowMs) const {
        if (!havePending_) return 0;
        return (uint32_t)(nowMs - firstPendingMs_);
    }

    // -------------------------------------------------------------
    // readyToFlush: o firmware deve gravar agora?
    //
    //   - por tamanho: o buffer pendente atingiu `flushBytes_`;
    //   - por tempo:   ha algo pendente ha mais de `flushMs_`.
    //
    // O buffer vazio NUNCA gera flush (escrita vazia = desgaste sem
    // motivo).
    // -------------------------------------------------------------
    bool readyToFlush(uint32_t nowMs) const {
        if (len_ == 0) return false;
        if (len_ >= flushBytes_) return true;
        if (havePending_ && pendingSinceMs(nowMs) >= flushMs_) return true;
        return false;
    }

    // -------------------------------------------------------------
    // commit: a gravacao foi confirmada.
    //
    // `written` deve ser exatamente `pendingBytes()`. Qualquer outro
    // valor e' uma gravacao parcial: o buffer NAO e' descartado (a
    // evidencia fica pendente para retentativa) e o erro e' contado.
    // -------------------------------------------------------------
    bool commit(uint32_t written) {
        if (written != len_) {
            writeErrors_++;
            retries_++;
            return false;
        }
        if (len_ > 0) {
            fileBytes_ += (uint32_t)len_;
            len_ = 0;
            havePending_ = false;
            flushes_++;
            // O estado confirmado avanca junto: e' ele que delimita o
            // que ja esta fisicamente no arquivo atual (rotacao,
            // manifesto e checkpoints usam este ponto, nunca o estado
            // de RAM pendente).
            pendingRecords_ = 0;
            memcpy(committedHead_, chain_, HEF_HASH_LEN);
            committedSeq_ = seq_;
            committedRecords_ = records_;
        }
        return true;
    }

    // Registra uma falha de escrita (o buffer permanece pendente).
    void noteWriteError() {
        writeErrors_++;
        retries_++;
    }

    // -------------------------------------------------------------
    // Rotacao
    // -------------------------------------------------------------
    void setFileBytes(uint32_t bytes) { fileBytes_ = bytes; }
    uint32_t fileBytes() const { return fileBytes_; }

    // Fecha o arquivo atual e abre o novo (rotacao).
    //
    // O arquivo fechado termina no estado CONFIRMADO. Os registros
    // PENDENTES ainda nao estao nele: eles passam a pertencer ao
    // arquivo NOVO, que os recebe no proximo flush. Por isso o estado
    // por arquivo recomeca em `pendingRecords_` (e nao em zero): zerar
    // aqui faria o manifesto do arquivo novo declarar menos registros
    // do que ele realmente tem.
    //
    // `seq_` e `chain_` NAO sao tocados: a cadeia e' global entre
    // arquivos (o header HLG6 do novo arquivo semeia a partir da
    // cabeca confirmada do anterior).
    void beginNewFile() {
        records_          = pendingRecords_;
        committedRecords_ = 0;
        // `fileBytes_` NAO e' zerado aqui: o arquivo novo ja' tem o
        // header hlG6 gravado. Quem chama define o tamanho real com
        // setFileBytes() — zerar faria o proximo flush achar que o
        // arquivo cresceu do nada (short write) e truncar o header.
    }

    // Estado confirmado no disco (limite real do arquivo atual).
    const uint8_t* committedHead() const { return committedHead_; }
    uint32_t committedSeq() const { return committedSeq_; }
    uint32_t committedRecords() const { return committedRecords_; }

    // O arquivo atual deve ser rotacionado antes deste flush?
    //
    // `maxBytes` e' o limite do arquivo (ex.: 64 MB). A decisao leva em
    // conta o que ja esta no arquivo E o que esta pendente no buffer:
    // girar com o buffer pendente exigiria escrever o lote no arquivo
    // novo, o que e' correto e desejavel.
    bool shouldRotate(uint32_t maxBytes) const {
        if (maxBytes == 0) return false;
        return (uint64_t)fileBytes_ + (uint64_t)len_ >= (uint64_t)maxBytes;
    }

    // -------------------------------------------------------------
    // Checkpoints
    // -------------------------------------------------------------
    // Ha um checkpoint a emitir? O checkpoint e' um ponto de ancoragem
    // da cadeia: `seq` + hash da cabeca naquele instante.
    //
    // Na v5.1.0 o checkpoint e' gravado SEM assinatura (a assinatura
    // Ed25519 depende da identidade por dispositivo da Fase 2 e do
    // verificador da Fase 3.3). O verificador offline distingue
    // explicitamente "checkpoint sem assinatura" de "checkpoint
    // assinado" — um checkpoint nao assinado nunca e' apresentado
    // como verificavel por terceiro.
    bool checkpointDue() const { return checkpointPending_; }
    uint32_t checkpointSeq() const { return checkpointSeq_; }
    const uint8_t* checkpointHead() const { return checkpointHead_; }
    void markCheckpointWritten() {
        checkpointPending_ = false;
        // A janela recomeca AQUI: o proximo checkpoint vem
        // HEF_LOG_CHECKPOINT_RECORDS registros depois deste, nao
        // imediatamente (o contador nao pode ter acumulado enquanto o
        // checkpoint anterior estava pendente).
        sinceCheckpoint_ = 0;
    }

    // -------------------------------------------------------------
    // Consultas
    // -------------------------------------------------------------
    const uint8_t* chainHead() const { return chain_; }
    uint32_t seq() const { return seq_; }
    uint32_t recordCount() const { return records_; }
    uint32_t flushCount() const { return flushes_; }
    uint32_t writeErrorCount() const { return writeErrors_; }
    uint32_t droppedCount() const { return dropped_; }
    uint32_t retryCount() const { return retries_; }
    uint32_t flushBytesLimit() const { return flushBytes_; }
    uint32_t flushMsLimit() const { return flushMs_; }

    // -------------------------------------------------------------
    // Estimativa de escritas por dia
    //
    // Usada para provar (no host) que o lote mantem as escritas em
    // menos de 8 k/dia, e para expor a conta na documentacao.
    //
    // `recordsPerDay` e' a taxa de chegada; `avgRecordBytes` e' o
    // tamanho medio serializado de um registro.
    //
    // O numero de flushes por dia e' o maximo entre:
    //   - pelo tamanho: bytes/dia / flushBytes;
    //   - pelo tempo:   86.400.000 ms / flushMs (quando ha dado).
    // -------------------------------------------------------------
    static uint32_t estimatedFlushesPerDay(uint32_t recordsPerDay,
                                           uint32_t avgRecordBytes,
                                           uint32_t flushBytes,
                                           uint32_t flushMs) {
        if (flushBytes == 0) flushBytes = HEF_LOG_FLUSH_BYTES;
        if (flushMs == 0) flushMs = HEF_LOG_FLUSH_MS;
        uint64_t bytesPerDay = (uint64_t)recordsPerDay * avgRecordBytes;
        uint64_t bySize = bytesPerDay / flushBytes;
        // flushMs esta em MILISSEGUNDOS: um dia tem 86.400.000 ms.
        uint64_t byTime = 86400000ULL / flushMs;
        uint64_t n = bySize > byTime ? bySize : byTime;
        if (n > 0xFFFFFFFFULL) n = 0xFFFFFFFFULL;
        return (uint32_t)n;
    }
};

#endif // HEF_FIELD_LOG_BUFFER_H
