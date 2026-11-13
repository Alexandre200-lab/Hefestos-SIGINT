// =====================================================================
// tests/field_log_buffer.cpp
//
// Teste de unidade do log forense em LOTES (item 1.6 do plano).
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/field_log_buffer.cpp -o /tmp/hef_flog_test
//
// FALHA COBERTA
//   A v5.0.0/v5.1.0 gravava UM registro por escrita no SD (open/write/
//   close por registro): a 1 registro/s isso significa ~86,4 mil
//   escritas/dia — o desgaste do cartao e' a principal causa de perda
//   de evidencia em campo. Nenhuma compilacao ou revisao de codigo
//   apontava esse numero: e' uma propriedade de OPERACAO, nao de
//   sintaxe. Este teste fixa o KPI do plano (< 8 mil escritas/dia) e
//   a propriedade estrutural: um lote gravado PARCIALMENTE nao pode
//   avancar o estado confirmado, senao a cadeia fica com um "buraco"
//   indistinguivel de manipulacao.
//
//   Blocos:
//     1. cadeia de hash na ordem de chegada (nao de gravacao);
//     2. formato byte-a-byte compativel com a v5.0.0 (HLG5);
//     3. gatilhos de flush (tamanho, tempo, buffer vazio);
//     4. commit so apos gravacao confirmada; gravacao parcial retenta
//        com os MESMOS bytes (mesmos hashes);
//     5. rotacao: limite do arquivo conta o CONFIRMADO + pendente; o
//        ponto de corte (committed*) delimita o arquivo fechado;
//     6. checkpoints a cada HEF_LOG_CHECKPOINT_RECORDS;
//     7. KPI: escritas/dia < 8 mil (vs 86,4 mil antes) — o teste
//        demonstra que o comportamento ANTERIOR viola o KPI;
//     8. reidratacao da cadeia (setChain) e contadores de diagnostico;
//     9. buffer cheio: registro contabilizado como perdido, nunca
//        descartado silenciosamente; rejeita hash nulo.
//
// Roda no HOST (g++), sem hardware. A funcao de hash e' a referencia
// do NIST (tests/sha256_ref.h), validada no proprio teste.
// =====================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

#include "framework.h"
#include "sha256_ref.h"
#include "field_log_buffer.h"

// ---------------------------------------------------------------------
// Funcao de hash injetada (a mesma assinatura do firmware)
// ---------------------------------------------------------------------
static void refHash(const uint8_t* data, size_t len, uint8_t* out) {
    hefref::sha256(data, len, out);
}

// Hash independente (para conferir o formato byte-a-byte).
static void expectedRecordHash(uint32_t seq, uint32_t utc, uint8_t type,
                               const uint8_t* data, uint16_t len,
                               const uint8_t* prevChain, uint8_t* out) {
    uint8_t tmp[HEF_HASH_LEN + HEF_LOG_REC_FIXED + HEF_LOG_MAX_DATA];
    memcpy(tmp, prevChain, HEF_HASH_LEN);
    size_t pos = HEF_HASH_LEN;
    tmp[pos++] = (uint8_t)(seq >> 24); tmp[pos++] = (uint8_t)(seq >> 16);
    tmp[pos++] = (uint8_t)(seq >> 8);  tmp[pos++] = (uint8_t)seq;
    tmp[pos++] = (uint8_t)(utc >> 24); tmp[pos++] = (uint8_t)(utc >> 16);
    tmp[pos++] = (uint8_t)(utc >> 8);  tmp[pos++] = (uint8_t)utc;
    tmp[pos++] = type;
    tmp[pos++] = (uint8_t)(len >> 8);  tmp[pos++] = (uint8_t)len;
    if (len) memcpy(tmp + pos, data, len);
    pos += len;
    hefref::sha256(tmp, pos, out);
}

// =====================================================================
// 1) Cadeia de hash na ordem de chegada
// =====================================================================
static void testChain() {
    SECTION("cadeia de hash calculada na chegada");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);

    // Cadeia vazia: cabece inicial nula ate a semente ser definida.
    const uint8_t zero[HEF_HASH_LEN] = {0};
    CHECK(memcmp(b.chainHead(), zero, HEF_HASH_LEN) == 0,
          "cadeia comeca nula");

    uint8_t d1[4] = {1, 2, 3, 4};
    CHECK(b.append(0x11, 1000, d1, 4, 0), "1o registro aceito");
    CHECK(b.seq() == 1, "seq = 1");
    CHECK(b.recordCount() == 1, "1 registro contabilizado");

    // Hash esperado: SHA256(0x00*32 || registro sem hash).
    uint8_t exp[HEF_HASH_LEN];
    expectedRecordHash(1, 1000, 0x11, d1, 4, zero, exp);
    CHECK(memcmp(b.chainHead(), exp, HEF_HASH_LEN) == 0,
          "hash[1] = SHA256(zero || registro)");

    // O registro JA encadeou antes de qualquer gravacao: o buffer
    // pendente guarda bytes, mas a ordem forense e' a de chegada.
    uint8_t d2[2] = {9, 9};
    CHECK(b.append(0x12, 1001, d2, 2, 10), "2o registro aceito");
    CHECK(b.seq() == 2, "seq = 2");
    uint8_t exp2[HEF_HASH_LEN];
    expectedRecordHash(2, 1001, 0x12, d2, 2, exp, exp2);
    CHECK(memcmp(b.chainHead(), exp2, HEF_HASH_LEN) == 0,
          "hash[2] = SHA256(hash[1] || registro)");

    // A cabeca so avanca para frente: encadear N resetaria.
    uint32_t seqAntes = b.seq();
    uint8_t  headAntes[HEF_HASH_LEN];
    memcpy(headAntes, b.chainHead(), HEF_HASH_LEN);
    CHECK(b.append(0x13, 1002, d2, 2, 20), "3o registro aceito");
    CHECK(b.seq() == seqAntes + 1, "seq monotonicamente crescente");
    CHECK(memcmp(b.chainHead(), headAntes, HEF_HASH_LEN) != 0,
          "cada registro avanca a cabeca da cadeia");
}

// =====================================================================
// 2) Formato byte-a-byte (compatibilidade com a v5.0.0)
// =====================================================================
static void testFormat() {
    SECTION("formato byte-a-byte identico ao da v5.0.0");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);

    const uint8_t seed[HEF_HASH_LEN] = {0xAB};
    b.setChain(seed, 41, 42);

    // Texto com delimitadores para provar que o "data" e' opaco.
    const char* txt = "T,\"track\",0xAA,0x55";
    uint16_t tlen = (uint16_t)strlen(txt);
    uint32_t utc = 1735689600UL;
    CHECK(b.append(0x07, utc, (const uint8_t*)txt, tlen, 0),
          "registro com payload arbitrario aceito");

    const uint8_t* pend = b.pendingData();
    size_t plen = b.pendingBytes();

    // Tamanho total = 11 (fixo) + payload + 32 (hash).
    CHECK(plen == HEF_LOG_REC_FIXED + (size_t)tlen + HEF_HASH_LEN,
          "tamanho do registro serializado correto");

    // seq(4, big-endian) = 41 + 1 = 42.
    CHECK(pend[0] == 0 && pend[1] == 0 && pend[2] == 0 && pend[3] == 42,
          "seq(4 BE) = 42");
    // utc(4, big-endian).
    CHECK(pend[4] == (uint8_t)(utc >> 24) && pend[5] == (uint8_t)(utc >> 16) &&
          pend[6] == (uint8_t)(utc >> 8)  && pend[7] == (uint8_t)utc,
          "utc(4 BE) correto");
    CHECK(pend[8] == 0x07, "type(1) correto");
    CHECK(pend[9] == (uint8_t)(tlen >> 8) && pend[10] == (uint8_t)tlen,
          "len(2 BE) correto");
    CHECK(memcmp(pend + HEF_LOG_REC_FIXED, txt, tlen) == 0,
          "data copiada sem transformacao (opaca)");

    // Hash do registro = SHA256(seed || registro sem hash) — o mesmo
    // formato que a v5.0.0 gravava (HLG5).
    uint8_t exp[HEF_HASH_LEN];
    expectedRecordHash(42, utc, 0x07, (const uint8_t*)txt, tlen, seed, exp);
    CHECK(memcmp(pend + plen - HEF_HASH_LEN, exp, HEF_HASH_LEN) == 0,
          "hash e' os ultimos 32 bytes e bate com o formato da v5.0.0");

    // O payload com " e \\ nao e' escapado no binario (escapar e'
    // responsabilidade do JSONL na exportacao).
    bool crua = true;
    for (size_t i = 0; i < tlen; i++) {
        if (pend[HEF_LOG_REC_FIXED + i] != (uint8_t)txt[i]) crua = false;
    }
    CHECK(crua, "binario nao escapa o payload (compatibilidade)");
}

// =====================================================================
// 3) Gatilhos de flush
// =====================================================================
static void testTriggers() {
    SECTION("gatilhos de flush (tamanho, tempo, buffer vazio)");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);

    uint8_t d[8] = {0};
    CHECK(!b.readyToFlush(0), "buffer vazio NUNCA dispara flush");

    // Por tamanho: enche ate o gatilho.
    uint32_t n = 0;
    while (b.pendingBytes() < HEF_LOG_FLUSH_BYTES && b.append(1, 1, d, 8, n))
        n++;
    CHECK(b.readyToFlush(0), "atingiu o gatilho de tamanho");
    CHECK(b.pendingBytes() >= HEF_LOG_FLUSH_BYTES,
          "pendente >= HEF_LOG_FLUSH_BYTES");

    // Por tempo: pouco dado, mas velho.
    HefLogBatch b2;
    b2.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    CHECK(b2.append(1, 1, d, 8, 100000), "registro aceito");
    CHECK(!b2.readyToFlush(100000 + HEF_LOG_FLUSH_MS - 1),
          "antes do prazo de tempo: nao dispara");
    CHECK(b2.readyToFlush(100000 + HEF_LOG_FLUSH_MS),
          "no prazo de tempo: dispara (rede de seguranca)");

    // Buffer cheio: registros maximos cabem ate o limite e o excedente
    // e' recusado (contabilizado, nunca descartado em silencio).
    HefLogBatch b3;
    b3.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    uint16_t grande = HEF_LOG_MAX_DATA;
    uint32_t fits = 0;
    while (b3.append(1, 1, nullptr, grande, fits)) fits++;
    CHECK(fits > 0, "registros maximos cabem ate o limite do buffer");
    CHECK(b3.droppedCount() == 1, "recusa contabilizada como perdida");
    CHECK(b3.pendingBytes() <= HEF_LOG_BUF_CAP,
          "buffer nunca ultrapassa a capacidade");

    // Sem hash configurado: recusa segura (nunca encadeia sem hash).
    HefLogBatch b4;
    CHECK(!b4.append(1, 1, d, 8, 0), "sem hash injetado: recusa");
}

// =====================================================================
// 4) Commit, gravacao parcial e retentativa
// =====================================================================
static void testCommitAndRetry() {
    SECTION("commit so apos gravacao confirmada (gravacao parcial)");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    uint8_t d[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    for (int i = 0; i < 3; i++) b.append(2, 100 + (uint32_t)i, d, 8, (uint32_t)i);

    size_t pend = b.pendingBytes();

    // Escrita menor que o lote: NAO confirma.
    CHECK(!b.commit((uint32_t)pend - 1), "gravacao parcial e' recusada");
    CHECK(b.pendingBytes() == pend, "lote permanece pendente");
    CHECK(b.writeErrorCount() == 1, "erro de escrita contabilizado");
    CHECK(b.retryCount() == 1, "retentativa contabilizada");

    // Os bytes pendentes NAO mudaram: a retentativa grava o MESMO lote
    // com os MESMOS hashes (a cadeia nao e' recalculada, entao uma
    // falha de escrita nao quebra a cadeia).
    std::vector<uint8_t> antes(b.pendingData(), b.pendingData() + pend);
    b.append(2, 200, d, 8, 10);   // chegada nova durante a falha
    bool iguais = (memcmp(b.pendingData(), antes.data(), pend) == 0);
    CHECK(iguais, "bytes anteriores preservados (retentativa identica)");

    // Confirmando o lote inteiro: estado avanca.
    size_t total = b.pendingBytes();
    CHECK(b.commit((uint32_t)total), "gravacao integral confirmada");
    CHECK(b.pendingBytes() == 0, "buffer esvaziado");
    CHECK(b.flushCount() == 1, "flush contabilizado");
    CHECK(b.fileBytes() == total, "bytes do arquivo avancam com o commit");

    // O estado CONFIRMADO (rotacao) reflete a gravacao confirmada.
    CHECK(b.committedSeq() == b.seq(), "seq confirmado = seq atual");
    CHECK(b.committedRecords() == b.recordCount(),
          "registros confirmados = registros atuais");
    CHECK(b.pendingRecordCount() == 0, "sem registros pendentes");
    CHECK(memcmp(b.committedHead(), b.chainHead(), HEF_HASH_LEN) == 0,
          "cabeca confirmada = cabeca atual");

    // noteWriteError: usado quando a I/O falha antes de gravar.
    uint32_t err = b.writeErrorCount();
    b.noteWriteError();
    CHECK(b.writeErrorCount() == err + 1, "noteWriteError contabiliza");
}

// =====================================================================
// 5) Rotacao
// =====================================================================
static void testRotation() {
    SECTION("rotacao: limite conta confirmado + pendente");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    uint8_t d[8] = {0};

    // Sem limite (0): nunca rotaciona.
    CHECK(!b.shouldRotate(0), "limite 0 = rotacao desativada");

    // Nada pendente e arquivo abaixo do limite.
    b.setFileBytes(HEF_LOG_MAX_BYTES - 1000);
    CHECK(!b.shouldRotate(HEF_LOG_MAX_BYTES), "abaixo do limite: nao gira");

    // Pendente empurra o total para cima do limite.
    b.append(1, 1, d, 8, 0);
    size_t rec = HEF_LOG_REC_OVERHEAD + 8;
    b.setFileBytes(HEF_LOG_MAX_BYTES - rec + 1);
    CHECK(b.shouldRotate(HEF_LOG_MAX_BYTES),
          "confirmado + pendente >= limite: gira ANTES de gravar");

    // O ponto de corte e' o estado confirmado: o arquivo fechado
    // termina em committedSeq/committedHead, e o lote pendente vai
    // para o arquivo novo (que comeca com prevHead = committedHead).
    uint8_t  cHead[HEF_HASH_LEN];
    uint32_t cSeq, cRec;
    memcpy(cHead, b.committedHead(), HEF_HASH_LEN);
    cSeq = b.committedSeq();
    cRec = b.committedRecords();

    // Simula a rotacao: o arquivo novo comeca em 0 e recebe o lote
    // pendente (o fechado terminou em committed*).
    b.setFileBytes(0);
    CHECK(b.commit((uint32_t)b.pendingBytes()), "lote gravado no arquivo novo");
    CHECK(b.committedSeq() > cSeq, "seq confirmado avanca apos o lote novo");
    CHECK(memcmp(b.committedHead(), cHead, HEF_HASH_LEN) != 0,
          "cabeca confirmada avanca (prevHead do proximo corte)");
    CHECK(b.fileBytes() == rec, "arquivo novo comeca em 0 + lote");

    // setChain (abertura de arquivo novo) reinicia o estado por arquivo.
    b.setChain(cHead, cSeq, cRec);
    CHECK(b.seq() == cSeq && b.recordCount() == cRec,
          "setChain restaura estado por arquivo");
    CHECK(b.fileBytes() == rec,
          "setChain NAO mexe nos bytes do arquivo (setFileBytes e' quem define)");

    // Regressao: DUAS rotacoes seguidas. O contador POR ARQUIVO nao
    // pode acumular os registros do arquivo anterior — se acumular, o
    // manifesto do 2o arquivamento declara records/first_seq errados e
    // o verificador offline RECUSA o cartao.
    HefLogBatch r;
    r.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    uint8_t seed[HEF_HASH_LEN] = {0x5A};
    r.setChain(seed, 0, 0);
    auto gravar = [&](int n) {
        for (int i = 0; i < n; i++) r.append(1, (uint32_t)i, d, 8, 0);
        r.commit((uint32_t)r.pendingBytes());
    };
    gravar(3);
    CHECK(r.committedRecords() == 3, "arquivo 0: 3 registros confirmados");
    uint32_t seq0 = r.committedSeq();
    r.beginNewFile();
    r.setFileBytes(0);
    gravar(4);
    CHECK(r.committedRecords() == 4,
          "arquivo 1: contador POR ARQUIVO reinicia (nao acumula o 0)");
    CHECK(r.committedSeq() == seq0 + 4, "seq continua entre arquivos");
    CHECK(r.committedSeq() - r.committedRecords() + 1 == seq0 + 1,
          "first_seq do arquivo 1 nao volta ao inicio da serie");

    // Rotacao com lote PENDENTE: os pendentes vao para o arquivo novo.
    r.append(1, 1, d, 8, 0);
    r.append(1, 1, d, 8, 0);
    r.beginNewFile();
    r.setFileBytes(0);
    CHECK(r.recordCount() == 2, "pendentes passam a pertencer ao arquivo novo");
    CHECK(r.committedRecords() == 0, "nada confirmado no arquivo novo ainda");
    r.commit((uint32_t)r.pendingBytes());
    CHECK(r.committedRecords() == 2, "pendentes confirmados no arquivo novo");
}

// =====================================================================
// 6) Checkpoints
// =====================================================================
static void testCheckpoints() {
    SECTION("checkpoints a cada HEF_LOG_CHECKPOINT_RECORDS");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    uint8_t d[4] = {0};

    // Grava o lote a cada registro (simula o flush do firmware) para
    // que o buffer nao encha: o checkpoint e' uma decisao de CHEGADA.
    auto chegada = [&](uint32_t i) {
        b.append(1, i, d, 4, i);
        b.commit((uint32_t)b.pendingBytes());
    };

    // Ate 255 registros: sem checkpoint.
    for (uint32_t i = 0; i < HEF_LOG_CHECKPOINT_RECORDS - 1; i++) chegada(i);
    CHECK(!b.checkpointDue(), "antes do limite: sem checkpoint pendente");

    // O 256o vence o checkpoint (na chegada, nao na gravacao).
    chegada(255);
    CHECK(b.checkpointDue(), "ao atingir o limite: checkpoint pendente");
    CHECK(b.checkpointSeq() == HEF_LOG_CHECKPOINT_RECORDS,
          "checkpoint aponta o seq do limite");

    // E permanece pendente APOS a gravacao do lote: o checkpoint e'
    // ancorado na chegada, confirmado pelo firmware ao gravar HEFCHK.
    CHECK(b.checkpointDue(),
          "checkpoint continua pendente apos o flush do lote");

    // Somente UM checkpoint por janela (o proximo vence em 2x limite).
    uint32_t seqNoCp = b.checkpointSeq();
    uint8_t  headNoCp[HEF_HASH_LEN];
    memcpy(headNoCp, b.checkpointHead(), HEF_HASH_LEN);
    for (uint32_t i = 0; i < HEF_LOG_CHECKPOINT_RECORDS; i++) {
        chegada(1000 + i);
    }
    CHECK(b.checkpointSeq() == seqNoCp,
          "checkpoint anterior ainda pendente (nao sobrescrito)");
    CHECK(memcmp(b.checkpointHead(), headNoCp, HEF_HASH_LEN) == 0,
          "cabeca do checkpoint anterior preservada");

    // markCheckpointWritten encerra a janela.
    b.markCheckpointWritten();
    CHECK(!b.checkpointDue(), "checkpoint confirmado: janela encerrada");

    // O PROXIMO checkpoint vem HEF_LOG_CHECKPOINT_RECORDS registros
    // depois do anterior (nao imediatamente, apesar de a janela
    // anterior ter acumulado registros enquanto estava pendente).
    for (uint32_t i = 0; i < HEF_LOG_CHECKPOINT_RECORDS - 1; i++) {
        chegada(2000 + i);
    }
    CHECK(!b.checkpointDue(), "janela nova ainda nao venceu");
    chegada(3000);
    CHECK(b.checkpointDue(), "nova janela vence 1x limite apos a anterior");
    CHECK(b.checkpointSeq() == 3 * HEF_LOG_CHECKPOINT_RECORDS,
          "seq do novo checkpoint correto");

    // setChain limpa checkpoint pendente (abertura de arquivo).
    b.setChain(d, 0, 0);
    CHECK(!b.checkpointDue(), "setChain reinicia a janela de checkpoint");
}

// =====================================================================
// 7) KPI: escritas por dia
// =====================================================================
static void testWritesPerDay() {
    SECTION("KPI do plano: < 8 mil escritas/dia (vs 86,4 mil antes)");

    // Taxa de referência do plano: 1 registro/s, ~143 B por registro
    // (11 fixo + 100 de payload medio + 32 de hash).
    const uint32_t regsPorDia = 86400;
    const uint32_t bytesMedios = 143;

    // ---- O comportamento ANTERIOR viola o KPI ----
    // v5.0.0: 1 escrita por registro (open/write/close por registro).
    uint32_t antes = regsPorDia;
    CHECK(antes > 8000,
          "comportamento anterior (1 escrita/registro) VIOLA o KPI de 8k/dia");
    CHECK(antes == 86400, "86,4 mil escritas/dia na taxa de referencia");

    // ---- O comportamento ATUAL cumpre o KPI ----
    uint32_t agora = HefLogBatch::estimatedFlushesPerDay(
        regsPorDia, bytesMedios, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);

    // Pelo tamanho: 86400*143/4096 = 3016.
    // Pelo tempo (rede de seguranca): 86400/30 = 2880 (so quando ha
    // dado chegando devagar; a 1/s o gatilho de tamanho domina).
    CHECK(agora == 3016, "lote 4 KB -> 3016 escritas/dia (gatilho de tamanho)");
    CHECK(agora < 8000, "KPI do plano cumprido (< 8 mil escritas/dia)");
    CHECK(agora * 28 < antes,
          "pelo menos 28x menos escritas que a v5.0.0");

    // O gatilho de tempo so domina quando a taxa de chegada e' baixa.
    // 1 registro a cada 60 s: 1440/dia pelo tempo vs ~5 pelo tamanho.
    uint32_t devagar = HefLogBatch::estimatedFlushesPerDay(
        1440, bytesMedios, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);
    CHECK(devagar == 2880,
          "taxa baixa: o gatilho de tempo domina (rede de seguranca)");
    CHECK(devagar < 8000, "mesmo devagar, o KPI e' cumprido");

    // Parametros invalidos: fallback seguro.
    CHECK(HefLogBatch::estimatedFlushesPerDay(86400, 143, 0, 0) == agora,
          "parametros 0 usam os padroes do firmware");
}

// =====================================================================
// 8) Reidratacao e contadores
// =====================================================================
static void testRehydration() {
    SECTION("reidratacao da cadeia (boot) e contadores");

    HefLogBatch b;
    b.configure(refHash, HEF_LOG_FLUSH_BYTES, HEF_LOG_FLUSH_MS);

    // O boot varre o arquivo e restaura seq/registros/cabeca.
    uint8_t head[HEF_HASH_LEN];
    for (int i = 0; i < HEF_HASH_LEN; i++) head[i] = (uint8_t)(i + 1);
    b.setChain(head, 1234, 5678);

    CHECK(b.seq() == 1234, "seq restaurado");
    CHECK(b.recordCount() == 5678, "contador restaurado");
    CHECK(memcmp(b.chainHead(), head, HEF_HASH_LEN) == 0, "cabeca restaurada");
    CHECK(b.pendingBytes() == 0, "buffer inicia vazio");

    // O proximo registro continua a numeracao (nunca reinicia).
    uint8_t d[2] = {7, 7};
    CHECK(b.append(3, 999, d, 2, 0), "registro apos o boot aceito");
    CHECK(b.seq() == 1235, "seq continua (nunca reinicia a numeracao)");
    CHECK(b.recordCount() == 5679, "contador continua");

    uint8_t exp[HEF_HASH_LEN];
    expectedRecordHash(1235, 999, 3, d, 2, head, exp);
    CHECK(memcmp(b.chainHead(), exp, HEF_HASH_LEN) == 0,
          "hash calculado sobre a cabeca restaurada");

    // setChain com nullptr: cadeia zerada (fail-safe).
    b.setChain(nullptr, 0, 0);
    const uint8_t zero[HEF_HASH_LEN] = {0};
    CHECK(memcmp(b.chainHead(), zero, HEF_HASH_LEN) == 0,
          "setChain(nullptr) zera a cadeia");
    CHECK(b.seq() == 0 && b.recordCount() == 0, "estado zerado");
}

// =====================================================================
// main
// =====================================================================
int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - log forense em lotes (item 1.6)\n");
    printf("=====================================================\n");

    // O hash de referencia DEVE bater com o NIST antes de qualquer
    // verificacao da cadeia: nunca se valida uma cadeia com um hash
    // que nao e' o padrao.
    SECTION("referencia SHA-256 (vetores NIST FIPS 180-4)");
    CHECK(hefref::selfTest(), "implementacao de referencia bate com o NIST");

    testChain();
    testFormat();
    testTriggers();
    testCommitAndRetry();
    testRotation();
    testCheckpoints();
    testWritesPerDay();
    testRehydration();

    return heftest::summary("log forense em lotes");
}
