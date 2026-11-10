// =====================================================================
// tests/anti_replay_persistence.cpp
//
// Teste de unidade do estado anti-replay persistido por par.
//
// VULNERABILIDADE COBERT (v5.0.0 -> v5.1.0):
//   O estado anti-replay do receptor vivia apenas em RAM. Um frame
//   capturado por SDR (com tag GCM legitima) era ACEITO como frame novo
//   depois que o receptor reiniciava, porque o par recomecava sem
//   epoch/contador. O replay era criptograficamente autentico: passava
//   por todas as verificacoes.
//
//   Este teste reproduz o ciclo completo (aceitar -> exportar ->
//   serializar -> "reiniciar" -> desserializar -> hidratar -> replay) e
//   exige que o frame capturado seja REJEITADO.
//
// Roda no HOST (g++), sem hardware.
//
// Compilacao (ver test_functional.sh):
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/anti_replay_persistence.cpp -o /tmp/hef_replay_test
// =====================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "framework.h"
#include "peer_state.h"

// ---------------------------------------------------------------------
// Simula o receptor: guarda de replay + espelho persistido do vault.
// ---------------------------------------------------------------------
struct Receiver {
    PeerReplayGuard guard;
};

// ---------------------------------------------------------------------
// Simula o ciclo completo de persistencia (vault -> NVS -> vault).
// ---------------------------------------------------------------------
static bool persistAndReload(const Receiver& rx, uint16_t nodeId,
                             PeerStateStore* outStore) {
    uint16_t epoch = 0;
    uint32_t ctr = 0;
    rx.guard.exportState(&epoch, &ctr);
    if (!outStore->put(nodeId, epoch, ctr)) return false;

    uint8_t blob[HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN];
    size_t n = outStore->serialize(blob, sizeof(blob));
    if (n == 0) return false;

    // Simula a ida ao NVS: um store novo le o blob gravado.
    PeerStateStore reloaded;
    if (!reloaded.deserialize(blob, n)) return false;
    *outStore = reloaded;
    return true;
}

// ---------------------------------------------------------------------
// 1) PeerStateStore: API basica
// ---------------------------------------------------------------------
static void testStoreBasics() {
    SECTION("PeerStateStore - API basica");

    PeerStateStore s;
    CHECK(s.count() == 0, "store novo esta vazio");

    CHECK(s.put(0x1234, 100, 42), "insere par");
    CHECK(s.put(0x5678, 200, 7),  "insere segundo par");
    CHECK(s.count() == 2, "store tem 2 pares");

    uint16_t ep = 0;
    uint32_t ct = 0;
    CHECK(s.get(0x1234, &ep, &ct) && ep == 100 && ct == 42,
          "get devolve epoch e contador do par");
    CHECK(!s.get(0x9999, &ep, &ct), "get de par inexistente falha");

    CHECK(s.put(0x1234, 101, 43), "atualiza par existente");
    CHECK(s.get(0x1234, &ep, &ct) && ep == 101 && ct == 43,
          "atualizacao sobrescreve epoch/contador");
    CHECK(s.count() == 2, "atualizar nao cria par duplicado");

    CHECK(!s.put(0, 1, 1), "nodeId 0 e' rejeitado");

    uint16_t nid = 0;
    CHECK(s.getByIndex(0, &nid, &ep, &ct) && nid == 0x1234,
          "getByIndex devolve o par pelo indice");
    CHECK(!s.getByIndex(9, &nid, &ep, &ct), "getByIndex fora de faixa falha");

    CHECK(s.remove(0x1234), "remove par");
    CHECK(s.count() == 1, "store tem 1 par apos remocao");
    CHECK(!s.get(0x1234, nullptr, nullptr), "par removido nao e' encontrado");
}

// ---------------------------------------------------------------------
// 2) PeerStateStore: serializacao (formato gravado no vault)
// ---------------------------------------------------------------------
static void testStoreSerialization() {
    SECTION("PeerStateStore - serializacao");

    PeerStateStore s;
    s.put(0x0102, 0x0304, 0x05060708UL);
    s.put(0x1112, 0x1314, 0x15161718UL);

    uint8_t blob[64];
    size_t n = s.serialize(blob, sizeof(blob));
    CHECK(n == 2 * HEF_PEER_STATE_REC_LEN, "serializedSize == 2 registros");

    // Little-endian explicito: o formato nao depende da arquitetura.
    CHECK(blob[0] == 0x02 && blob[1] == 0x01, "nodeId em little-endian");
    CHECK(blob[2] == 0x04 && blob[3] == 0x03, "epoch em little-endian");
    CHECK(blob[4] == 0x08 && blob[5] == 0x07 && blob[6] == 0x06 &&
          blob[7] == 0x05, "counter em little-endian");

    PeerStateStore r;
    CHECK(r.deserialize(blob, n), "deserialize aceita o blob");
    uint16_t ep = 0;
    uint32_t ct = 0;
    CHECK(r.get(0x0102, &ep, &ct) && ep == 0x0304 && ct == 0x05060708UL,
          "round-trip preserva epoch e contador");
    CHECK(r.count() == 2, "round-trip preserva a contagem");

    // Capacidade insuficiente: serialize devolve 0 (falha fechada).
    uint8_t small[4];
    CHECK(s.serialize(small, sizeof(small)) == 0,
          "serialize falha com capacidade insuficiente");

    // Registro corrompido (nodeId == 0) e' descartado.
    uint8_t bad[16];
    memcpy(bad, blob, 16);
    bad[8] = 0; bad[9] = 0;           // segundo registro com nodeId 0
    PeerStateStore r2;
    r2.deserialize(bad, 16);
    CHECK(r2.count() == 1, "registro corrompido (nodeId 0) e' descartado");

    // Blob truncado: carrega apenas os registros completos.
    PeerStateStore r3;
    r3.deserialize(blob, HEF_PEER_STATE_REC_LEN + 3);
    CHECK(r3.count() == 1, "blob truncado carrega so registros completos");
}

// ---------------------------------------------------------------------
// 3) RxSequence: regras estritas de anti-replay
// ---------------------------------------------------------------------
static void testSequenceRules() {
    SECTION("RxSequence - regras de anti-replay");

    RxSequence rx;
    uint32_t lost = 0;

    CHECK(rx.accept(100, 1, &lost) == LINK_RX_ACCEPT, "primeiro frame aceito (TOFU)");
    CHECK(rx.accept(100, 2, &lost) == LINK_RX_ACCEPT, "contador sequencial aceito");
    CHECK(rx.accept(100, 2, &lost) == LINK_RX_REPLAY, "contador repetido -> REPLAY");
    CHECK(rx.accept(100, 1, &lost) == LINK_RX_REPLAY, "contador antigo -> REPLAY");
    CHECK(rx.accept(99, 50, &lost) == LINK_RX_STALE_EPOCH, "epoch antigo -> STALE_EPOCH");
    CHECK(rx.accept(101, 1, &lost) == LINK_RX_ACCEPT, "epoch novo -> nova sessao");
    CHECK(rx.epoch() == 101 && rx.highest() == 1, "epoch novo reseta a janela");

    // Salto dentro da janela: aceito e a perda e' contada.
    RxSequence rx2;
    rx2.accept(10, 1, &lost);
    uint32_t before = rx2.gaps();
    CHECK(rx2.accept(10, 5, &lost) == LINK_RX_ACCEPT, "salto dentro da janela aceito");
    CHECK(lost == 3, "perda dentro da janela e' contada");
    CHECK(rx2.gaps() == before + 3, "acumulador de gaps atualizado");

    // Salto maior que a janela de bits, mas dentro de MAX_GAP: reancora.
    RxSequence rx3;
    rx3.accept(10, 1, &lost);
    uint32_t resyncsBefore = rx3.resyncs();
    CHECK(rx3.accept(10, 2000, &lost) == LINK_RX_ACCEPT,
          "salto grande (dentro de MAX_GAP) reancora e aceita");
    CHECK(rx3.resyncs() == resyncsBefore + 1, "reancoragem contabilizada");
    CHECK(rx3.highest() == 2000, "high-water avancou para o novo contador");

    // Salto absurdo: falha fechada.
    RxSequence rx4;
    rx4.accept(10, 1, &lost);
    CHECK(rx4.accept(10, 1UL + HEF_COUNTER_MAX_GAP + 1, &lost) == LINK_RX_FAR,
          "salto acima de MAX_GAP -> FAR (falha fechada)");
    CHECK(rx4.highest() == 1, "high-water nao avanca em caso de FAR");
}

// ---------------------------------------------------------------------
// 4) PeerReplayGuard: hidratacao e sinalizacao de persistencia
// ---------------------------------------------------------------------
static void testGuardFlags() {
    SECTION("PeerReplayGuard - hidratacao e persistencia");

    PeerReplayGuard g;
    uint32_t lost = 0;

    CHECK(!g.isDirty(), "guarda nova nao esta suja");
    CHECK(!g.needsImmediatePersist(), "guarda nova nao exige persistencia urgente");

    g.accept(500, 1, &lost);
    CHECK(g.isDirty(), "estado avancou -> guarda suja");
    CHECK(g.needsImmediatePersist(), "primeiro contato exige persistencia imediata");

    g.clearPersistFlags();
    CHECK(!g.isDirty(), "flags limpos apos gravacao");

    g.accept(500, 2, &lost);
    CHECK(g.isDirty(), "avanco do contador suja a guarda");
    CHECK(!g.needsImmediatePersist(),
          "avanco do contador (mesmo epoch) nao e' urgente");

    g.accept(501, 1, &lost);
    CHECK(g.needsImmediatePersist(), "epoch novo exige persistencia imediata");

    // Hidratacao a partir de estado persistido.
    PeerReplayGuard h;
    h.hydrate(777, 55);
    CHECK(h.isActive(), "guarda hidratada fica ativa");
    CHECK(h.epoch() == 777 && h.highest() == 55, "estado hidratado");
    CHECK(!h.isDirty(), "hidratacao nao marca a guarda como suja");
    CHECK(h.accept(777, 55, &lost) == LINK_RX_REPLAY,
          "frame repetido apos hidratacao -> REPLAY");
    CHECK(h.accept(777, 56, &lost) == LINK_RX_ACCEPT,
          "frame seguinte apos hidratacao -> aceito");
}

// ---------------------------------------------------------------------
// 5) CENARIO CRITICO: replay de frame capturado apos reinicio do receptor
// ---------------------------------------------------------------------
static void testReplayAfterReboot() {
    SECTION("Replay pos-reboot - cenario critico");

    // --- Receiver online recebe frames normais ---
    Receiver rx;
    uint32_t lost = 0;
    CHECK(rx.guard.accept(1000, 1, &lost) == LINK_RX_ACCEPT, "frame 1 aceito");
    CHECK(rx.guard.accept(1000, 2, &lost) == LINK_RX_ACCEPT, "frame 2 aceito");
    CHECK(rx.guard.accept(1000, 3, &lost) == LINK_RX_ACCEPT, "frame 3 aceito");

    // O atacante captura o frame 2 (epoch 1000, contador 2).
    const uint16_t capturedEpoch   = 1000;
    const uint32_t capturedCounter = 2;

    // --- Persistencia do estado (o que o Node2 grava no vault) ---
    PeerStateStore store;
    CHECK(persistAndReload(rx, 0x2001, &store), "estado persistido e' relido");

    uint16_t ep = 0;
    uint32_t ct = 0;
    CHECK(store.get(0x2001, &ep, &ct) && ep == 1000 && ct == 3,
          "estado persistido contem epoch=1000 e high-water=3");

    // --- REINICIO do receptor ---
    Receiver rx2;                       // tudo em RAM, como depois do boot
    PeerStateStore loaded;
    uint8_t blob[HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN];
    size_t n = store.serialize(blob, sizeof(blob));
    CHECK(loaded.deserialize(blob, n), "estado relido do vault apos o boot");
    CHECK(loaded.get(0x2001, &ep, &ct), "estado do par disponivel apos o boot");
    rx2.guard.hydrate(ep, ct);          // rehidratacao no boot

    // --- O atacante replaya o frame capturado ---
    LinkRxResult r = rx2.guard.accept(capturedEpoch, capturedCounter, &lost);
    CHECK(r != LINK_RX_ACCEPT,
          "REPLAY do frame capturado apos reinicio e' REJEITADO");
    CHECK(r == LINK_RX_REPLAY, "classificado como REPLAY (contador ja visto)");

    // --- Replay de uma sessao ANTERIOR (epoch antigo) ---
    r = rx2.guard.accept(capturedEpoch - 1, 99, &lost);
    CHECK(r == LINK_RX_STALE_EPOCH, "replay de epoch anterior -> STALE_EPOCH");

    // --- E o trafego legitimo continua funcionando ---
    CHECK(rx2.guard.accept(1000, 4, &lost) == LINK_RX_ACCEPT,
          "frame legitimo seguinte e' aceito");
    CHECK(rx2.guard.accept(1001, 1, &lost) == LINK_RX_ACCEPT,
          "nova sessao do emissor (epoch novo) e' aceita");
}

// ---------------------------------------------------------------------
// 6) BASELINE: o comportamento ANTIGO (sem persistencia) era vulneravel
// ---------------------------------------------------------------------
// Este bloco documenta por que a correcao e' necessaria: com o codigo da
// v5.0.0 (estado so em RAM, sem hidratacao no boot) o frame capturado
// DEPOIS do reinicio era aceito. Se a hidratacao deixar de funcionar, o
// teste do cenario 5 falha - mas este bloco mostra a falha concreta.
static void testVulnerableBaseline() {
    SECTION("Baseline v5.0.0 - replay pos-reboot era aceito");

    Receiver rx;
    uint32_t lost = 0;
    rx.guard.accept(1000, 1, &lost);
    rx.guard.accept(1000, 2, &lost);

    // Receptor reinicia: estado perdido, guard sem hidratacao.
    Receiver rxAfterReboot;
    LinkRxResult r = rxAfterReboot.guard.accept(1000, 2, &lost);
    CHECK(r == LINK_RX_ACCEPT,
          "SEM hidratacao o replay e' aceito (vulnerabilidade da v5.0.0)");

    // Com a hidratacao, o mesmo frame e' rejeitado.
    PeerStateStore store;
    store.put(0x2001, 1000, 2);
    uint16_t ep = 0;
    uint32_t ct = 0;
    store.get(0x2001, &ep, &ct);

    Receiver rxFixed;
    rxFixed.guard.hydrate(ep, ct);
    r = rxFixed.guard.accept(1000, 2, &lost);
    CHECK(r == LINK_RX_REPLAY,
          "COM hidratacao o mesmo replay e' rejeitado");
}

// ---------------------------------------------------------------------
// 7) Multiplos pares: estado independente por par
// ---------------------------------------------------------------------
static void testMultiplePeers() {
    SECTION("Multiplos pares - estado independente");

    PeerStateStore s;
    s.put(0x0001, 10, 100);
    s.put(0x0002, 20, 200);
    s.put(0x0003, 30, 300);

    uint8_t blob[HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN];
    size_t n = s.serialize(blob, sizeof(blob));

    PeerStateStore r;
    r.deserialize(blob, n);
    CHECK(r.count() == 3, "3 pares persistidos e relidos");

    uint16_t ep = 0;
    uint32_t ct = 0;
    CHECK(r.get(0x0002, &ep, &ct) && ep == 20 && ct == 200,
          "estado do par do meio preservado");

    // Hidratar um par nao afeta o outro.
    PeerReplayGuard a, b;
    a.hydrate(10, 100);
    b.hydrate(20, 200);
    uint32_t lost = 0;
    CHECK(a.accept(10, 100, &lost) == LINK_RX_REPLAY,
          "par A rejeita replay do proprio contador");
    CHECK(b.accept(20, 201, &lost) == LINK_RX_ACCEPT,
          "par B aceita o proximo contador");
    CHECK(a.accept(10, 101, &lost) == LINK_RX_ACCEPT,
          "par A aceita o proximo contador");
}

// ---------------------------------------------------------------------
// 8) Capacidade do vault: o pior caso precisa caber
// ---------------------------------------------------------------------
// O vault falha FECHADO quando o conteudo nao cabe (descartar uma entrada
// em silencio perderia o epoch persistido). Este bloco prova que o pior
// caso realista - todos os campos no maximo - ainda cabe.
static void testVaultCapacity() {
    SECTION("Capacidade do vault - pior caso cabe");

    const size_t tlvHdr = 3;

    size_t worst = 0;
    worst += tlvHdr + HEF_KEY_LEN;                              // PSK
    worst += tlvHdr + HEF_MAX_ENROLLMENTS * 4;                 // enrollments
    worst += tlvHdr + 2;                                        // node_id
    worst += tlvHdr + 33;                                       // wifi ssid
    worst += tlvHdr + 33;                                       // wifi pass
    worst += tlvHdr + 17;                                       // cli user
    worst += tlvHdr + 33;                                       // cli pass
    worst += tlvHdr + HEF_TOTP_SECRET_MAX;                      // totp
    worst += tlvHdr + HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN;  // peer state

    CHECK(worst <= HEF_VAULT_MAX_PLAIN,
          "pior caso do vault cabe no plaintext disponivel");
    CHECK(HEF_VAULT_MAX_PLAIN + HEF_VAULT_HEADER_LEN + HEF_TAG_LEN
              == HEF_VAULT_BUF,
          "header + plaintext + tag = tamanho do blob");

    // O estado anti-replay de 8 pares ocupa 64 bytes: 12% do vault.
    CHECK(HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN == 64,
          "estado anti-replay de 8 pares ocupa 64 bytes");
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - estado anti-replay persistido\n");
    printf("=====================================================\n");

    testStoreBasics();
    testStoreSerialization();
    testSequenceRules();
    testGuardFlags();
    testReplayAfterReboot();
    testVulnerableBaseline();
    testMultiplePeers();
    testVaultCapacity();

    return heftest::summary("estado anti-replay persistido");
}
