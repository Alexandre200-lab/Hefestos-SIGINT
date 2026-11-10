// =====================================================================
// tests/tx_policy.cpp
//
// Teste de unidade da politica de TX adaptativa (item 1.3 do plano).
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/tx_policy.cpp -o /tmp/hef_txpolicy_test
//
// VULNERABILIDADE / FALHA COBERTA
//   A v5.0.0 transmitia PERIODICAMENTE (1 frame/30 s), sem importar se o
//   alvo tivesse se movido. Numa frota, isso e' desperdicio de espectro
//   e de energia. Alem disso, um alvo PARADO era indistinguivel de um
//   alvo que saiu de campo.
//
//   Este teste cobre:
//     - transmissao por MOVIMENTO (acima do limiar);
//     - NAO transmissao por movimento abaixo do limiar;
//     - HEARTBEAT periodico mesmo parado (o no precisa ficar vivo);
//     - o PISO de intervalo (um alvo em movimento perpetuo nao pode
//       inundar o enlace);
//     - sem fix GNSS: so o heartbeat dispara;
//     - o beacon FM: duty cycle proprio e corte automatico por bateria.
//
// Roda no HOST (g++), sem hardware.
// =====================================================================
#include <cstdio>
#include <cstdint>

#include "framework.h"
#include "tx_policy.h"

// ---------------------------------------------------------------------
// 1) Distancia (Haversine)
// ---------------------------------------------------------------------
static void testDistance() {
    SECTION("Distancia - Haversine");

    // 1 grau de latitude ~= 111,19 km.
    double d = hefHaversineMeters(0.0, 0.0, 1.0, 0.0);
    CHECK(d > 111000.0 && d < 111300.0, "1 grau de latitude ~ 111,2 km");

    // 1 grau de longitude no equador ~= 111,19 km.
    d = hefHaversineMeters(0.0, 0.0, 0.0, 1.0);
    CHECK(d > 111000.0 && d < 111300.0, "1 grau de longitude no equador ~ 111,2 km");

    // Mesma posicao -> 0.
    d = hefHaversineMeters(-23.5505, -46.6333, -23.5505, -46.6333);
    CHECK(d < 0.001, "mesma posicao -> distancia nula");

    // Distancia pequena e' precisa (metros).
    // 0,0001 grau de latitude ~= 11,1 m.
    d = hefHaversineMeters(-23.5505, -46.6333, -23.5504, -46.6333);
    CHECK(d > 10.0 && d < 12.0, "0,0001 grau de latitude ~ 11,1 m");

    // 10 metros e' o limiar padrao: um alvo parado nao deve disparar.
    d = hefHaversineMeters(0.0, 0.0, 0.0, 0.0001);
    CHECK(d < 20.0, "deslocamento de ~11 m fica abaixo do limiar de 10 m?");

    // Simetria.
    double a = hefHaversineMeters(10.0, 20.0, -30.0, 40.0);
    double b = hefHaversineMeters(-30.0, 40.0, 10.0, 20.0);
    CHECK(a > 0 && (a - b < 0.001) && (b - a < 0.001), "haversine e' simetrica");
}

// ---------------------------------------------------------------------
// 2) Politica de TX: movimento
// ---------------------------------------------------------------------
static void testMoveTrigger() {
    SECTION("TX por evento - movimento");

    HefTxPolicy p;
    p.configure(10.0,   // limiar: 10 m
                60000UL, // heartbeat: 60 s
                30000UL);// piso de intervalo: 30 s

    // Primeiro contato: heartbeat.
    CHECK(p.evaluate(0, true, -23.55, -46.63) == HEF_TX_TRIGGER_HEARTBEAT,
          "primeiro contato dispara heartbeat");
    p.onTransmitted(0, true, -23.55, -46.63);

    // Dentro do piso de intervalo: nada, mesmo que o alvo se mova.
    CHECK(p.evaluate(10000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "piso de intervalo bloqueia TX aos 10 s");
    CHECK(p.evaluate(29000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "piso de intervalo bloqueia TX aos 29 s");

    // Passou o piso, mas o alvo nao se moveu: nada (heartbeat ainda nao).
    CHECK(p.evaluate(30000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "sem movimento e sem heartbeat: nao transmite");

    // Movimento de 5 m (abaixo do limiar): nada.
    CHECK(p.evaluate(31000, true, -23.55004, -46.63) == HEF_TX_TRIGGER_NONE,
          "movimento de ~5 m (abaixo do limiar) nao dispara");

    // Movimento de ~44 m (0,0004 grau de latitude): dispara.
    CHECK(p.evaluate(32000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_MOVE,
          "movimento de ~44 m (acima do limiar) dispara TX");
    p.noteTrigger(HEF_TX_TRIGGER_MOVE);
    p.onTransmitted(32000, true, -23.5496, -46.63);
    CHECK(p.events() == 1, "contador de eventos de movimento incremented");
    CHECK(p.lastDistanceM() > 40.0 && p.lastDistanceM() < 50.0,
          "distancia medida ~44 m");
}

// ---------------------------------------------------------------------
// 3) Politica de TX: heartbeat
// ---------------------------------------------------------------------
static void testHeartbeat() {
    SECTION("TX por evento - heartbeat");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    p.evaluate(0, true, -23.55, -46.63);
    p.onTransmitted(0, true, -23.55, -46.63);

    // Alvo PARADO: so transmite quando o heartbeat vence.
    CHECK(p.evaluate(30000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "parado aos 30 s: ainda nao e' heartbeat");
    CHECK(p.evaluate(59000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "parado aos 59 s: ainda nao e' heartbeat");
    CHECK(p.evaluate(60000, true, -23.55, -46.63) == HEF_TX_TRIGGER_HEARTBEAT,
          "parado aos 60 s: heartbeat dispara");

    // Repete o ciclo.
    p.onTransmitted(60000, true, -23.55, -46.63);
    CHECK(p.evaluate(119999, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "segundo ciclo: nada antes de 60 s");
    CHECK(p.evaluate(120000, true, -23.55, -46.63) == HEF_TX_TRIGGER_HEARTBEAT,
          "segundo ciclo: heartbeat aos 120 s");
    p.noteTrigger(HEF_TX_TRIGGER_HEARTBEAT);
    CHECK(p.heartbeats() == 1, "contador de heartbeats incrementado");
}

// ---------------------------------------------------------------------
// 4) Politica de TX: sem fix GNSS
// ---------------------------------------------------------------------
static void testNoFix() {
    SECTION("TX por evento - sem fix GNSS");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    // Sem fix: o primeiro contato ainda e' heartbeat (a base precisa
    // saber que o no esta vivo).
    CHECK(p.evaluate(0, false, 0.0, 0.0) == HEF_TX_TRIGGER_HEARTBEAT,
          "sem fix: primeiro contato ainda e' heartbeat");
    p.onTransmitted(0, false, 0.0, 0.0);

    // Sem fix, o "movimento" nao pode ser estimado: nao dispara por
    // evento, so por heartbeat.
    CHECK(p.evaluate(31000, false, 10.0, 10.0) == HEF_TX_TRIGGER_NONE,
          "sem fix: nao ha evento de movimento");
    CHECK(p.evaluate(60000, false, 0.0, 0.0) == HEF_TX_TRIGGER_HEARTBEAT,
          "sem fix: heartbeat continua funcionando");

    // Com fix agora, um movimento real dispara (apos o piso de intervalo).
    p.onTransmitted(60000, false, 0.0, 0.0);
    CHECK(p.evaluate(61000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "primeiro fix apenas establish a referencia (sem evento)");
    p.onTransmitted(61000, true, -23.55, -46.63);
    // O piso de 30 s ainda se aplica: so aos 91 s o movimento dispara.
    CHECK(p.evaluate(91000, true, -23.40, -46.63) == HEF_TX_TRIGGER_MOVE,
          "fix valido: movimento dispara evento apos o piso de intervalo");
}

// ---------------------------------------------------------------------
// 5) Politica de TX: piso de intervalo sob movimento perpetuo
// ---------------------------------------------------------------------
static void testIntervalFloor() {
    SECTION("TX por evento - piso de intervalo");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    uint32_t now = 0;
    p.evaluate(now, true, -23.55, -46.63);
    p.onTransmitted(now, true, -23.55, -46.63);

    // Alvo em movimento perpetuo: a cada 1 s ele "se move" mais de 10 m.
    // O piso de 30 s DEVE limitar as transmissoes.
    int tx = 0;
    for (int i = 1; i <= 120; i++) {
        now = (uint32_t)(i * 1000);
        double lat = -23.55 + (double)i * 0.001;   // ~111 m por passo
        if (p.evaluate(now, true, lat, -46.63) != HEF_TX_TRIGGER_NONE) {
            tx++;
            p.onTransmitted(now, true, lat, -46.63);
        }
    }
    // 120 s de movimento perpetuo, com piso de 30 s -> no maximo 4 TX
    // (0, 30, 60, 90 e 120 = 5, mas o primeiro foi em t=0).
    CHECK(tx >= 3 && tx <= 4,
          "movimento perpetuo respeita o piso de 30 s (3..4 TX em 120 s)");
}

// ---------------------------------------------------------------------
// 6) Politica de TX: primeiro contato e estado inicial
// ---------------------------------------------------------------------
static void testFirstContact() {
    SECTION("TX por evento - primeiro contato");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    CHECK(!p.hasLastTx(), "politica nova nao tem ultima TX");
    CHECK(p.evaluate(12345, true, 1.0, 2.0) == HEF_TX_TRIGGER_HEARTBEAT,
          "primeiro contato dispara (base precisa saber que o no vive)");
    p.onTransmitted(12345, true, 1.0, 2.0);
    CHECK(p.hasLastTx(), "apos transmitir, ha ultima TX");
    CHECK(p.lastTxMs() == 12345, "momento da ultima TX registrado");
}

// ---------------------------------------------------------------------
// 6b) Evento NAO e' perdido durante o piso de intervalo
// ---------------------------------------------------------------------
// Se a referencia de posicao avancasse durante o piso de intervalo, o
// movimento que ocorreu nesse periodo seria PERDIDO: o alvo teria se
// movido e a base nao receberia nada. A politica verifica o piso ANTES
// de consumir o evento.
static void testEventNotLostDuringFloor() {
    SECTION("TX por evento - evento nao e' perdido no piso");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    p.evaluate(0, true, -23.55, -46.63);
    p.onTransmitted(0, true, -23.55, -46.63);

    // O alvo se move aos 5 s (durante o piso de 30 s).
    CHECK(p.evaluate(5000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_NONE,
          "durante o piso: nao transmite");

    // Aos 31 s o piso passou: o movimento PENDENTE e' detectado.
    CHECK(p.evaluate(31000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_MOVE,
          "apos o piso: o movimento acumulado e' reportado");
}

// ---------------------------------------------------------------------
// 6c) O evento PENDENTE nao e' perdido; sem flood de log
// ---------------------------------------------------------------------
// A referencia de posicao e' a do ULTIMO frame REPORTADO, nao a da
// ultima posicao observada. Consequencia: se a transmissao for
// negada (duty cycle, erro), o movimento NAO e' perdido — ele
// continua pendente e sera reportado na proxima oportunidade.
//
// O flooding e' evitado pelo `onTxFailed()`, que reprograma o piso de
// intervalo: assim a proxima tentativa so acontece no proximo ciclo
// util, e nao milhares de vezes por segundo.
static void testPendingMoveNotLost() {
    SECTION("TX por evento - movimento pendente nao e' perdido");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    p.evaluate(0, true, -23.55, -46.63);
    p.onTransmitted(0, true, -23.55, -46.63);

    // O alvo se moveu: a primeira avaliacao detecta.
    CHECK(p.evaluate(31000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_MOVE,
          "primeira avaliacao detecta o movimento");
    CHECK(p.hasPendingMove(), "o movimento fica PENDENTE ate ser reportado");

    // A transmissao foi negada (duty cycle): o movimento NAO pode ser
    // descartado — a base ainda nao conhece a posicao nova.
    p.onTxFailed(31000);

    // O piso foi reprogramado: a proxima avaliacao nao dispara (evita
    // flood de log a cada iteracao do loop).
    CHECK(p.evaluate(32000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_NONE,
          "apos falha, o piso evita re-disparo imediato");
    CHECK(p.evaluate(40000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_NONE,
          "o piso continua valendo dentro da janela");

    // Passado o piso: o movimento pendente e' re-detectado.
    CHECK(p.evaluate(61000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_MOVE,
          "o movimento pendente e' reportado na proxima oportunidade");

    // Agora a transmissao succeeds: o movimento deixa de estar pendente.
    p.onTransmitted(61000, true, -23.5496, -46.63);
    CHECK(!p.hasPendingMove(), "apos o envio, o movimento deixa de estar pendente");

    // Passado o piso, a posicao reportada NAO e' re-reportada: a
    // referencia passou a ser a posicao que a base ja conhece.
    CHECK(p.evaluate(91000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_NONE,
          "movimento ja reportado nao e' re-reportado apos o piso");
    CHECK(p.evaluate(92000, true, -23.5496, -46.63) == HEF_TX_TRIGGER_NONE,
          "movimento ja reportado continua nao reportado");

    // Um movimento NOVO e' detectado normalmente.
    CHECK(p.evaluate(93000, true, -23.5492, -46.63) == HEF_TX_TRIGGER_MOVE,
          "um movimento novo e' detectado");
}

// ---------------------------------------------------------------------
// 6c-bis) A primeira posicao valida e' reportada
// ---------------------------------------------------------------------
// Se o no transmits sem fix (por exemplo, dentro de um tunel), a
// referencia de posicao fica invalida. A proxima posicao valida e'
// entao uma "primeira posicao" e precisa ser reportada: a base ainda
// nao conhece NENHUMA posicao deste no.
static void testFirstValidPositionReported() {
    SECTION("TX por evento - primeira posicao valida e' reportada");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    // Primeiro contato SEM fix: so heartbeat.
    CHECK(p.evaluate(0, false, 0.0, 0.0) == HEF_TX_TRIGGER_HEARTBEAT,
          "primeiro contato sem fix: heartbeat");
    p.onTransmitted(0, false, 0.0, 0.0);

    // Agora ha fix. Como a base nunca recebeu uma posicao, o evento
    // deve disparar (apos o piso), e a distancia e' desconhecida.
    CHECK(p.evaluate(31000, true, -23.55, -46.63) == HEF_TX_TRIGGER_MOVE,
          "a primeira posicao valida e' reportada como evento");
    CHECK(p.lastDistanceM() < 0.001,
          "a distancia e' desconhecida na primeira posicao valida");

    p.onTransmitted(31000, true, -23.55, -46.63);

    // A partir daqui, a referencia e' a posicao reportada.
    CHECK(p.evaluate(32000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "posicao igual a referencia nao dispara");
}

// ---------------------------------------------------------------------
// 6d) Jitter do piso de intervalo
// ---------------------------------------------------------------------
// O jitter (+/- 10%) e' o que dessincroniza a frota: varias unidades
// que acordam juntas nao podem transmitir no mesmo instante.
static uint32_t gRandState = 12345;
static uint32_t testRand() {
    // LCG deterministico (xorshift32): reproduzivel no host.
    gRandState ^= gRandState << 13;
    gRandState ^= gRandState >> 17;
    gRandState ^= gRandState << 5;
    return gRandState;
}

static void testJitter() {
    SECTION("TX por evento - jitter do piso");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);
    p.setJitterPct(10);
    p.setRandomSource(testRand);

    // Sem fonte de aleatoriedade: piso fixo.
    HefTxPolicy q;
    q.configure(10.0, 60000UL, 30000UL);
    q.onTransmitted(0, true, 1.0, 2.0);
    CHECK(q.nextAllowedMs() == 30000UL, "sem RNG: piso fixo de 30 s");

    // Com RNG: o piso varia dentro de +/- 10% (27 s .. 33 s).
    uint32_t minSeen = 0xFFFFFFFFUL;
    uint32_t maxSeen = 0;
    bool varied = false;
    for (int i = 0; i < 200; i++) {
        p.onTransmitted(0, true, 1.0, 2.0);
        uint32_t next = p.nextAllowedMs();
        if (next < minSeen) minSeen = next;
        if (next > maxSeen) maxSeen = next;
        if (next != 30000UL) varied = true;
    }
    CHECK(minSeen >= 27000UL, "piso com jitter nunca fica abaixo de 27 s");
    CHECK(maxSeen <= 33000UL, "piso com jitter nunca fica acima de 33 s");
    CHECK(varied, "o jitter realmente varia o piso");

    // Com o piso jitterizado, o evaluate() respeita o instante exato.
    p.onTransmitted(1000, true, 1.0, 2.0);
    uint32_t next = p.nextAllowedMs();
    CHECK(p.evaluate(next - 1, true, 1.0, 2.0) == HEF_TX_TRIGGER_NONE,
          "antes do instante permitido: nao transmite");
}

// ---------------------------------------------------------------------
// 6e) O piso vale ANTES do primeiro contato
// ---------------------------------------------------------------------
// Se a primeira transmissao for negada (duty cycle, chave ausente),
// `onTxFailed()` reprograma o piso. Sem isso, o loop principal
// re-tentaria milhares de vezes por segundo, cada tentativa incrementando
// `txDenied` e escrevendo no log — um flood que pode, sozinho, esgotar
// a flash e o buffer da serial.
static void testFloorBeforeFirstContact() {
    SECTION("TX por evento - piso vale antes do primeiro contato");

    HefTxPolicy p;
    p.configure(10.0, 60000UL, 30000UL);

    // Primeiro contato: dispara.
    CHECK(p.evaluate(0, true, -23.55, -46.63) == HEF_TX_TRIGGER_HEARTBEAT,
          "primeiro contato dispara");

    // A transmissao falhou: o piso e' reprogramado.
    p.onTxFailed(0);

    // As avaliacoes seguintes NAO podem re-disparar.
    CHECK(p.evaluate(1, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "apos falha, o piso bloqueia o re-disparo imediato");
    CHECK(p.evaluate(1000, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "o piso continua bloqueando dentro da janela");
    CHECK(p.evaluate(29999, true, -23.55, -46.63) == HEF_TX_TRIGGER_NONE,
          "o piso bloqueia ate o fim da janela");

    // Passado o piso: o primeiro contato e' retomado.
    CHECK(p.evaluate(30000, true, -23.55, -46.63) == HEF_TX_TRIGGER_HEARTBEAT,
          "passado o piso, o primeiro contato e' retomado");
}

// ---------------------------------------------------------------------
// 7) Beacon FM: duty cycle proprio
// ---------------------------------------------------------------------
static void testBeaconDutyCycle() {
    SECTION("Beacon FM - duty cycle proprio");

    HefBeaconPolicy b;
    b.configure(3000UL, 27000UL, 20);   // 3 s ON, 27 s OFF = 10%

    CHECK(b.dutyPercent() > 9.9f && b.dutyPercent() < 10.1f,
          "duty cycle nominal do beacon = 10%");
    CHECK(!b.isOn(), "beacon começa desligado");

    // t=0: liga (primeira fase ON).
    CHECK(b.evaluate(0, true, 255) == HEF_BEACON_ON, "beacon liga na fase ON");
    CHECK(b.isOn(), "beacon ligado");

    // Ainda dentro da fase ON.
    CHECK(b.evaluate(2000, true, 255) == HEF_BEACON_NONE, "fase ON mantem o beacon");

    // Fim da fase ON -> desliga.
    CHECK(b.evaluate(3000, true, 255) == HEF_BEACON_OFF, "fase ON termina em OFF");
    CHECK(!b.isOn(), "beacon desligado");

    // Fim da fase OFF -> religa.
    CHECK(b.evaluate(30000, true, 255) == HEF_BEACON_ON, "fase OFF termina em ON");

    // Operador desliga: o beacon apaga.
    CHECK(b.evaluate(31000, false, 255) == HEF_BEACON_OFF,
          "desligar pelo operador apaga o beacon");
    CHECK(b.evaluate(40000, false, 255) == HEF_BEACON_NONE,
          "com o beacon desligado nao ha acao");
}

// ---------------------------------------------------------------------
// 8) Beacon FM: corte automatico por bateria
// ---------------------------------------------------------------------
static void testBeaconBatteryCut() {
    SECTION("Beacon FM - corte por bateria");

    HefBeaconPolicy b;
    b.configure(3000UL, 27000UL, 20);

    b.evaluate(0, true, 255);
    CHECK(b.isOn(), "beacon ligado com bateria desconhecida");

    // Bateria em 15% (< 20%): desliga imediatamente.
    CHECK(b.evaluate(1000, true, 15) == HEF_BEACON_OFF,
          "bateria < 20% desliga o beacon");
    CHECK(!b.isOn(), "beacon apagado");
    CHECK(b.isPoweredOff(), "corte por bateria travado");

    // Nao religa sozinho, mesmo com bateria de novo alta e beacon ligado.
    CHECK(b.evaluate(5000, true, 90) == HEF_BEACON_NONE,
          "beacon nao religa sozinho apos o corte por bateria");
    CHECK(!b.isOn(), "beacon continua apagado");

    // Somente o rearm manual (operador recarregou a unidade) religa.
    b.rearm();
    CHECK(b.evaluate(6000, true, 90) == HEF_BEACON_ON,
          "rearm religa o beacon");
    CHECK(b.isOn(), "beacon religado apos rearm");

    // Bateria exatamente no limiar (20%) NAO desliga.
    HefBeaconPolicy c;
    c.configure(3000UL, 27000UL, 20);
    c.evaluate(0, true, 255);
    CHECK(c.evaluate(1000, true, 20) == HEF_BEACON_NONE,
          "bateria exatamente no limiar nao desliga");
    CHECK(c.isOn(), "beacon segue ligado com 20%");

    // Bateria desconhecida (255) nunca desliga.
    HefBeaconPolicy d;
    d.configure(3000UL, 27000UL, 20);
    d.evaluate(0, true, 255);
    CHECK(d.evaluate(1000, true, 255) == HEF_BEACON_NONE,
          "bateria desconhecida nao desliga");
    CHECK(d.isOn(), "beacon segue ligado sem leitura de bateria");
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - politica de TX adaptativa\n");
    printf("=====================================================\n");

    testDistance();
    testMoveTrigger();
    testHeartbeat();
    testNoFix();
    testIntervalFloor();
    testFirstContact();
    testEventNotLostDuringFloor();
    testPendingMoveNotLost();
    testFirstValidPositionReported();
    testFloorBeforeFirstContact();
    testJitter();
    testBeaconDutyCycle();
    testBeaconBatteryCut();

    return heftest::summary("politica de TX adaptativa");
}
