// =====================================================================
// tests/serial_roundtrip.cpp
//
// Teste de unidade do protocolo serial Node2 <-> Node3 (link_protocol
// binario com CRC16). Roda no HOST (g++), sem hardware.
//
// Motivo: o parser de frames (HefSerialRx::feed) Ja teve um erro de
// offset de 1 byte (LEN/CRC/PAYLOAD lidos na posicao errada) que nao
// aparecia em nenhum build nem em nenhum teste estatico: o codigo
// compilava e o link simplesmente nunca funcionava em campo.
//
// Compilacao (ver test_functional.sh):
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I lib/src
//       tests/serial_roundtrip.cpp -o /tmp/hef_serial_test
// =====================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "serial_protocol.h"

static int failures = 0;
static int checks = 0;

static void check(bool cond, const char* msg) {
    checks++;
    if (cond) {
        printf("  [PASS] %s\n", msg);
    } else {
        printf("  [FAIL] %s\n", msg);
        failures++;
    }
}

// Stream fake que entrega bytes em memoria.
class FakeStream : public Stream {
public:
    uint8_t buf[4096];
    size_t  len = 0;
    size_t  pos = 0;

    void push(const uint8_t* d, size_t n) {
        if (len + n > sizeof(buf)) n = sizeof(buf) - len;
        memcpy(buf + len, d, n);
        len += n;
    }
    int available() override { return (int)(len - pos); }
    int read() override { return (pos < len) ? (int)buf[pos++] : -1; }
    void reset() { len = 0; pos = 0; }
};

struct Cb {
    int count = 0;
    HefSerFrame last;
};

static void onFrame(const HefSerFrame& f, void* ctx) {
    Cb* c = (Cb*)ctx;
    c->count++;
    c->last = f;
}

int main() {
    HefSerialTx tx;
    HefSerialRx rx;

    // ---------------------------------------------------------------
    // 1) Round-trip simples
    // ---------------------------------------------------------------
    {
        const char* msg = "T,1,1760000000,-23.5505000,-46.6333000,760,12,90,8,1,87,0,-95,7.5";
        uint8_t payload[HEF_SER_MAX_PAYLOAD];
        memcpy(payload, msg, strlen(msg));
        uint16_t plen = (uint16_t)strlen(msg);

        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_DATA, 42, payload, plen, frame);
        check(n == (int)(9 + plen), "encode() devolve 9 + len bytes");

        FakeStream s;
        s.push(frame, (size_t)n);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 1, "1 frame decodificado");
        check(cb.count == 1, "callback chamado uma vez");
        check(cb.last.type == HEF_SER_DATA, "tipo preservado");
        check(cb.last.seq == 42, "sequencia preservada");
        check(cb.last.len == plen, "comprimento preservado");
        check(memcmp(cb.last.payload, payload, plen) == 0, "payload preservado");
        check(rx.crcErrors() == 0, "nenhum erro de CRC");
        check(rx.overflows() == 0, "nenhum overflow");
    }

    // ---------------------------------------------------------------
    // 2) Payload contendo os delimitadores 0x55 (END) e 0xAA (START)
    // ---------------------------------------------------------------
    {
        uint8_t payload[16];
        for (int i = 0; i < 16; i++) payload[i] = (uint8_t)((i % 2) ? 0x55 : 0xAA);
        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_RESPONSE, 7, payload, sizeof(payload), frame);

        FakeStream s;
        s.push(frame, (size_t)n);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 1, "frame com 0x55/0xAA no payload decodificado");
        check(cb.last.len == sizeof(payload), "comprimento com delimitadores correto");
        check(memcmp(cb.last.payload, payload, sizeof(payload)) == 0,
              "payload com 0x55/0xAA preservado");
    }

    // ---------------------------------------------------------------
    // 3) Dois frames concatenados em um unico stream
    // ---------------------------------------------------------------
    {
        uint8_t f1[HEF_SER_MAX_PAYLOAD + 16];
        uint8_t f2[HEF_SER_MAX_PAYLOAD + 16];
        uint8_t p1[4] = {1, 2, 3, 4};
        uint8_t p2[2] = {9, 8};
        int n1 = tx.encode(HEF_SER_HEARTBEAT, 1, p1, sizeof(p1), f1);
        int n2 = tx.encode(HEF_SER_REQUEST, 2, p2, sizeof(p2), f2);

        FakeStream s;
        s.push(f1, (size_t)n1);
        s.push(f2, (size_t)n2);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 2, "2 frames concatenados decodificados");
        check(cb.count == 2, "callback chamado 2 vezes");
        check(cb.last.type == HEF_SER_REQUEST, "ultimo frame e' o segundo");
    }

    // ---------------------------------------------------------------
    // 4) Frame corrompido => erro de CRC, nenhum frame entregue
    // ---------------------------------------------------------------
    {
        uint8_t payload[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};
        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_DATA, 9, payload, sizeof(payload), frame);
        frame[6 + 2] ^= 0x01;   // corrompe um byte do payload

        FakeStream s;
        s.push(frame, (size_t)n);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        uint32_t errsBefore = rx.crcErrors();
        check(got == 0, "frame corrompido nao e' entregue");
        check(cb.count == 0, "callback nao chamado para frame corrompido");
        check(errsBefore > 0, "erro de CRC contabilizado");
    }

    // ---------------------------------------------------------------
    // 5) Payload vazio
    // ---------------------------------------------------------------
    {
        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_ACK, 11, nullptr, 0, frame);
        check(n == 9, "frame vazio tem 9 bytes");

        FakeStream s;
        s.push(frame, (size_t)n);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 1, "frame vazio decodificado");
        check(cb.last.len == 0, "payload vazio com len=0");
        check(cb.last.type == HEF_SER_ACK, "tipo ACK preservado");
    }

    // ---------------------------------------------------------------
    // 6) Payload maximo (512 bytes)
    // ---------------------------------------------------------------
    {
        uint8_t payload[HEF_SER_MAX_PAYLOAD];
        for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i & 0xFF);
        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_RESPONSE, 13, payload, sizeof(payload), frame);

        FakeStream s;
        s.push(frame, (size_t)n);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 1, "frame de 512 bytes decodificado");
        check(cb.last.len == HEF_SER_MAX_PAYLOAD, "len maximo preservado");
        check(memcmp(cb.last.payload, payload, sizeof(payload)) == 0,
              "payload maximo preservado");
    }

    // ---------------------------------------------------------------
    // 7) Bytes ruido antes do frame sao descartados
    // ---------------------------------------------------------------
    {
        uint8_t payload[4] = {1, 2, 3, 4};
        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_DATA, 21, payload, sizeof(payload), frame);

        FakeStream s;
        uint8_t noise[5] = {0x00, 0xAA, 0x13, 0x55, 0xAA};   // inclui START falso
        s.push(noise, sizeof(noise));
        s.push(frame, (size_t)n);
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 1, "frame recuperado apos ruido (com START falso)");
        check(cb.last.seq == 21, "frame correto apos ruido");
    }

    // ---------------------------------------------------------------
    // 8) Frame truncado (bytes perdidos) seguido de frame valido:
    //    o receptor deve ressincronizar e entregar apenas o valido.
    // ---------------------------------------------------------------
    {
        uint8_t p1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t p2[4] = {0xAA, 0x55, 0xAA, 0x55};
        uint8_t f1[HEF_SER_MAX_PAYLOAD + 16];
        uint8_t f2[HEF_SER_MAX_PAYLOAD + 16];
        int n1 = tx.encode(HEF_SER_DATA, 31, p1, sizeof(p1), f1);
        int n2 = tx.encode(HEF_SER_RESPONSE, 32, p2, sizeof(p2), f2);

        FakeStream s;
        s.push(f1, (size_t)n1 - 3);   // frame truncado
        s.push(f2, (size_t)n2);       // frame completo em seguida
        Cb cb;
        int got = rx.feed(s, onFrame, &cb);

        check(got == 1, "frame truncado nao e' entregue");
        check(cb.count == 1, "apenas 1 callback apos truncamento");
        check(cb.last.seq == 32, "frame valido seguinte foi recuperado");
    }

    // ---------------------------------------------------------------
    // 9) Feed byte a byte (cenario tipico de UART com pacing)
    // ---------------------------------------------------------------
    {
        uint8_t payload[32];
        for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i * 3);
        uint8_t frame[HEF_SER_MAX_PAYLOAD + 16];
        int n = tx.encode(HEF_SER_DATA, 55, payload, sizeof(payload), frame);

        HefSerialRx slow;
        Cb cb;
        FakeStream s;
        for (int i = 0; i < n; i++) {
            s.reset();
            s.push(&frame[i], 1);
            slow.feed(s, onFrame, &cb);
        }
        check(cb.count == 1, "frame entregue no feed byte-a-byte");
        check(cb.last.len == sizeof(payload), "len correto no feed byte-a-byte");
        check(memcmp(cb.last.payload, payload, sizeof(payload)) == 0,
              "payload correto no feed byte-a-byte");
    }

    printf("\n  round-trip serial: %d verificacoes, %d falha(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
