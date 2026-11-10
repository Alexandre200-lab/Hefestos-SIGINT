// serial_protocol.h - Link serial binario e nao-bloqueante (Node2 <-> Node3)
//
// v5.0.0 - REESCRITO.
//
// Bugs da v4.x corrigidos:
//   - Node2 NUNCA enviava nada ao Node3 (encodeFrame() nunca era chamado).
//     O logger forense so recebia heartbeats.
//   - processSerialBuffer() so rodava DENTRO dos handlers HTTP bloqueantes,
//     logo as capturas eram perdidas se ninguem pollasse o dashboard.
//   - Os handlers bloqueavam o event loop por 200-500 ms com delay(),
//     travando tambem o loop de RX LoRa (perdendo tracks).
//   - serialBufferResponse era uma String global sem limite -> crescimento
//     de heap sem limites (DoS).
//   - Baud 9600 era insuficiente para o historico JSON.
//
// v5:
//   - Frames binarios com CRC16 e numero de sequencia.
//   - RX e TX 100% nao-bloqueantes, processados no loop principal.
//   - Ring buffer de TX com descarte por overflow (politica explicita).
//   - Protocolo de comandos/requisicoes (RESPOSTA com ID de request).
#ifndef HEF_SERIAL_PROTOCOL_H
#define HEF_SERIAL_PROTOCOL_H

#include <stdint.h>
#include <string.h>
#include <HardwareSerial.h>

#include "hefestos_pins.h"

#define HEF_SER_START     0xAA
#define HEF_SER_END       0x55
#define HEF_SER_MAX_PAYLOAD 512

enum HefSerType {
    HEF_SER_DATA       = 0x01,   // Node2 -> Node3: registro forense
    HEF_SER_HEARTBEAT  = 0x02,   // Node3 -> Node2: keepalive
    HEF_SER_REQUEST    = 0x03,   // Node2 -> Node3: requisicao
    HEF_SER_RESPONSE   = 0x04,   // Node3 -> Node2: resposta
    HEF_SER_TIME       = 0x05,   // Node2 -> Node3: sincronismo de tempo
    HEF_SER_ACK        = 0x06
};

enum HefSerRequest {
    HEF_REQ_CAPTURE_LAST  = 0x01,
    HEF_REQ_CAPTURE_LIST  = 0x02,
    HEF_REQ_CAPTURE_CLEAR = 0x03,
    HEF_REQ_LOG_EXPORT    = 0x04,
    HEF_REQ_LOG_INFO      = 0x05
};

// Cabecalho: START(1) TYPE(1) SEQ(2) LEN(2) PAYLOAD(N) CRC16(2) END(1)
struct HefSerFrame {
    uint8_t  type;
    uint16_t seq;
    uint16_t len;
    uint8_t  payload[HEF_SER_MAX_PAYLOAD];
};

class Crc16 {
public:
    static uint16_t calculate(const uint8_t* data, size_t len) {
        uint16_t crc = 0xFFFF;
        for (size_t i = 0; i < len; i++) {
            crc ^= data[i];
            for (int j = 0; j < 8; j++) {
                crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
            }
        }
        return crc;
    }
};

// Codificador de frames (usado pelo lado que envia).
class HefSerialTx {
private:
    uint8_t  buf_[HEF_SER_MAX_PAYLOAD + 16];
    uint16_t seq_;
public:
    HefSerialTx() : seq_(1) {}
    uint16_t nextSeq() { return seq_++; }

    // Codifica em `out`. Retorna o tamanho ou -1.
    int encode(uint8_t type, uint16_t seq, const uint8_t* data, uint16_t len, uint8_t* out) {
        if (len > HEF_SER_MAX_PAYLOAD) return -1;
        size_t pos = 0;
        out[pos++] = HEF_SER_START;
        out[pos++] = type;
        out[pos++] = (uint8_t)(seq >> 8);
        out[pos++] = (uint8_t)(seq);
        out[pos++] = (uint8_t)(len >> 8);
        out[pos++] = (uint8_t)(len);
        if (len && data) memcpy(out + pos, data, len);
        pos += len;
        uint16_t crc = Crc16::calculate(out + 1, 5 + len);
        out[pos++] = (uint8_t)(crc >> 8);
        out[pos++] = (uint8_t)(crc);
        out[pos++] = HEF_SER_END;
        return (int)pos;
    }
};

// Receptor de frames nao-bloqueante com reassembly por deslocamento.
class HefSerialRx {
private:
    uint8_t  buf_[HEF_SER_MAX_PAYLOAD + 32];
    size_t   pos_;
    uint32_t crcErrors_;
    uint32_t framesOk_;
    uint32_t overflows_;

public:
    HefSerialRx() : pos_(0), crcErrors_(0), framesOk_(0), overflows_(0) {
        memset(buf_, 0, sizeof(buf_));
    }

    uint32_t crcErrors()  const { return crcErrors_; }
    uint32_t framesOk()   const { return framesOk_; }
    uint32_t overflows()  const { return overflows_; }

    void reset() { pos_ = 0; }

    // Alimenta bytes do stream. Quando um frame completo e' decodificado,
    // chama o callback (pode ser nullptr). Retorna o numero de frames
    // completos processados nesta chamada.
    int feed(Stream& stream, void (*onFrame)(const HefSerFrame&, void*), void* ctx) {
        int completed = 0;
        while (stream.available()) {
            int c = stream.read();
            if (c < 0) break;
            uint8_t b = (uint8_t)c;

            if (pos_ == 0) {
                if (b != HEF_SER_START) continue;   // procura o inicio
                buf_[pos_++] = b;
                continue;
            }

            if (pos_ >= sizeof(buf_)) { pos_ = 0; overflows_++; continue; }
            buf_[pos_++] = b;

            // Precisa de START + TYPE + SEQ(2) + LEN(2) para saber o total.
            if (pos_ < 7) continue;

            uint16_t len = (uint16_t)(((uint16_t)buf_[5] << 8) | buf_[6]);
            if (len > HEF_SER_MAX_PAYLOAD) { pos_ = 0; crcErrors_++; continue; }

            size_t expected = 8 + (size_t)len + 1;
            if (pos_ < expected) continue;   // payload pode conter 0x55

            // Frame completo: START(1) TYPE(1) SEQ(2) LEN(2) PAYLOAD(N) CRC(2) END(1)
            if (buf_[pos_ - 1] != HEF_SER_END) { pos_ = 0; crcErrors_++; continue; }

            uint16_t gotCrc = (uint16_t)(((uint16_t)buf_[7 + len] << 8) | buf_[8 + len]);
            uint16_t calc = Crc16::calculate(buf_ + 1, 5 + len);
            if (gotCrc != calc) { crcErrors_++; pos_ = 0; continue; }

            HefSerFrame frame;
            frame.type = buf_[1];
            frame.seq  = (uint16_t)(((uint16_t)buf_[2] << 8) | buf_[3]);
            frame.len  = len;
            if (len) memcpy(frame.payload, buf_ + 7, len);
            framesOk_++;
            completed++;
            if (onFrame) onFrame(frame, ctx);
            pos_ = 0;
        }
        return completed;
    }
};

#endif // HEF_SERIAL_PROTOCOL_H
