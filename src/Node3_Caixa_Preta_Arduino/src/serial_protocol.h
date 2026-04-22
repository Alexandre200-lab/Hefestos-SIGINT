// serial_protocol.h - Reliable UART communication with CRC16
// Node2 <-> Node3 serial link com checksum e detecção de erros

#ifndef SERIAL_PROTOCOL_H
#define SERIAL_PROTOCOL_H

#include <stdint.h>
#include <string.h>

#define SERIAL_FRAME_START 0xAA
#define SERIAL_FRAME_END 0x55
#define SERIAL_MAX_PAYLOAD 256

class CRC16 {
public:
  static uint16_t calculate(const uint8_t* data, int len) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
      crc ^= data[i];
      for (int j = 0; j < 8; j++) {
        if (crc & 1) {
          crc = (crc >> 1) ^ 0xA001;
        } else {
          crc >>= 1;
        }
      }
    }
    return crc;
  }

  static bool verify(const uint8_t* data, int len, uint16_t expected) {
    return calculate(data, len - 2) == expected;
  }
};

// Frame Structure:
// | START(1) | TYPE(1) | LEN(2) | PAYLOAD(N) | CRC16(2) | END(1) |
struct SerialFrame {
  uint8_t start;
  uint8_t type;
  uint16_t len;
  uint8_t payload[SERIAL_MAX_PAYLOAD];
  uint16_t crc;
  uint8_t end;

  int getTotalSize() {
    return 1 + 1 + 2 + len + 2 + 1;
  }
};

enum FrameType {
  FRAME_DATA = 0x01,
  FRAME_ACK = 0x02,
  FRAME_NAK = 0x03,
  FRAME_HEARTBEAT = 0x04
};

class SerialProtocol {
private:
  uint8_t buffer[512];
  int bufpos = 0;
  unsigned long last_heartbeat = 0;
  const unsigned long HEARTBEAT_INTERVAL = 5000;

public:
  SerialProtocol() {}

  // Encoda mensagem em frame com CRC
  int encodeFrame(uint8_t type, const uint8_t* data, int datalen, uint8_t* output) {
    if (datalen > SERIAL_MAX_PAYLOAD) return -1;

    int pos = 0;
    output[pos++] = SERIAL_FRAME_START;
    output[pos++] = type;
    output[pos++] = (datalen >> 8) & 0xFF;
    output[pos++] = datalen & 0xFF;

    if (data != NULL) {
      memcpy(&output[pos], data, datalen);
    }
    pos += datalen;

    uint16_t crc = CRC16::calculate(&output[1], 3 + datalen);
    output[pos++] = (crc >> 8) & 0xFF;
    output[pos++] = crc & 0xFF;
    output[pos++] = SERIAL_FRAME_END;

    return pos;
  }

  // Decodifica frame recebido
  bool decodeFrame(const uint8_t* data, int len, SerialFrame* frame) {
    if (len < 8) return false;

    int pos = 0;
    if (data[pos++] != SERIAL_FRAME_START) return false;

    frame->type = data[pos++];
    frame->len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    if (frame->len > SERIAL_MAX_PAYLOAD) return false;
    if (pos + frame->len + 3 > len) return false;

    memcpy(frame->payload, &data[pos], frame->len);
    pos += frame->len;

    frame->crc = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    if (data[pos] != SERIAL_FRAME_END) return false;

    // Verifica CRC
    uint16_t calculated_crc = CRC16::calculate(&data[1], 3 + frame->len);
    return calculated_crc == frame->crc;
  }

  // Envia dados com retry
  void sendWithRetry(Stream& serial, const uint8_t* data, int len, int max_retries = 3) {
    uint8_t frame[len + 8];
    int frame_len = encodeFrame(FRAME_DATA, data, len, frame);

    for (int retry = 0; retry < max_retries; retry++) {
      serial.write(frame, frame_len);
      serial.flush();
      delay(10);
    }
  }

  // Detecta heartbeat quando inativo
  void sendHeartbeat(Stream& serial) {
    unsigned long now = millis();
    if (now - last_heartbeat > HEARTBEAT_INTERVAL) {
      uint8_t frame[8];
      int frame_len = encodeFrame(FRAME_HEARTBEAT, NULL, 0, frame);
      serial.write(frame, frame_len);
      last_heartbeat = now;
    }
  }
};

#endif // SERIAL_PROTOCOL_H
