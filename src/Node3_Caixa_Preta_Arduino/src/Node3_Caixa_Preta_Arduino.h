#include <SoftwareSerial.h>
#include "serial_protocol.h"
#include "debug.h"

SoftwareSerial SerialESP(2, 3);

class SerialWrapper : public Stream {
public:
    SoftwareSerial* serial;
    SerialWrapper(SoftwareSerial& s) : serial(&s) {}
    size_t write(uint8_t b) { return serial->write(b); }
    int available() { return serial->available(); }
    int read() { return serial->read(); }
    int peek() { return serial->peek(); }
    void flush() { serial->flush(); }
};

SerialWrapper serialWrap(SerialESP);

CRC16 crc16;