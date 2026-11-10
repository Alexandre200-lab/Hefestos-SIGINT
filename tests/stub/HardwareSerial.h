// Stub minimo de Arduino/HardwareSerial para compilar os headers da
// biblioteca compartilhada no host (testes de unidade sem hardware).
//
// NAO faz parte do firmware: e' usado apenas por tests/serial_roundtrip.cpp.
#ifndef HEF_STUB_HARDWARE_SERIAL_H
#define HEF_STUB_HARDWARE_SERIAL_H

#include <stdint.h>
#include <stddef.h>

class Stream {
public:
    virtual ~Stream() {}
    virtual int available() = 0;
    virtual int read() = 0;
    virtual int availableForWrite() { return 0; }
    virtual size_t write(uint8_t) { return 0; }
    virtual size_t write(const uint8_t* buf, size_t len) { (void)buf; return len; }
};

class HardwareSerial : public Stream {
public:
    int available() override { return 0; }
    int read() override { return -1; }
};

#endif // HEF_STUB_HARDWARE_SERIAL_H
