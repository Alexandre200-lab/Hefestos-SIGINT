// debug.h - Logging com controle de release - v5.0.0
//
// v5: remove qualquer rotina de dump de segredos. Nao existe mais
// nenhuma funcao que imprima chave, senha ou PSK - nem em builds DEBUG.
#ifndef HEF_DEBUG_H
#define HEF_DEBUG_H

#include <HardwareSerial.h>
#include <stdarg.h>

#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#endif

#define HEF_FW_VERSION "5.0.0"

class DebugLogger {
private:
    HardwareSerial* port_;
    bool enabled_;

public:
    explicit DebugLogger(HardwareSerial* serialPort = &Serial)
        : port_(serialPort), enabled_(DEBUG_MODE ? true : false) {}

    void begin(uint32_t baud = 115200) {
        // O console e' SEMPRE aberto no alvo (baud logico), mas o ruido de
        // log so e' emitido quando DEBUG_MODE=1. O modo release mantem o
        // console vivo para diagnostico de campo sem poluir a operacao.
        port_->begin(baud);
        if (!enabled_) return;
        port_->println();
        port_->println("===== HEFESTOS SIGINT v" HEF_FW_VERSION " (DEBUG) =====");
    }

    void enable()  { enabled_ = true; }
    void disable() { enabled_ = false; }
    bool isEnabled() const { return enabled_; }

    void log(const char* msg) {
        if (!enabled_ || !msg) return;
        port_->print("[H] ");
        port_->println(msg);
    }

    void logf(const char* fmt, ...) {
        if (!enabled_ || !fmt) return;
        char buf[256];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        port_->print("[H] ");
        port_->println(buf);
    }

    void logError(const char* msg) {
        if (!enabled_ || !msg) return;
        port_->print("[E] ");
        port_->println(msg);
    }

    void logWarning(const char* msg) {
        if (!enabled_ || !msg) return;
        port_->print("[W] ");
        port_->println(msg);
    }

    void logHex(const uint8_t* data, int len, const char* label = nullptr) {
        if (!enabled_ || !data) return;
        if (label) { port_->print("[X] "); port_->print(label); port_->print(": "); }
        for (int i = 0; i < len; i++) {
            if (data[i] < 16) port_->print('0');
            port_->print(data[i], HEX);
            port_->print(' ');
        }
        port_->println();
    }

    void printMemory() {
        if (!enabled_) return;
#if defined(ESP32)
        port_->print("[M] heap livre: ");
        port_->println((unsigned long)ESP.getFreeHeap());
#endif
    }

    // Saida irrestrita: usada para mensagens de boot e credenciais de
    // primeiro provisioning, que o operador PRECISA ver.
    void critical(const char* msg) {
        if (!msg) return;
        port_->println(msg);
    }
};

#endif // HEF_DEBUG_H
