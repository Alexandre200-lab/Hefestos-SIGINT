// debug.h - Debug logging utilities
// Controlado por #define DEBUG_MODE para economia de memória

#ifndef DEBUG_H
#define DEBUG_H

#include <HardwareSerial.h>
#include <stdarg.h>

#define FW_VERSION "2.1.0"
#define FW_BUILD_DATE __DATE__
#define FW_BUILD_TIME __TIME__

// Define DEBUG_MODE em compile time para ativar logs verbosos
// Use: arduino-cli compile -D DEBUG_MODE=1
#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#endif

class DebugLogger {
private:
  HardwareSerial* port;
  bool enabled;

public:
  DebugLogger(HardwareSerial* serial_port = &Serial) : port(serial_port), enabled(DEBUG_MODE) {}

  void begin(uint32_t baud = 115200) {
    if (!enabled) return;
    port->begin(baud);
    delay(1000);
    port->println("\n\n===== HEFESTOS SIGINT v" FW_VERSION " =====");
    port->print("Compiled: ");
    port->print(FW_BUILD_DATE);
    port->print(" ");
    port->println(FW_BUILD_TIME);
    port->println("Debug mode: ENABLED");
  }

  void logMsg(const char* msg) {
    if (!enabled) return;
    port->print("[DEBUG] ");
    port->println(msg);
  }

  void logf(const char* fmt, ...) {
    if (!enabled) return;
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    port->print("[DEBUG] ");
    port->println(buf);
  }

  void logHex(const byte* data, int len, const char* label = NULL) {
    if (!enabled) return;
    if (label) {
      port->print("[HEX] ");
      port->print(label);
      port->print(": ");
    }
    for (int i = 0; i < len; i++) {
      if (data[i] < 16) port->print("0");
      port->print(data[i], HEX);
      port->print(" ");
    }
    port->println();
  }

  void logError(const char* msg) {
    if (!enabled) return;
    port->print("[ERROR] ");
    port->println(msg);
  }

  void logWarning(const char* msg) {
    if (!enabled) return;
    port->print("[WARN] ");
    port->println(msg);
  }

  void printMemory() {
    if (!enabled) return;
    extern int __heap_start;
    extern int __brkval;
    int freeRam = (int)(&__heap_start) - (__brkval == 0 ? (int)(&__heap_start) : (int)__brkval);
    port->print("[MEM] Free: ");
    port->print(freeRam);
    port->println(" bytes");
  }

  void enable() { enabled = true; }
  void disable() { enabled = false; }
  bool isEnabled() { return enabled; }
};

#endif // DEBUG_H
