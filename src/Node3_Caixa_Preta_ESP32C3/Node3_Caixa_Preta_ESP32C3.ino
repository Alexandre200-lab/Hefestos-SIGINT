// Node 3: Caixa Preta Forense (ESP32-C3) - v4.0
// Ported from Arduino Uno to ESP32-C3
// Native UART (no SoftwareSerial), LEDC PWM for buzzer

#include <SPI.h>
#include <SD.h>

#include "../lib/hefestos_pins.h"
#include "../lib/serial_protocol.h"
#include "../lib/debug.h"

#define SD_RETRY_MAX 3
#define SD_RETRY_DELAY 500
#define LOG_BUFFER_SIZE 256
#define BUZZER_PWM_CHANNEL 0

HardwareSerial SerialNode2(0);
File arquivoLog;
SerialProtocol serialProto;
DebugLogger debug;

uint32_t total_logs = 0;
uint32_t failed_writes = 0;
unsigned long last_sd_check = 0;
bool sd_ok = false;

struct LogEntry {
  uint32_t timestamp;
  char tipo[10];
  char dados[48];
};
LogEntry log_buffer[LOG_BUFFER_SIZE];
int log_buffer_idx = 0;
int log_buffer_count = 0;

void initSDCard() {
  int retries = 0;
  while (!SD.begin(N3_SD_CS, SPI, 20000000, N3_SD_MOSI, N3_SD_MISO, N3_SD_SCK) && retries < SD_RETRY_MAX) {
    debug.logError("SD init failed, retrying...");
    toneBuzzer(300, 200);
    delay(SD_RETRY_DELAY);
    retries++;
  }

  if (SD.begin(N3_SD_CS, SPI, 20000000, N3_SD_MOSI, N3_SD_MISO, N3_SD_SCK)) {
    sd_ok = true;
    debug.log("SD Card initialized OK");
    toneBuzzer(1000, 100);
    delay(100);
    toneBuzzer(1500, 100);

    if (!SD.exists("HEFESTOS.CSV")) {
      arquivoLog = SD.open("HEFESTOS.CSV", FILE_WRITE);
      if (arquivoLog) {
        arquivoLog.println("TEMPO_MS,TIPO,DADOS");
        arquivoLog.close();
      }
    }

    flushRAMBuffer();
  } else {
    sd_ok = false;
    debug.logError("SD Card FAILED - using RAM buffer only");
    toneBuzzer(500, 500);
  }
}

void toneBuzzer(int freq, int duration) {
  ledcSetup(BUZZER_PWM_CHANNEL, freq, 8);
  ledcAttachPin(N3_BUZZER, BUZZER_PWM_CHANNEL);
  ledcWrite(BUZZER_PWM_CHANNEL, 128);
  delay(duration);
  ledcWrite(BUZZER_PWM_CHANNEL, 0);
  ledcDetachPin(N3_BUZZER);
}

bool writeToSD(uint32_t timestamp, const char* tipo, const char* dados) {
  if (!sd_ok) return false;

  int retries = 0;
  while (retries < SD_RETRY_MAX) {
    arquivoLog = SD.open("HEFESTOS.CSV", FILE_WRITE);
    if (arquivoLog) {
      arquivoLog.print(timestamp);
      arquivoLog.print(",");
      arquivoLog.print(tipo);
      arquivoLog.print(",");
      arquivoLog.println(dados);
      arquivoLog.close();
      return true;
    }
    retries++;
    delay(SD_RETRY_DELAY);
  }

  failed_writes++;
  return false;
}

void addToRAMBuffer(uint32_t timestamp, const char* tipo, const char* dados) {
  LogEntry* entry = &log_buffer[log_buffer_idx];
  entry->timestamp = timestamp;
  strncpy(entry->tipo, tipo, sizeof(entry->tipo) - 1);
  entry->tipo[sizeof(entry->tipo) - 1] = '\0';
  strncpy(entry->dados, dados, sizeof(entry->dados) - 1);
  entry->dados[sizeof(entry->dados) - 1] = '\0';

  log_buffer_idx = (log_buffer_idx + 1) % LOG_BUFFER_SIZE;
  if (log_buffer_count < LOG_BUFFER_SIZE) log_buffer_count++;
}

void flushRAMBuffer() {
  if (!sd_ok || log_buffer_count == 0) return;

  debug.log("Flushing RAM buffer to SD...");
  int flushed = 0;

  for (int i = 0; i < log_buffer_count; i++) {
    int idx = (log_buffer_idx - log_buffer_count + i + LOG_BUFFER_SIZE) % LOG_BUFFER_SIZE;
    LogEntry* entry = &log_buffer[idx];

    if (writeToSD(entry->timestamp, entry->tipo, entry->dados)) {
      flushed++;
    }
  }

  debug.logf("Flushed %d/%d entries to SD", flushed, log_buffer_count);
  log_buffer_count = 0;
  log_buffer_idx = 0;
}

void setup() {
  Serial.begin(115200);
  debug.begin(115200);

  SerialNode2.begin(9600, SERIAL_8N1, N3_UART_RX, N3_UART_TX);

  pinMode(N3_LED_GREEN, OUTPUT);
  pinMode(N3_LED_RED, OUTPUT);

  Serial.println("=========================================");
  Serial.println(" HEFESTOS - DATA LOGGER FORENSE v4.0");
  Serial.println(" ESP32-C3 + CRC16 + RAM Flush + Recovery");
  Serial.println("=========================================");

  initSDCard();

  delay(500);
  debug.log("Node3: Pronto para receber dados");
}

void loop() {
  unsigned long now = millis();
  if (now - last_sd_check > 30000) {
    last_sd_check = now;
    if (!sd_ok) {
      initSDCard();
    }
  }

  if (SerialNode2.available()) {
    SerialFrame frame;
    uint8_t buffer[512];
    int buffer_idx = 0;

    while (SerialNode2.available() && buffer_idx < 512) {
      uint8_t b = SerialNode2.read();
      buffer[buffer_idx++] = b;

      if (buffer_idx > 1 && buffer[buffer_idx - 1] == SERIAL_FRAME_END &&
          buffer[0] == SERIAL_FRAME_START) {
        if (serialProto.decodeFrame(buffer, buffer_idx, &frame)) {
          if (frame.type == FRAME_DATA) {
            char tipo[16];
            char dados[64];

            int pipe_pos = 0;
            for (int i = 0; i < frame.len && pipe_pos == 0; i++) {
              if (frame.payload[i] == '|') pipe_pos = i;
            }

            if (pipe_pos > 0) {
              memcpy(tipo, frame.payload, pipe_pos);
              tipo[pipe_pos] = '\0';

              int data_len = frame.len - pipe_pos - 1;
              if (data_len > 127) data_len = 127;
              memcpy(dados, &frame.payload[pipe_pos + 1], data_len);
              dados[data_len] = '\0';
            } else {
              strcpy(tipo, "RAW");
              int data_len = frame.len;
              if (data_len > 127) data_len = 127;
              memcpy(dados, frame.payload, data_len);
              dados[data_len] = '\0';
            }

            uint32_t timestamp = millis();
            bool wrote_ok = writeToSD(timestamp, tipo, dados);
            addToRAMBuffer(timestamp, tipo, dados);

            if (strcmp(tipo, "ALVO") == 0) {
              digitalWrite(N3_LED_GREEN, HIGH);
              toneBuzzer(2000, 200);
              delay(50);
              digitalWrite(N3_LED_GREEN, LOW);
              Serial.print("[+] ALVO_TX: ");
            } else {
              digitalWrite(N3_LED_RED, HIGH);
              delay(30);
              digitalWrite(N3_LED_RED, LOW);
              Serial.print("[!] SNIFF_RX: ");
            }

            Serial.println(dados);
            total_logs++;

            if (DEBUG_MODE) {
              Serial.print("    Bytes: ");
              Serial.print(frame.len);
              Serial.print(" | SD: ");
              Serial.println(wrote_ok ? "OK" : "BUFFER");
              Serial.print("    Total: ");
              Serial.print(total_logs);
              Serial.print(" | Failed: ");
              Serial.print(failed_writes);
              Serial.print(" | Buffer: ");
              Serial.println(log_buffer_count);
            }
          }

          buffer_idx = 0;
        } else {
          for (int i = 1; i < buffer_idx; i++) {
            if (buffer[i] == SERIAL_FRAME_START) {
              memcpy(buffer, &buffer[i], buffer_idx - i);
              buffer_idx -= i;
              break;
            }
          }
        }
      }
    }
  }

  serialProto.sendHeartbeat(SerialNode2);
}