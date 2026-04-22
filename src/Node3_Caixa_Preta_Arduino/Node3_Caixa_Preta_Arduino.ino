// Node 3: Caixa Preta Forense e Interface Serial (Arduino) - v2.1
// Melhorias: RAM buffer flush quando SD voltar, protocolo CRC completo
#include <SoftwareSerial.h>
#include <SPI.h>
#include <SD.h>

#include "src/serial_protocol.h"
#include "src/debug.h"

SoftwareSerial SerialESP(2, 3);

#define LED_VERDE 7
#define LED_VERMELHO 8
#define BUZZER 9
#define CS_SD 4

#define DEBUG_MODE 1
#define SD_RETRY_MAX 3
#define SD_RETRY_DELAY 500

File arquivoLog;
SerialProtocol serialProto;
DebugLogger debug;

uint32_t total_logs = 0;
uint32_t failed_writes = 0;
unsigned long last_sd_check = 0;
bool sd_ok = false;

#define LOG_BUFFER_SIZE 16
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
  while (!SD.begin(CS_SD) && retries < SD_RETRY_MAX) {
    debug.logError("SD init failed, retrying...");
    tone(BUZZER, 300, 200);
    delay(SD_RETRY_DELAY);
    retries++;
  }

  if (SD.begin(CS_SD)) {
    sd_ok = true;
    debug.log("SD Card initialized OK");
    tone(BUZZER, 1000, 100);
    delay(100);
    tone(BUZZER, 1500, 100);

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
    tone(BUZZER, 500, 500);
  }
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

  SerialESP.begin(9600);

  pinMode(LED_VERDE, OUTPUT);
  pinMode(LED_VERMELHO, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  Serial.println("=========================================");
  Serial.println(" HEFESTOS - DATA LOGGER FORENSE v2.1");
  Serial.println(" CRC16 + RAM Flush + Error Recovery");
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

  if (SerialESP.available()) {
    SerialFrame frame;
    uint8_t buffer[512];
    int buffer_idx = 0;

    while (SerialESP.available() && buffer_idx < 512) {
      uint8_t b = SerialESP.read();
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
              digitalWrite(LED_VERDE, HIGH);
              tone(BUZZER, 2000, 200);
              delay(50);
              digitalWrite(LED_VERDE, LOW);
              Serial.print("[+] ALVO_TX: ");
            } else {
              digitalWrite(LED_VERMELHO, HIGH);
              delay(30);
              digitalWrite(LED_VERMELHO, LOW);
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

  serialProto.sendHeartbeat(SerialESP);
}