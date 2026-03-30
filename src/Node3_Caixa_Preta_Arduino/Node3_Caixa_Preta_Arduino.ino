// Node 3: Caixa Preta Forense e Interface Serial (Arduino) - Refatorado v2.0
// Melhorias: CRC16 para UART, error recovery SD, logs circulares, modo debug
#include <SoftwareSerial.h>
#include <SPI.h>
#include <SD.h>

// Bibliotecas modulares
#include "../lib/serial_protocol.h"
#include "../lib/debug.h"

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

// Circular buffer para logs (melhoria #9)
#define LOG_BUFFER_SIZE 50
struct LogEntry {
  uint32_t timestamp;
  char tipo[16];
  char dados[128];
};
LogEntry log_buffer[LOG_BUFFER_SIZE];
int log_buffer_idx = 0;

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

    // Cria arquivo com cabeçalho
    if (!SD.exists("HEFESTOS.CSV")) {
      arquivoLog = SD.open("HEFESTOS.CSV", FILE_WRITE);
      if (arquivoLog) {
        arquivoLog.println("TEMPO_MS,TIPO,DADOS");
        arquivoLog.close();
      }
    }
  } else {
    sd_ok = false;
    debug.logError("SD Card FAILED - using RAM buffer only");
    tone(BUZZER, 500, 500);
  }
}

bool writeToSD(const char* tipo, const char* dados) {
  if (!sd_ok) {
    return false; // Usa fallback RAM buffer
  }

  int retries = 0;
  while (retries < SD_RETRY_MAX) {
    arquivoLog = SD.open("HEFESTOS.CSV", FILE_WRITE);
    if (arquivoLog) {
      arquivoLog.print(millis());
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

void addToRAMBuffer(const char* tipo, const char* dados) {
  LogEntry* entry = &log_buffer[log_buffer_idx];
  entry->timestamp = millis();
  strncpy(entry->tipo, tipo, sizeof(entry->tipo) - 1);
  strncpy(entry->dados, dados, sizeof(entry->dados) - 1);

  log_buffer_idx = (log_buffer_idx + 1) % LOG_BUFFER_SIZE;
}

void setup() {
  Serial.begin(115200);
  debug.begin(115200);

  SerialESP.begin(9600);

  pinMode(LED_VERDE, OUTPUT);
  pinMode(LED_VERMELHO, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  Serial.println("=========================================");
  Serial.println(" HEFESTOS - DATA LOGGER FORENSE v2.0");
  Serial.println(" CRC16 + Error Recovery + RAM Fallback");
  Serial.println("=========================================");

  initSDCard();

  delay(500);
  debug.log("Node3: Pronto para receber dados");
}

void loop() {
  // Verifica saúde do SD periodicamente
  unsigned long now = millis();
  if (now - last_sd_check > 30000) { // 30 segundos
    last_sd_check = now;
    if (!sd_ok) {
      initSDCard();
    }
  }

  if (SerialESP.available()) {
    // Tenta decodificar frame com CRC
    SerialFrame frame;
    uint8_t buffer[512];
    int buffer_idx = 0;

    // Lê bytes até encontrar start marker
    while (SerialESP.available() && buffer_idx < 512) {
      uint8_t b = SerialESP.read();
      buffer[buffer_idx++] = b;

      if (buffer_idx > 1 && buffer[buffer_idx - 1] == SERIAL_FRAME_END &&
          buffer[0] == SERIAL_FRAME_START) {
        // Tentativa de decodificar frame completo
        if (serialProto.decodeFrame(buffer, buffer_idx, &frame)) {
          // Frame válido com CRC OK
          char tipo[16];
          char dados[128];

          if (frame.type == FRAME_DATA) {
            // Extrai tipo (primeiros 5 caracteres antes de |)
            int pipe_pos = 0;
            for (int i = 0; i < frame.len && pipe_pos == 0; i++) {
              if (frame.payload[i] == '|') {
                pipe_pos = i;
              }
            }

            if (pipe_pos > 0) {
              memcpy(tipo, frame.payload, pipe_pos);
              tipo[pipe_pos] = '\0';

              int data_len = frame.len - pipe_pos - 1;
              memcpy(dados, &frame.payload[pipe_pos + 1], data_len);
              dados[data_len] = '\0';
            } else {
              strcpy(tipo, "RAW");
              memcpy(dados, frame.payload, frame.len);
              dados[frame.len] = '\0';
            }

            // Grava em SD com retry
            bool wrote_ok = writeToSD(tipo, dados);

            // Sempre grava em buffer RAM (fallback)
            addToRAMBuffer(tipo, dados);

            // Feedback físico
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
              Serial.println(failed_writes);
            }
          }

          // Reseta buffer
          buffer_idx = 0;
        } else {
          // Frame inválido - procura próximo START
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

  // Transmite heartbeat periodicamente (melhoria #5)
  serialProto.sendHeartbeat(SerialESP);
}
