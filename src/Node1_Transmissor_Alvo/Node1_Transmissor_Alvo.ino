// Node 1: Transmissor Alvo Tatica (ESP32) - v3.0
// Segurança: AES-GCM + Nonce/Counter Anti-Replay
#include <SPI.h>
#include <LoRa.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <Adafruit_SI4713.h>

#include "../lib/config.h"
#include "../lib/crypto_gcm.h"
#include "../lib/secure_protocol.h"
#include "../lib/debug.h"

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define FM_RST 32
#define FM_FREQ 10010

#define GPS_POLL_INTERVAL 1000

TinyGPSPlus gps;
HardwareSerial SerialGPS(2);
Adafruit_SI4713 radioTX = Adafruit_SI4713(FM_RST);

ConfigManager config;
DebugLogger debug;
SecureProtocol secProto;
AESGCM aesgcm;

byte aes_key[16];
uint8_t iv[12];

unsigned long tempoAnterior = 0;
bool gps_valid = false;

void setup() {
  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node1 v3.0: Inicializando...");

  config.begin();
  memcpy(aes_key, config.getAESKey(), 16);
  aesgcm.setKey(aes_key, 16);

  SerialGPS.begin(9600, SERIAL_8N1, 16, 17);

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  LoRa.begin(915E6);
  LoRa.setSpreadingFactor(10);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setTxPower(20);
  
  secProto.begin(0xDEADBEEF);
  debug.logf("Counter init: %u", secProto.getTXCounter());

  radioTX.begin();
  radioTX.powerUp();
  radioTX.setTXpower(115);
  radioTX.tuneFM(FM_FREQ);

  debug.log("Node1 v3.0: Pronto para transmissao");
}

void loop() {
  while (SerialGPS.available() > 0) {
    gps.encode(SerialGPS.read());
  }

  if (millis() - tempoAnterior >= GPS_POLL_INTERVAL) {
    tempoAnterior = millis();

    gps_valid = gps.location.isValid() && gps.location.lat() != 0.0 && gps.location.lng() != 0.0;

    if (!gps_valid) {
      debug.logWarning("GPS: Sem sinal valido, aguardando...");
      return;
    }

    char latStr[16];
    char lonStr[16];
    dtostrf(gps.location.lat(), 10, 6, latStr);
    dtostrf(gps.location.lng(), 10, 6, lonStr);

    char payload[128];
    snprintf(payload, sizeof(payload), "ALVO_01|%s|%s", latStr, lonStr);

    uint32_t counter = secProto.getNextCounter();
    uint8_t output[256];
    int outLen = aesgcm.encrypt((byte*)payload, strlen(payload), output, counter);

    if (outLen > 0) {
      LoRa.beginPacket();
      LoRa.write(output, outLen);
      LoRa.endPacket();

      if (DEBUG_MODE) {
        debug.logf("TX #%u: %s,%s (GCM OK)", counter, latStr, lonStr);
      }
    }
  }
}