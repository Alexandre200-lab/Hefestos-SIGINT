// Node 1: Tactical Target Transmitter (ESP32) - v4.0
// Uses centralized pin definitions from hefestos_pins.h
#include <SPI.h>
#include <LoRa.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <Adafruit_Si4713.h>

#include <EEPROM.h>
#include "../lib/hefestos_pins.h"
#include "../lib/config.h"
#include "../lib/crypto_gcm.h"
#include "../lib/secure_protocol.h"
#include "../lib/debug.h"

TinyGPSPlus gps;
HardwareSerial SerialGPS(2);
Adafruit_Si4713 radioTX = Adafruit_Si4713(N1_FM_RST);

ConfigManager config;
DebugLogger debug;
SecureProtocol secProto;
AESGCM aesgcm;

uint8_t aes_key[16];
uint8_t iv[12];

unsigned long lastPollTime = 0;
bool gpsValid = false;

void setup() {
  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node1 v4.0: Inicializando...");

  config.begin();
  memcpy(aes_key, config.getAESKey(), 16);
  aesgcm.setKey(aes_key, 16);

  secProto.begin(0xDEADBEEF);

  uint32_t saved;
  EEPROM.get(EEPROM_ADDR_COUNTER, saved);
  if (saved != 0xFFFFFFFF && saved != 0) {
    secProto.setCounter(saved);
    debug.logf("Counter loaded from EEPROM: %u", saved);
  }
  debug.logf("Counter init: %u", secProto.getTXCounter());

  SerialGPS.begin(9600, SERIAL_8N1, N1_GPS_RX, N1_GPS_TX);

  LoRa.setPins(N1_LORA_SS, N1_LORA_RST, N1_LORA_DIO0);
  LoRa.begin(LORA_FREQ);
  LoRa.setSpreadingFactor(LORA_SF);
  LoRa.setSignalBandwidth(LORA_BW);
  LoRa.setTxPower(LORA_TX_POWER);

  radioTX.begin();
  radioTX.powerUp();
  radioTX.setTXpower(115);
  radioTX.tuneFM(10010);

  debug.log("Node1 v4.0: Pronto para transmissao");
}

void loop() {
  while (SerialGPS.available() > 0) {
    gps.encode(SerialGPS.read());
  }

  if (millis() - lastPollTime >= GPS_POLL_INTERVAL) {
    lastPollTime = millis();

    gpsValid = gps.location.isValid() && gps.location.lat() != 0.0 && gps.location.lng() != 0.0;

    if (!gpsValid) {
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
    int outLen = aesgcm.encrypt((uint8_t*)payload, strlen(payload), output, counter);

    if (outLen > 0) {
      // CSMA/CA: check channel before transmit
      unsigned long csma_start = millis();
      while (millis() - csma_start < 1000) {
        if (LoRa.parsePacket() == 0) break;  // Channel clear
        delay(random(5, 20));  // Random backoff
      }
      
      LoRa.beginPacket();
      LoRa.write(output, outLen);
      LoRa.endPacket();

      if (counter % TX_SAVE_INTERVAL == 0) {
        EEPROM.put(EEPROM_ADDR_COUNTER, counter);
        EEPROM.commit();
      }

      if (DEBUG_MODE) {
        debug.logf("TX #%u: %s,%s (GCM OK)", counter, latStr, lonStr);
      }
    }
  }
}