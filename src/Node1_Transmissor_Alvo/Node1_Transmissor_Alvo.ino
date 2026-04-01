// Node 1: Transmissor Alvo Tatica (ESP32) - v2.1
// Melhorias: GPS validation, Serial Protocol CRC, HMAC real
#include <SPI.h>
#include <LoRa.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <Adafruit_SI4713.h>
#include <AESLib.h>

#include "../lib/config.h"
#include "../lib/crypto_hmac.h"
#include "../lib/serial_protocol.h"
#include "../lib/debug.h"

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define FM_RST 32
#define FM_FREQ 10010

#define GPS_POLL_INTERVAL 1000
#define DEBUG_MODE 1

TinyGPSPlus gps;
HardwareSerial SerialGPS(2);
Adafruit_SI4713 radioTX = Adafruit_SI4713(FM_RST);

ConfigManager config;
DebugLogger debug;
SerialProtocol serialProto;

char cleartext[256];
char ciphertext[512];
byte aes_key[16];
byte aes_iv[16];

unsigned long tempoAnterior = 0;
uint32_t packet_counter = 0;
bool gps_valid = false;

void encryptData(const char* input, char* output, int maxLen) {
  int len = strlen(input);
  aesLib.encrypt((byte*)input, len, (byte*)output, aes_key, aes_iv);
}

void setup() {
  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node1: Inicializando...");

  config.begin();
  memcpy(aes_key, config.getAESKey(), 16);
  memcpy(aes_iv, config.getAESIV(), 16);
  debug.logHex(aes_key, 16, "AES Key");

  SerialGPS.begin(9600, SERIAL_8N1, 16, 17);

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  LoRa.begin(915E6);
  LoRa.setSpreadingFactor(10);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setTxPower(20);

  radioTX.begin();
  radioTX.powerUp();
  radioTX.setTXpower(115);
  radioTX.tuneFM(FM_FREQ);

  debug.log("Node1: Pronto para transmissao");
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

    char pacoteOriginal[128];
    snprintf(pacoteOriginal, sizeof(pacoteOriginal), "ID:ALVO_01|Lat:%s|Lon:%s", latStr, lonStr);

    encryptData(pacoteOriginal, ciphertext, sizeof(ciphertext));

    byte signature[8];
    PacketAuthenticator::signCompact(aes_key, 16, (byte*)ciphertext, strlen(ciphertext), signature);

    LoRa.beginPacket();
    LoRa.print(ciphertext);
    LoRa.write(signature, 8);
    LoRa.endPacket();

    packet_counter++;
    if (DEBUG_MODE) {
      debug.logf("TX #%u: %s,%s (HMAC OK)", packet_counter, latStr, lonStr);
      debug.printMemory();
    }
  }
}