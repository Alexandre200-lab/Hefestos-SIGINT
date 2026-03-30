// Node 1: Transmissor Alvo Tatica (ESP32) - Refatorado v2.0
#include <SPI.h>
#include <LoRa.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <Adafruit_SI4713.h>
#include <AESLib.h>

// Bibliotecas modulares
#include "../lib/config.h"
#include "../lib/crypto_hmac.h"
#include "../lib/debug.h"

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define FM_RST 32
#define FM_FREQ 10010

#define GPS_POLL_INTERVAL 1000  // Reduzido de 3000ms para 1000ms (melhoria #10)
#define DEBUG_MODE 1            // Ativa logs (melhoria #13)

TinyGPSPlus gps;
HardwareSerial SerialGPS(2);
Adafruit_SI4713 radioTX = Adafruit_SI4713(FM_RST);

ConfigManager config;
DebugLogger debug;
AESLib aesLib;

char cleartext[256];
char ciphertext[512];
byte aes_key[16];
byte aes_iv[16];

unsigned long tempoAnterior = 0;
uint32_t packet_counter = 0;

String encriptarDados(String mensagem) {
  mensagem.toCharArray(cleartext, 256);
  uint16_t clen = String(cleartext).length();
  aesLib.encrypt64((const byte*)cleartext, clen, (char*)ciphertext, aes_key, sizeof(aes_key), aes_iv);
  return String(ciphertext);
}

void setup() {
  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node1: Inicializando...");

  // Carrega configuração de EEPROM (melhoria #1)
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
    String lat = gps.location.isValid() ? String(gps.location.lat(), 6) : "Buscando...";
    String lon = gps.location.isValid() ? String(gps.location.lng(), 6) : "Buscando...";

    String pacoteOriginal = "ID:ALVO_01|Lat:" + lat + "|Lon:" + lon;
    String pacoteSeguro = encriptarDados(pacoteOriginal);

    // Calcula assinatura HMAC para autenticidade (melhoria #4)
    byte signature[8];
    PacketAuthenticator::sign(aes_key, 16, (byte*)pacoteSeguro.c_str(), pacoteSeguro.length(), signature);

    // Transmite com HMAC
    LoRa.beginPacket();
    LoRa.print(pacoteSeguro);
    LoRa.write(signature, 8);
    LoRa.endPacket();

    packet_counter++;
    if (DEBUG_MODE) {
      debug.logf("TX Packet #%u: %s (HMAC OK)", packet_counter, lat.c_str());
      debug.printMemory();
    }
  }
}