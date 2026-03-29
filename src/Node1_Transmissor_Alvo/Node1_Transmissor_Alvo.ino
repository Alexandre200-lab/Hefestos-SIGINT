// Node 1: Transmissor Alvo Tatica (ESP32)
#include <SPI.h>
#include <LoRa.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <Adafruit_SI4713.h>
#include <AESLib.h>

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define FM_RST 32
#define FM_FREQ 10010 // Frequencia Operacional FM: 100.1 MHz

TinyGPSPlus gps;
HardwareSerial SerialGPS(2); 
Adafruit_SI4713 radioTX = Adafruit_SI4713(FM_RST);

AESLib aesLib;
char cleartext[256];
char ciphertext[512];
byte aes_key[] = "ChaveTatica12345"; 
byte aes_iv[]  = "VetorInicializacao"; 

unsigned long tempoAnterior = 0;

String encriptarDados(String mensagem) {
  mensagem.toCharArray(cleartext, 256);
  uint16_t clen = String(cleartext).length();
  aesLib.encrypt64((const byte*)cleartext, clen, (char*)ciphertext, aes_key, sizeof(aes_key), aes_iv);
  return String(ciphertext);
}

void setup() {
  Serial.begin(115200);
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
}

void loop() {
  while (SerialGPS.available() > 0) { gps.encode(SerialGPS.read()); }

  if (millis() - tempoAnterior >= 3000) {
    tempoAnterior = millis();
    String lat = gps.location.isValid() ? String(gps.location.lat(), 6) : "Buscando...";
    String lon = gps.location.isValid() ? String(gps.location.lng(), 6) : "Buscando...";
    
    String pacoteOriginal = "ID:ALVO_01|Lat:" + lat + "|Lon:" + lon;
    String pacoteSeguro = encriptarDados(pacoteOriginal);

    LoRa.beginPacket(); 
    LoRa.print(pacoteSeguro); 
    LoRa.endPacket();
  }
}