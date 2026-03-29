// Node 3: Caixa Preta Forense e Interface Serial (Arduino)
#include <SoftwareSerial.h>
#include <SPI.h>
#include <SD.h>

SoftwareSerial SerialESP(2, 3); 

#define LED_VERDE 7    
#define LED_VERMELHO 8 
#define BUZZER 9       
#define CS_SD 4 

File arquivoLog;

void setup() {
  Serial.begin(115200);
  SerialESP.begin(9600); 

  pinMode(LED_VERDE, OUTPUT); 
  pinMode(LED_VERMELHO, OUTPUT); 
  pinMode(BUZZER, OUTPUT);

  Serial.println("=========================================");
  Serial.println(" HEFESTOS - DATA LOGGER FORENSE (SD)");
  Serial.println("=========================================");

  if (!SD.begin(CS_SD)) {
    Serial.println("[ ERRO ] Falha na leitura do modulo SPI SD Card."); 
    tone(BUZZER, 500, 1000); 
  } else {
    arquivoLog = SD.open("HEFESTOS.CSV", FILE_WRITE);
    if (arquivoLog) {
      arquivoLog.println("TEMPO_MS,TIPO,DADOS"); 
      arquivoLog.close();
      Serial.println("Sistema de log indexado com sucesso.");
    }
  }
  
  tone(BUZZER, 1000, 100); 
  delay(150); 
  tone(BUZZER, 1500, 100);
}

void gravarNoSD(String dado) {
  arquivoLog = SD.open("HEFESTOS.CSV", FILE_WRITE);
  if (arquivoLog) {
    String tipo = dado.startsWith("ALVO|") ? "ALVO_CONFIRMADO" : "SNIFFER_RAW";
    dado.replace("ALVO|", ""); 
    dado.replace("SNIFFER|", "");
    
    arquivoLog.print(millis()); 
    arquivoLog.print(",");
    arquivoLog.print(tipo); 
    arquivoLog.print(",");
    arquivoLog.println(dado);
    arquivoLog.close(); 
  }
}

void loop() {
  if (SerialESP.available()) {
    String dados = SerialESP.readStringUntil('\n'); 
    dados.trim();
    
    if (dados.length() > 0) {
      gravarNoSD(dados);

      if (dados.startsWith("ALVO|")) {
        Serial.println("\n[+] TARGET: " + dados.substring(5));
        digitalWrite(LED_VERDE, HIGH); 
        tone(BUZZER, 2000, 200); 
        delay(300); 
        digitalWrite(LED_VERDE, LOW);
      } 
      else if (dados.startsWith("SNIFFER|")) {
        Serial.println("[!] RAW: " + dados.substring(8));
        digitalWrite(LED_VERMELHO, HIGH); 
        delay(50); 
        digitalWrite(LED_VERMELHO, LOW);
      }
    }
  }
}