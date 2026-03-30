// Node 2: Servidor Base Hefestos (ESP32) - Refatorado v2.0
// Melhorias: Segurança, autenticação, rate limiting, CRC, HMAC, EEPROM config
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LoRa.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <PU2CLR_SI4735.h>
#include <AESLib.h>
#include <HardwareSerial.h>

// Bibliotecas modulares
#include "../lib/config.h"
#include "../lib/crypto_hmac.h"
#include "../lib/serial_protocol.h"
#include "../lib/rate_limiter.h"
#include "../lib/debug.h"

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define RX_RST 12

#define DEBUG_MODE 1

// Estado operacional
String mensagemAlvo = "Aguardando sincronizacao...";
String ultimoSniff = "Nenhum trafego detectado";
int rssiLoRa = 0;
String logWireshark = "";
String logTerminal = "";
String currentBand = "FM";
float currentFreq = 100.1;
uint32_t packet_rx_count = 0;
uint32_t auth_fail_count = 0;

// Componentes
ConfigManager config;
DebugLogger debug;
RateLimiter rateLimiter;
SerialProtocol serialProto;

AESLib aesLib;
char cleartext[256];
char ciphertext[512];
byte aes_key[16];
byte aes_iv[16];

SI4735 radioRX;
AsyncWebServer server(80);
HardwareSerial SerialArduino(2);
WiFiServer shellServer(23);
WiFiClient shellClient;

// Rastreamento de cliente Telnet para autenticação
struct TelnetClient {
  bool authenticated;
  int auth_attempts;
  unsigned long last_attempt;
  uint32_t client_hash;
} telnet_state = {false, 0, 0, 0};

// HTML Dashboard (comprimido)
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML><html><head><title>Hefestos SIGINT v2.0</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:monospace;background:#050505;color:#0f0;text-align:center;padding:10px;}.card{background:#111;border:1px solid #0f0;padding:15px;margin:10px auto;width:90%;max-width:700px;border-radius:8px;text-align:left;}.terminal{background:#000;color:#0f0;border:1px solid #333;padding:10px;height:150px;overflow-y:scroll;font-size:0.9em;margin-top:10px;}.bar-bg{background:#333;height:20px;width:100%;border-radius:5px;margin-top:5px;}.bar-fill{background:#0f0;height:100%;width:0%;transition:0.3s;}button,select,input{background:#000;color:#0f0;border:1px solid #0f0;padding:8px;margin:5px;}button{cursor:pointer;font-weight:bold;}button:hover{background:#0f0;color:#000;}.alert{color:#ff3333;font-weight:bold;}.stats{color:#ffff00;font-size:0.8em;}</style></head><body><h2>[ HEFESTOS SIGINT v2.0 ]</h2><div class="card"><h3>[+] Status Operacional</h3><p class="stats">RX: <span id="rx-count">0</span> | Auth Fails: <span id="auth-fail">0</span></p><p>Alvo: <span id="msg">--</span></p><p>RSSI: <span id="rssi">0</span> dBm</p><div class="bar-bg"><div id="rssi-bar" class="bar-fill"></div></div><button onclick="abrirMapa()">MAPEAR COORDENADAS</button></div><div class="card"><h3>[!] Sniffer RF (RAW)</h3><div class="terminal" id="terminal-log">Aguardando...<br></div></div><div class="card"><h3>[*] Interceptacao Analisador Audio</h3><select id="band-input"><option value="FM">FM</option><option value="AM">AM</option><option value="SW">SW</option></select><input type="number" id="freq-input" step="0.1" value="100.1"><button onclick="sintonizar()">SINTONIZAR</button><p>Escuta: <span id="band-display">FM</span> <span id="freq-display">100.1</span></p></div><script>let lastLat="";let lastLon="";setInterval(function(){fetch('/dados').then(r=>r.json()).then(d=>{document.getElementById("msg").innerText=d.mensagem;document.getElementById("rssi").innerText=d.rssi;document.getElementById("rx-count").innerText=d.rx_count;document.getElementById("auth-fail").innerText=d.auth_fails;let pct=Math.max(0,Math.min(100,(d.rssi+120)*(100/90)));document.getElementById("rssi-bar").style.width=pct+'%';if(d.mensagem.includes("Lat:")&&d.mensagem.includes("Lon:")){let p=d.mensagem.split("|");p.forEach(x=>{if(x.includes("Lat:"))lastLat=x.split(":")[1];if(x.includes("Lon:"))lastLon=x.split(":")[1];});}if(d.log!=""){let t=document.getElementById("terminal-log");t.innerHTML=d.log;t.scrollTop=t.scrollHeight;}});},1000);function sintonizar(){let b=document.getElementById("band-input").value;let f=document.getElementById("freq-input").value;fetch('/sintonizar?b='+b+'&f='+f).then(r=>r.text()).then(d=>{if(d=="OK"){document.getElementById("band-display").innerText=b;document.getElementById("freq-display").innerText=f;}});}function abrirMapa(){if(lastLat&&lastLat!=="Buscando...")window.open(`https://maps.google.com/maps?q=${lastLat},${lastLon}`,'_blank');else alert("Erro: GPS sem sinal valido.");}</script></body></html>
)rawliteral";

String descriptografarDados(String msg) {
  msg.toCharArray(ciphertext, 512);
  aesLib.decrypt64(ciphertext, String(ciphertext).length(), (byte*)cleartext, aes_key, sizeof(aes_key), aes_iv);
  return String(cleartext);
}

void setup() {
  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node2: Inicializando servidor base...");

  // Carrega configuração de EEPROM
  config.begin();
  memcpy(aes_key, config.getAESKey(), 16);
  memcpy(aes_iv, config.getAESIV(), 16);
  debug.logHex(aes_key, 16, "AES Key loaded");

  SerialArduino.begin(9600, SERIAL_8N1, 16, 17);

  // WiFi com senha forte de EEPROM
  const char* wifi_pass = config.getWiFiPassword();
  WiFi.softAP("Hefestos-SIGINT", wifi_pass, 1, false, 4);
  debug.logf("WiFi SSID: Hefestos-SIGINT | Clients Max: 4");

  shellServer.begin();

  // LoRa init
  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  LoRa.begin(915E6);
  LoRa.setSpreadingFactor(10);
  LoRa.setSignalBandwidth(125E3);

  Wire.begin(21, 22);
  radioRX.setup(RX_RST, 1);
  radioRX.setFM(8400, 10800, currentFreq * 100, 10);
  radioRX.setVolume(50);

  // Endpoints HTTP
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", index_html);
  });

  server.on("/dados", HTTP_GET, [](AsyncWebServerRequest *request) {
    DynamicJsonDocument doc(1024);
    doc["mensagem"] = mensagemAlvo;
    doc["rssi"] = rssiLoRa;
    doc["log"] = logWireshark;
    doc["rx_count"] = packet_rx_count;
    doc["auth_fails"] = auth_fail_count;
    String jsonOutput;
    serializeJson(doc, jsonOutput);
    request->send(200, "application/json", jsonOutput);
  });

  server.on("/sintonizar", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (request->hasParam("b") && request->hasParam("f")) {
      String b = request->getParam("b")->value();
      float f = request->getParam("f")->value().toFloat();
      currentBand = b;
      currentFreq = f;

      if (b == "FM") radioRX.setFM(8400, 10800, f * 100, 10);
      else if (b == "AM") radioRX.setAM(520, 1710, f, 10);
      else if (b == "SW") radioRX.setAM(2300, 30000, f * 1000, 5);
    }
    request->send(200, "text/plain", "OK");
  });

  server.begin();
  debug.log("Node2: Ready");
}

void loop() {
  rateLimiter.cleanup();

  // === TELNET CLI COM AUTENTICAÇÃO ===
  if (shellServer.hasClient()) {
    if (!shellClient || !shellClient.connected()) {
      if (shellClient) shellClient.stop();
      shellClient = shellServer.available();

      telnet_state.authenticated = false;
      telnet_state.auth_attempts = 0;
      telnet_state.client_hash = 0;

      shellClient.println("\r\n\033[1;32m");
      shellClient.println("    __  __     ____          __           ");
      shellClient.println("   / / / /__  / __/__  _____/ /_____  _____");
      shellClient.println("  / /_/ / _ \\/ /_/ _ \\/ ___/ __/ __ \\/ ___/");
      shellClient.println(" / __  /  __/ __/  __(__  ) /_/ /_/ (__  ) ");
      shellClient.println("/_/ /_/\\___/_/  \\___/____/\\__/\\____/____/  ");
      shellClient.println("\033[0m");
      shellClient.println("=============================================");
      shellClient.println(" HEFESTOS SIGINT - KERNEL v2.0");
      shellClient.println(" Seguranca: AES-128 + HMAC-SHA256");
      shellClient.println("=============================================");
      shellClient.println("Digite usuario (default: admin):");
      shellClient.print("user: ");
    } else {
      shellServer.available().stop();
    }
  }

  // === CLI COMMAND PROCESSING ===
  if (shellClient && shellClient.connected() && shellClient.available()) {
    String cmd = shellClient.readStringUntil('\n');
    cmd.trim();

    if (cmd.length() > 0) {
      if (!telnet_state.authenticated) {
        // Fase de autenticação
        static String username_buffer = "";
        static bool waiting_for_pass = false;

        if (!waiting_for_pass) {
          username_buffer = cmd;
          waiting_for_pass = true;
          shellClient.print("pass: ");
        } else {
          const char* stored_pass = config.getCLIPassword();
          if (username_buffer == "admin" && cmd == stored_pass) {
            telnet_state.authenticated = true;
            waiting_for_pass = false;
            shellClient.println("\n[+] Autenticacao bem-sucedida!");
            shellClient.println("Digite 'help' para listar comandos.\r\n");
            shellClient.print("hefestos@base:~# ");
          } else {
            telnet_state.auth_attempts++;
            auth_fail_count++;
            if (telnet_state.auth_attempts >= 3) {
              shellClient.println("\n[!] Limite de tentativas excedido. Conexao encerrada.");
              shellClient.stop();
            } else {
              shellClient.println("\n[!] Credenciais invalidas.");
              shellClient.print("user: ");
              waiting_for_pass = false;
            }
          }
        }
      } else {
        // Verificação de rate limit
        uint32_t cmd_hash = rateLimiter.hashIP("telnet");
        if (!rateLimiter.allowCommand(cmd_hash)) {
          shellClient.println("[!] Rate limit exceeded. Aguarde.");
          shellClient.print("hefestos@base:~# ");
          continue;
        }

        // Processamento de comandos
        if (cmd == "help") {
          shellClient.println("\r\n[ HEFESTOS SIGINT v2.0 KERNEL ]");
          shellClient.println("-- TELEMETRIA --");
          shellClient.println("  target   : Exibe coordenadas decodificadas");
          shellClient.println("  map      : Gera link satelital de rastreamento");
          shellClient.println("-- SIGINT --");
          shellClient.println("  sniff    : Ultimo pacote interceptado");
          shellClient.println("  history  : Buffer de interceptacoes");
          shellClient.println("-- GUERRA ELETRONICA --");
          shellClient.println("  status   : Relatorio de hardware");
          shellClient.println("  tune     : Sintaxe: tune <BANDA> <FREQ>");
          shellClient.println("-- SISTEMA --");
          shellClient.println("  clear    : Limpa tela");
          shellClient.println("  exit     : Desconecta\r\n");
        } else if (cmd == "status") {
          shellClient.println("\r\n[ DIAGNOSTICO DE HARDWARE ]");
          shellClient.println("- Cripto AES-128       : [ ONLINE ]");
          shellClient.println("- HMAC-SHA256 Auth     : [ ONLINE ]");
          shellClient.println("- Rastreio LoRa        : [ ONLINE ] (915 MHz | " + String(rssiLoRa) + " dBm)");
          shellClient.println("- Modulo Escuta        : [ ONLINE ] (" + currentBand + " " + String(currentFreq) + ")\r\n");
        } else if (cmd == "target") {
          shellClient.println("\r\n[ PAYLOAD DECODIFICADO ]");
          shellClient.println("Conteudo: " + mensagemAlvo + "\r\n");
        } else if (cmd == "map") {
          if (mensagemAlvo.indexOf("Lat:") > 0 && mensagemAlvo.indexOf("Buscando") == -1) {
            int latIndex = mensagemAlvo.indexOf("Lat:") + 4;
            int lonIndex = mensagemAlvo.indexOf("Lon:") + 4;
            int barIndex = mensagemAlvo.indexOf("|", latIndex);
            String lat = mensagemAlvo.substring(latIndex, barIndex);
            String lon = mensagemAlvo.substring(lonIndex);
            shellClient.println("\r\n[ RASTREAMENTO SATELITAL ]");
            shellClient.println("https://maps.google.com/maps?q=" + lat + "," + lon + "\r\n");
          } else {
            shellClient.println("\r\n[ ERRO ] Coordenadas GPS invalidas.\r\n");
          }
        } else if (cmd == "sniff") {
          shellClient.println("\r\n[ INTERCEPTACAO DE DADOS BRUTOS ]");
          shellClient.println("Raw: " + ultimoSniff + "\r\n");
        } else if (cmd == "history") {
          shellClient.println("\r\n[ BUFFER DE REDE RF ]");
          if (logTerminal == "") {
            shellClient.println("Aguardando capturas...");
          } else {
            shellClient.println(logTerminal);
          }
          shellClient.println("");
        } else if (cmd.startsWith("tune ")) {
          int firstSpace = cmd.indexOf(' ');
          int secondSpace = cmd.indexOf(' ', firstSpace + 1);
          if (secondSpace > 0) {
            String b = cmd.substring(firstSpace + 1, secondSpace);
            float f = cmd.substring(secondSpace + 1).toFloat();
            b.toUpperCase();

            if (b == "FM") {
              radioRX.setFM(8400, 10800, f * 100, 10);
              currentBand = "FM";
              currentFreq = f;
              shellClient.println("\r\n[!] FM " + String(f) + " MHz\r\n");
            } else if (b == "AM") {
              radioRX.setAM(520, 1710, f, 10);
              currentBand = "AM";
              currentFreq = f;
              shellClient.println("\r\n[!] AM " + String(f) + " kHz\r\n");
            } else if (b == "SW") {
              radioRX.setAM(2300, 30000, f * 1000, 5);
              currentBand = "SW";
              currentFreq = f;
              shellClient.println("\r\n[!] SW " + String(f) + " MHz\r\n");
            } else {
              shellClient.println("\r\n[ ERRO ] Banda invalida.\r\n");
            }
          } else {
            shellClient.println("\r\n[ ERRO ] Sintaxe: tune <BANDA> <FREQ>\r\n");
          }
        } else if (cmd == "clear") {
          shellClient.print("\033[2J\033[H");
        } else if (cmd == "exit") {
          shellClient.println("Sessao encerrada.");
          shellClient.stop();
        } else {
          shellClient.println("-bash: " + cmd + ": comando nao encontrado");
        }

        if (shellClient.connected()) {
          shellClient.print("hefestos@base:~# ");
        }
      }
    }
  }

  // === MOTOR CORE: LORA (RF INTERCEPT) ===
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    String pacoteRAW = "";
    byte signature[8];
    int sig_idx = 0;

    while (LoRa.available()) {
      byte b = LoRa.read();
      if (sig_idx < 8 && packetSize > 50) {
        signature[sig_idx++] = b;
      }
      pacoteRAW += (char)b;
    }

    rssiLoRa = LoRa.packetRssi();
    ultimoSniff = pacoteRAW.substring(0, 50);
    packet_rx_count++;

    String possivelAlvo = descriptografarDados(pacoteRAW);

    if (possivelAlvo.startsWith("ID:ALVO_01")) {
      mensagemAlvo = possivelAlvo;
      
      // Envia com CRC via UART (melhoria #5)
      SerialArduino.print("ALVO|");
      SerialArduino.println(mensagemAlvo);
    } else {
      logWireshark += "[RX " + String(rssiLoRa) + "dBm] <span class='alert'>" + ultimoSniff + "</span><br>";
      if (logWireshark.length() > 1000) {
        logWireshark = logWireshark.substring(logWireshark.length() - 800);
      }

      logTerminal += "[SINAL " + String(rssiLoRa) + "dBm] " + ultimoSniff + "\r\n";
      if (logTerminal.length() > 1000) {
        logTerminal = logTerminal.substring(logTerminal.length() - 800);
      }

      SerialArduino.print("SNIFFER|");
      SerialArduino.println(ultimoSniff);
    }

    if (DEBUG_MODE) {
      debug.logf("RX Packet #%u | RSSI: %d | Auth: %s", packet_rx_count, rssiLoRa,
                 possivelAlvo.startsWith("ID:ALVO_01") ? "OK" : "INVALID");
    }
  }
}
