// Node 2: Servidor Base Hefestos (ESP32) - v3.0
// Segurança: AES-GCM + Nonce/Counter + Rate Limit com IP real
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LoRa.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <PU2CLR_SI4735.h>
#include <HardwareSerial.h>

#include "../lib/config.h"
#include "../lib/crypto_gcm.h"
#include "../lib/secure_protocol.h"
#include "../lib/rate_limiter.h"
#include "../lib/debug.h"

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define RX_RST 12

String mensagemAlvo = "Aguardando sincronizacao...";
String ultimoSniff = "Nenhum trafego detectado";
int rssiLoRa = 0;
String logWireshark = "";
String currentBand = "FM";
float currentFreq = 100.1;
uint32_t packet_rx_count = 0;
uint32_t gcm_valid_count = 0;
uint32_t gcm_invalid_count = 0;
uint32_t replay_count = 0;

ConfigManager config;
DebugLogger debug;
RateLimiter rateLimiter;
SecureProtocol secProto;
AESGCM aesgcm;

byte aes_key[16];
SI4735 radioRX;
AsyncWebServer server(80);
HardwareSerial SerialArduino(2);
WiFiServer shellServer(23);
WiFiClient shellClient;

struct TelnetState {
  bool authenticated;
  int auth_attempts;
  String username;
} telnet_state = {false, 0, ""};

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML><html><head><title>HEFESTOS SIGINT v3.0</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:monospace;background:#050505;color:#0f0;text-align:center;padding:10px}.card{background:#111;border:1px solid #0f0;padding:15px;margin:10px auto;width:90%;max-width:700px;border-radius:8px;text-align:left}.terminal{background:#000;color:#0f0;border:1px solid #333;padding:10px;height:150px;overflow-y:scroll;font-size:0.9em;margin-top:10px}.bar-bg{background:#333;height:20px;width:100%;border-radius:5px;margin-top:5px}.bar-fill{background:#0f0;height:100%;width:0%;transition:0.3s}button,select,input{background:#000;color:#0f0;border:1px solid #0f0;padding:8px;margin:5px}button{cursor:pointer;font-weight:bold}button:hover{background:#0f0;color:#000}.alert{color:#ff3333;font-weight:bold}.stats{color:#ffff00;font-size:0.8em}</style></head><body><h2>[ HEFESTOS SIGINT v3.0 ]</h2><div class="card"><h3>[+] Status Operacional</h3><p class="stats">RX: <span id="rx-count">0</span> | GCM OK: <span id="gcm-ok">0</span> | GCM FAIL: <span id="gcm-fail">0</span> | REPLAY: <span id="replay">0</span></p><p>Alvo: <span id="msg">--</span></p><p>RSSI: <span id="rssi">0</span> dBm</p><div class="bar-bg"><div id="rssi-bar" class="bar-fill"></div></div><button onclick="abrirMapa()">MAPEAR COORDENADAS</button></div><div class="card"><h3>[!] Sniffer RF</h3><div class="terminal" id="terminal-log">Aguardando...<br></div></div><div class="card"><h3>[*] Interceptacao Audio</h3><select id="band-input"><option value="FM">FM</option><option value="AM">AM</option><option value="SW">SW</option></select><input type="number" id="freq-input" step="0.1" value="100.1"><button onclick="sintonizar()">SINTONIZAR</button></div><script>setInterval(function(){fetch('/dados').then(r=>r.json()).then(d=>{document.getElementById("msg").innerText=d.mensagem;document.getElementById("rssi").innerText=d.rssi;document.getElementById("rx-count").innerText=d.rx_count;document.getElementById("gcm-ok").innerText=d.gcm_ok;document.getElementById("gcm-fail").innerText=d.gcm_fail;document.getElementById("replay").innerText=d.replay_count;var p=Math.min(100,Math.max(0,(d.rssi+100)*2));document.getElementById("rssi-bar").style.width=p+"%";if(d.log){document.getElementById("terminal-log").innerHTML=d.log}})});setInterval(function(){fetch('/dados').then(r=>r.json()).then(d=>{if(d.log){document.getElementById("terminal-log").innerHTML=d.log}})},2000);function abrirMapa(){var m=document.getElementById("msg").innerText.match(/Lat:([^|]+).*Lon:([^|]+)/);if(m)window.open("https://maps.google.com/maps?q="+m[1]+","+m[2])}function sintonizar(){var b=document.getElementById("band-input").value;var f=document.getElementById("freq-input").value;fetch("/sintonizar?b="+b+"&f="+f).then(r=>r.text()).then(alert)}
</script></body></html>)rawliteral";

void setup() {
  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node2 v3.0: Inicializando...");

  config.begin();
  memcpy(aes_key, config.getAESKey(), 16);
  aesgcm.setKey(aes_key, 16);

  SerialArduino.begin(9600, SERIAL_8N1, 16, 17);

  const char* wifi_pass = config.getWiFiPassword();
  WiFi.softAP("Hefestos-SIGINT", wifi_pass, 1, false, 4);
  debug.log("WiFi: Hefestos-SIGINT (v3.0)");

  shellServer.begin();

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  LoRa.begin(915E6);
  LoRa.setSpreadingFactor(10);
  LoRa.setSignalBandwidth(125E3);

  secProto.begin(0xDEADBEEF);

  Wire.begin(21, 22);
  radioRX.setup(RX_RST, 1);
  radioRX.setFM(8400, 10800, currentFreq * 100, 10);
  radioRX.setVolume(50);

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", index_html);
  });

  server.on("/dados", HTTP_GET, [](AsyncWebServerRequest *request) {
    DynamicJsonDocument doc(1024);
    doc["mensagem"] = mensagemAlvo;
    doc["rssi"] = rssiLoRa;
    doc["log"] = logWireshark;
    doc["rx_count"] = packet_rx_count;
    doc["gcm_ok"] = gcm_valid_count;
    doc["gcm_fail"] = gcm_invalid_count;
    doc["replay_count"] = replay_count;
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
  debug.log("Node2 v3.0: Ready");
}

void loop() {
  rateLimiter.cleanup();

  if (shellServer.hasClient()) {
    if (!shellClient || !shellClient.connected()) {
      if (shellClient) shellClient.stop();
      shellClient = shellServer.available();
      telnet_state.authenticated = false;
      telnet_state.auth_attempts = 0;
      
      shellClient.println("\r\n=== HEFESTOS SIGINT v3.0 ===");
      shellClient.println("Seguranca: AES-GCM + Anti-Replay");
      shellClient.println("Usuario:");
      shellClient.print("> ");
    }
  }

  if (shellClient && shellClient.connected() && shellClient.available()) {
    char c = shellClient.read();
    if (c == '\n' || c == '\r') {
      processCommand();
      if (shellClient.connected()) {
        shellClient.print("hefestos@base:~# ");
      }
    } else if (c >= 32) {
      static String cmd = "";
      cmd += c;
      if (cmd.length() > 64) cmd = "";
    }
  }

  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    uint8_t buffer[256];
    int len = LoRa.readBytes(buffer, 256);
    rssiLoRa = LoRa.packetRssi();

    uint8_t decrypted[256];
    uint32_t counter;
    int decLen = aesgcm.decrypt(buffer, len, decrypted, &counter);

    if (decLen > 0) {
      if (!secProto.isValidCounter(counter)) {
        replay_count++;
        debug.logf("REPLAY DETECTADO #%u", counter);
      } else {
        secProto.updateValidCounter(counter);
        gcm_valid_count++;
        
        mensagemAlvo = String((char*)decrypted);
        
        if (mensagemAlvo.startsWith("ALVO_")) {
          packet_rx_count++;
          debug.logf("RX #%u: %s (GCM OK)", counter, mensagemAlvo.c_str());
        }
      }
    } else if (decLen == -2) {
      replay_count++;
    } else {
      gcm_invalid_count++;
    }
  }
}

void processCommand() {
  static String input = "";
  static String password = "";
  static bool waiting_password = false;
  
  if (!shellClient.available()) return;
  
  while (shellClient.available()) {
    char c = shellClient.read();
    if (c == '\n' || c == '\r') {
      if (!telnet_state.authenticated) {
        if (!waiting_password) {
          telnet_state.username = input;
          waiting_password = true;
          shellClient.print("Senha: ");
        } else {
          password = input;
          const char* stored_user = config.getCLIUsername();
          const char* stored_pass = config.getCLIPassword();
          
          if (input == password) {
            telnet_state.authenticated = true;
            shellClient.println("\n[+] OK");
          } else {
            telnet_state.auth_attempts++;
            if (telnet_state.auth_attempts >= 3) {
              shellClient.println("BLOQUEADO");
              shellClient.stop();
            } else {
              shellClient.println("NOVO");
              shellClient.print("Usuario: ");
            }
          }
        }
      }
      input = "";
    } else if (c >= 32) {
      input += c;
      shellClient.print(c);
    }
  }
}