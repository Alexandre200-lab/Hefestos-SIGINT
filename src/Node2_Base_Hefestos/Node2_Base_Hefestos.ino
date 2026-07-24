// Node 2: Hefestos Base Server (ESP32) - v4.0
// Uses centralized pin definitions from hefestos_pins.h
#include <WiFi.h>
#include <sys/time.h>
#include <esp_task_wdt.h>

void processCommand(String cmd);
void processAuth();
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LoRa.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <SI4735.h>
#include <HardwareSerial.h>

#include "../lib/hefestos_pins.h"
#include "../lib/config.h"
#include "../lib/crypto_gcm.h"
#include "../lib/secure_protocol.h"
#include "../lib/rate_limiter.h"
#include "../lib/debug.h"

String targetMessage = "Aguardando sincronizacao...";
int rssiLoRa = 0;
String currentBand = "FM";
float currentFreq = 100.1;
uint32_t packet_rx_count = 0;
uint32_t gcm_valid_count = 0;
uint32_t gcm_invalid_count = 0;
uint32_t replay_count = 0;

ConfigManager config;
DebugLogger debug;
SecureProtocol secProto;
AESGCM aesgcm;
PacketHistory packetHistory;

uint8_t aes_key[16];
SI4735 radioRX;
AsyncWebServer server(80);
WiFiServer shellServer(23);
WiFiClient shellClient;

struct TelnetState {
  bool authenticated;
  int auth_attempts;
  String username;
  unsigned long last_activity;
  unsigned long session_start;
  String auth_input;
  String auth_password;
  bool waiting_password;
} telnet_state = {false, 0, "", 0, 0, "", "", false};

struct BlockedIP {
  IPAddress ip;
  unsigned long blocked_since;
};
BlockedIP blocked_ips[MAX_BLOCKED_IPS];
int blocked_count = 0;

bool isIPBlocked(IPAddress ip) {
  unsigned long now = millis();
  for (int i = 0; i < blocked_count; i++) {
    if (blocked_ips[i].ip == ip) {
      if (now - blocked_ips[i].blocked_since > BLOCK_DURATION) {
        blocked_ips[i] = blocked_ips[--blocked_count];
        return false;
      }
      return true;
    }
  }
  return false;
}

void blockIP(IPAddress ip) {
  if (blocked_count < MAX_BLOCKED_IPS) {
    blocked_ips[blocked_count].ip = ip;
    blocked_ips[blocked_count].blocked_since = millis();
    blocked_count++;
  } else {
    int oldest = 0;
    for (int i = 1; i < MAX_BLOCKED_IPS; i++) {
      if (blocked_ips[i].blocked_since < blocked_ips[oldest].blocked_since) {
        oldest = i;
      }
    }
    debug.logf("BLOCK LRU: substituindo slot %d", oldest);
    blocked_ips[oldest].ip = ip;
    blocked_ips[oldest].blocked_since = millis();
  }
  persistBlockedIPs();
}

void persistBlockedIPs() {
  EEPROM.write(EEPROM_ADDR_BLOCKED, blocked_count);
  for (int i = 0; i < blocked_count; i++) {
    for (int j = 0; j < 4; j++) {
      EEPROM.write(EEPROM_ADDR_BLOCKED + 1 + i * 4 + j, blocked_ips[i].ip[j]);
    }
  }
  EEPROM.commit();
}

void loadBlockedIPs() {
  blocked_count = EEPROM.read(EEPROM_ADDR_BLOCKED);
  if (blocked_count > MAX_BLOCKED_IPS) blocked_count = 0;
  for (int i = 0; i < blocked_count; i++) {
    for (int j = 0; j < 4; j++) {
      blocked_ips[i].ip[j] = EEPROM.read(EEPROM_ADDR_BLOCKED + 1 + i * 4 + j);
    }
    blocked_ips[i].blocked_since = 0;
  }
  debug.logf("Loaded %d blocked IPs from EEPROM", blocked_count);
}

void cleanupBlockedIPs() {
  unsigned long now = millis();
  bool changed = false;
  for (int i = blocked_count - 1; i >= 0; i--) {
    if (now - blocked_ips[i].blocked_since > BLOCK_DURATION) {
      blocked_ips[i] = blocked_ips[--blocked_count];
      changed = true;
    }
  }
  if (changed && blocked_count > 0) {
    persistBlockedIPs();
  }
}

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML><html><head><title>HEFESTOS SIGINT v3.0</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:monospace;background:#050505;color:#0f0;text-align:center;padding:10px}.card{background:#111;border:1px solid #0f0;padding:15px;margin:10px auto;width:90%;max-width:700px;border-radius:8px;text-align:left}.terminal{background:#000;color:#0f0;border:1px solid #333;padding:10px;height:150px;overflow-y:scroll;font-size:0.9em;margin-top:10px}.bar-bg{background:#333;height:20px;width:100%;border-radius:5px;margin-top:5px}.bar-fill{background:#0f0;height:100%;width:0%;transition:0.3s}button,select,input{background:#000;color:#0f0;border:1px solid #0f0;padding:8px;margin:5px}button{cursor:pointer;font-weight:bold}button:hover{background:#0f0;color:#000}.alert{color:#ff3333;font-weight:bold}.stats{color:#ffff00;font-size:0.8em}</style></head><body><h2>[ HEFESTOS SIGINT v4.0 ]</h2><div class="card"><h3>[+] Status Operacional</h3><p class="stats">RX: <span id="rx-count">0</span> | GCM OK: <span id="gcm-ok">0</span> | GCM FAIL: <span id="gcm-fail">0</span> | REPLAY: <span id="replay">0</span></p><p>Alvo: <span id="msg">--</span></p><p>RSSI: <span id="rssi">0</span> dBm</p><div class="bar-bg"><div id="rssi-bar" class="bar-fill"></div></div><button onclick="abrirMapa()">MAPEAR COORDENADAS</button></div><div class="card"><h3>[!] Sniffer RF</h3><div class="terminal" id="terminal-log">Aguardando...<br></div></div><div class="card"><h3>[*] Interceptacao Audio</h3><select id="band-input"><option value="FM">FM</option><option value="AM">AM</option><option value="SW">SW</option></select><input type="number" id="freq-input" step="0.1" value="100.1"><button onclick="sintonizar()">SINTONIZAR</button></div><script>setInterval(function(){fetch('/dados').then(r=>r.json()).then(d=>{document.getElementById("msg").innerText=d.mensagem;document.getElementById("rssi").innerText=d.rssi;document.getElementById("rx-count").innerText=d.rx_count;document.getElementById("gcm-ok").innerText=d.gcm_ok;document.getElementById("gcm-fail").innerText=d.gcm_fail;document.getElementById("replay").innerText=d.replay_count;var p=Math.min(100,Math.max(0,(d.rssi+100)*2));document.getElementById("rssi-bar").style.width=p+"%";if(d.log){document.getElementById("terminal-log").innerText=d.log}})});function abrirMapa(){var m=document.getElementById("msg").innerText.match(/Lat:([^|]+).*Lon:([^|]+)/);if(m)window.open("https://maps.google.com/maps?q="+encodeURIComponent(m[1])+","+encodeURIComponent(m[2]))}function sintonizar(){var b=document.getElementById("band-input").value;var f=document.getElementById("freq-input").value;fetch("/sintonizar?b="+b+"&f="+f).then(r=>r.text()).then(alert)}
</script></body></html>)rawliteral";

void setup() {
  esp_task_wdt_init(10, true);
  esp_task_wdt_add(NULL);

  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node2 v4.0: Inicializando...");

  config.begin();
  memcpy(aes_key, config.getAESKey(), 16);
  aesgcm.setKey(aes_key, 16);

  loadBlockedIPs();

  const char* wifi_pass = config.getWiFiPassword();
  WiFi.softAP("Hefestos-SIGINT", wifi_pass, 1, false, 4);
  configTime(-3 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  debug.log("WiFi: Hefestos-SIGINT (v4.0)");

  shellServer.begin();

  LoRa.setPins(N2_LORA_SS, N2_LORA_RST, N2_LORA_DIO0);
  LoRa.begin(LORA_FREQ);
  LoRa.setSpreadingFactor(LORA_SF);
  LoRa.setSignalBandwidth(LORA_BW);

  secProto.begin(0xDEADBEEF);

  Wire.begin(N2_I2C_SDA, N2_I2C_SCL);
  radioRX.setup(N2_RX_RST, 1);
  radioRX.setFM(8400, 10800, currentFreq * 100, 10);
  radioRX.setVolume(50);

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    AsyncWebServerResponse *resp = request->beginResponse_P(200, "text/html", index_html);
    resp->addHeader("Content-Security-Policy", "default-src 'self'");
    resp->addHeader("X-Content-Type-Options", "nosniff");
    resp->addHeader("X-Frame-Options", "DENY");
    request->send(resp);
  });

  server.on("/dados", HTTP_GET, [](AsyncWebServerRequest *request) {
    DynamicJsonDocument doc(1024);
    doc["mensagem"] = targetMessage;
    doc["rssi"] = rssiLoRa;
    doc["rx_count"] = packet_rx_count;
    doc["gcm_ok"] = gcm_valid_count;
    doc["gcm_fail"] = gcm_invalid_count;
    doc["replay_count"] = replay_count;
    String jsonOutput;
    serializeJson(doc, jsonOutput);
    AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", jsonOutput);
    resp->addHeader("Content-Security-Policy", "default-src 'self'");
    resp->addHeader("X-Content-Type-Options", "nosniff");
    request->send(resp);
  });

  server.on("/sintonizar", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (request->hasParam("b") && request->hasParam("f")) {
      String b = request->getParam("b")->value();
      if (b.length() > 10) {
        request->send(400, "text/plain", "Parametro invalido");
        return;
      }
      float f = request->getParam("f")->value().toFloat();
      if (isnan(f) || isinf(f)) {
        request->send(400, "text/plain", "Frequencia invalida");
        return;
      }
      if (b != "FM" && b != "AM" && b != "SW") {
        request->send(400, "text/plain", "Banda invalida");
        return;
      }
      if (f < 0.1 || f > 30000.0) {
        request->send(400, "text/plain", "Frequencia invalida");
        return;
      }
      currentBand = b;
      currentFreq = f;
      if (b == "FM") radioRX.setFM(8400, 10800, f * 100, 10);
      else if (b == "AM") radioRX.setAM(520, 1710, f, 10);
      else if (b == "SW") radioRX.setAM(2300, 30000, f * 1000, 5);
    }
    AsyncWebServerResponse *resp = request->beginResponse(200, "text/plain", "OK");
    resp->addHeader("X-Content-Type-Options", "nosniff");
    request->send(resp);
  });

  server.begin();
  debug.log("Node2 v4.0: Ready");
}

void loop() {
  esp_task_wdt_reset();
  if (shellServer.hasClient()) {
    if (!shellClient || !shellClient.connected()) {
      if (shellClient) shellClient.stop();
      WiFiClient newClient = shellServer.available();

      if (isIPBlocked(newClient.remoteIP())) {
        newClient.println("\r\n=== HEFESTOS SIGINT v4.0 ===");
        newClient.println("IP temporariamente bloqueado.");
        delay(100);
        newClient.stop();
        return;
      }

      shellClient = newClient;
      telnet_state.authenticated = false;
      telnet_state.auth_attempts = 0;
      telnet_state.last_activity = millis();
      telnet_state.session_start = 0;
      telnet_state.waiting_password = false;
      telnet_state.auth_input = "";
      telnet_state.auth_password = "";

      shellClient.println("\r\n=== HEFESTOS SIGINT v4.0 ===");
      shellClient.println("Seguranca: AES-GCM + Anti-Replay");
      shellClient.println("Usuario:");
      shellClient.print("> ");
    }
  }

  if (shellClient && shellClient.connected()) {
    unsigned long now = millis();

    if (telnet_state.authenticated) {
      if (now - telnet_state.last_activity > SESSION_IDLE_TIMEOUT ||
          now - telnet_state.session_start > SESSION_ABSOLUTE_TIMEOUT) {
        shellClient.println("\r\n[SESSION EXPIRED]");
        shellClient.stop();
        telnet_state.authenticated = false;
        return;
      }
    }

    if (shellClient.available()) {
      if (!telnet_state.authenticated) {
        processAuth();
      } else {
        char cmdBuffer[128];
        int cmdLen = shellClient.readBytesUntil('\n', cmdBuffer, sizeof(cmdBuffer) - 1);
        if (cmdLen > 0) {
          cmdBuffer[cmdLen] = '\0';
          String cmdLine = String(cmdBuffer);
          cmdLine.trim();
          telnet_state.last_activity = millis();
          processCommand(cmdLine);
        }
        if (shellClient.connected()) {
          shellClient.print("hefestos@base:~# ");
        }
      }
    }
  }

  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    uint8_t buffer[256];
    int len = LoRa.readBytes(buffer, 256);
    rssiLoRa = LoRa.packetRssi();

    uint8_t decrypted[256];
    int decLen = aesgcm.decrypt(buffer, len, decrypted);

    if (decLen > 0) {
      uint32_t counter;
      memcpy(&counter, buffer, 4);

      if (!secProto.isValidCounter(counter)) {
        if (packetHistory.isDuplicate(counter)) {
          replay_count++;
          debug.logf("REPLAY DETECTADO #%u", counter);
        } else {
          debug.logf("RESYNC #%u (reboot detectado)", counter);
          secProto.updateValidCounter(counter);
          packetHistory.add(counter);
          gcm_valid_count++;
          targetMessage = String((char*)decrypted);
          if (targetMessage.startsWith("ALVO_")) {
            packet_rx_count++;
          }
        }
      } else {
        secProto.updateValidCounter(counter);
        packetHistory.add(counter);
        gcm_valid_count++;
        
        targetMessage = String((char*)decrypted);
        
        if (targetMessage.startsWith("ALVO_")) {
          packet_rx_count++;
          debug.logf("RX #%u: %s (GCM OK)", counter, mensagemAlvo.c_str());
        }
      }
    } else {
      gcm_invalid_count++;
    }
  }
}

static bool secureCompare(const char* a, const char* b, size_t maxLen) {
  volatile uint8_t result = 0;
  for (size_t i = 0; i < maxLen; i++) {
    result |= (uint8_t)a[i] ^ (uint8_t)b[i];
  }
  return result == 0;
}

void processAuth() {
  while (shellClient.available()) {
    char c = shellClient.read();
    if (c == '\n' || c == '\r') {
      if (!telnet_state.waiting_password) {
        telnet_state.username = telnet_state.auth_input;
        telnet_state.waiting_password = true;
        shellClient.print("Senha: ");
      } else {
        telnet_state.auth_password = telnet_state.auth_input;
        const char* stored_user = config.getCLIUsername();
        const char* stored_pass = config.getCLIPassword();

        if (secureCompare(telnet_state.username.c_str(), config.getCLIUsername(), CLI_USER_SIZE) &&
            secureCompare(telnet_state.auth_password.c_str(), config.getCLIPassword(), CLI_PASS_SIZE)) {
          telnet_state.authenticated = true;
          telnet_state.session_start = millis();
          telnet_state.last_activity = millis();
          shellClient.println("\n[+] OK");
        } else {
          telnet_state.auth_attempts++;
          if (telnet_state.auth_attempts >= MAX_AUTH_ATTEMPTS) {
            shellClient.println("BLOQUEADO");
            blockIP(shellClient.remoteIP());
            shellClient.stop();
          } else {
            shellClient.println("NOVO");
            shellClient.print("Usuario: ");
          }
        }
        telnet_state.waiting_password = false;
      }
      telnet_state.auth_input = "";
    } else if (c >= 32 && c <= 126) {
      if (telnet_state.auth_input.length() >= 64) {
        continue;
      }
      telnet_state.auth_input += c;
      if (telnet_state.waiting_password) {
        shellClient.print("*");
      } else {
        shellClient.print(c);
      }
    }
  }
}

void processCommand(String cmd) {
  if (cmd == "help") {
    shellClient.println("Comandos: help, status, freq, band, sair");
  } else if (cmd == "status") {
    shellClient.printf("RX: %u | GCM OK: %u | FAIL: %u | REPLAY: %u\r\n",
      packet_rx_count, gcm_valid_count, gcm_invalid_count, replay_count);
    shellClient.printf("RSSI: %d dBm | Banda: %s | Freq: %.1f\r\n",
      rssiLoRa, currentBand.c_str(), currentFreq);
  } else if (cmd == "sair") {
    shellClient.println("Encerrando sessao...");
    shellClient.stop();
    telnet_state.authenticated = false;
  } else if (cmd.startsWith("freq ")) {
    float f = cmd.substring(5).toFloat();
    if (f > 0) { currentFreq = f; shellClient.printf("Freq: %.1f\r\n", f); }
    else shellClient.println("Frequencia invalida");
  } else if (cmd.startsWith("band ")) {
    String b = cmd.substring(5);
    if (b == "FM" || b == "AM" || b == "SW") { currentBand = b; shellClient.println("Banda: " + b); }
    else shellClient.println("Banda invalida (FM/AM/SW)");
  } else if (cmd.length() > 0) {
    shellClient.println("Comando desconhecido. Digite 'help'.");
  }
}