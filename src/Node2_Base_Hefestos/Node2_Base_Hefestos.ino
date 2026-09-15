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

char targetMessage[128] = "Aguardando sincronizacao...";
int rssiLoRa = 0;
char currentBand[4] = "FM";
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
  char username[64];
  unsigned long last_activity;
  unsigned long session_start;
  char auth_input[64];
  char auth_password[64];
  bool waiting_password;
} telnet_state = {false, 0, "", 0, 0, "", "", false};

struct BlockedIP {
  IPAddress ip;
  unsigned long blocked_since;
};
BlockedIP blocked_ips[MAX_BLOCKED_IPS];
int blocked_count = 0;

unsigned long last_barrida_check = 0;

// === Serial Communication with Node3 ===
HardwareSerial SerialNode2(0);

// === HTTP Session Management ===
#define MAX_HTTP_SESSIONS 4
#define HTTP_SESSION_IDLE_TIMEOUT 1800000   // 30 min
#define HTTP_SESSION_ABSOLUTE_TIMEOUT 14400000  // 4 hours

struct HTTPSession {
  char token[33];        // 16 bytes -> 32 hex chars + null
  IPAddress ip;
  unsigned long last_activity;
  unsigned long created_at;
  bool active;
};

HTTPSession http_sessions[MAX_HTTP_SESSIONS];

bool verifyHTTPSession(AsyncWebServerRequest* request) {
  if (!request->hasHeader("Cookie") && !request->hasHeader("X-Hefestos-Token")) {
    return false;
  }
  
  String token = "";
  if (request->hasHeader("X-Hefestos-Token")) {
    token = request->getHeader("X-Hefestos-Token")->value();
  } else if (request->hasHeader("Cookie")) {
    String cookie = request->getHeader("Cookie")->value();
    int pos = cookie.indexOf("X-Hefestos-Token=");
    if (pos >= 0) {
      pos += 17; // length of "X-Hefestos-Token="
      int end = cookie.indexOf(';', pos);
      if (end < 0) end = cookie.length();
      token = cookie.substring(pos, end);
    }
  }
  
  if (token.length() != 32) return false;
  
  unsigned long now = millis();
  for (int i = 0; i < MAX_HTTP_SESSIONS; i++) {
    if (http_sessions[i].active && 
        secureCompare(http_sessions[i].token, token.c_str()) &&
        http_sessions[i].ip == request->client()->remoteIP()) {
      
      if (now - http_sessions[i].last_activity > HTTP_SESSION_IDLE_TIMEOUT ||
          now - http_sessions[i].created_at > HTTP_SESSION_ABSOLUTE_TIMEOUT) {
        http_sessions[i].active = false;
        return false;
      }
      
      http_sessions[i].last_activity = now;
      return true;
    }
  }
  return false;
}

void cleanupHTTPSessions() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_HTTP_SESSIONS; i++) {
    if (http_sessions[i].active &&
        (now - http_sessions[i].last_activity > HTTP_SESSION_IDLE_TIMEOUT ||
         now - http_sessions[i].created_at > HTTP_SESSION_ABSOLUTE_TIMEOUT)) {
      http_sessions[i].active = false;
    }
  }
}

String generateSessionToken() {
  uint8_t random_bytes[16];
  esp_fill_random(random_bytes, 16);
  String token = "";
  for (int i = 0; i < 16; i++) {
    char hex[3];
    sprintf(hex, "%02x", random_bytes[i]);
    token += hex;
  }
  return token;
}

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

// === V4.1: Band Sweep and Jamming Detection ===

void barridaBanda() {
  const char* bandas[] = {"FM", "AM", "SW"};
  float freqs[][3] = {
      {8400, 10800, 100.1},     // FM
      {520, 1710, 1000},         // AM  
      {2300, 30000, 5000}        // SW
  };

  for (int b = 0; b < 3; b++) {
    for (int f = 0; f < 3; f++) {
      radioRX.setBand(bandas[b], freqs[b][f]);
      delay(50);
      int rssi = readRSSI();
      logSpectra(bandas[b], freqs[b][f], rssi);
    }
  }
}

int readRSSI() {
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    rssiLoRa = LoRa.packetRssi();
    return rssiLoRa;
  }
  return rssiLoRa;
}

void logSpectra(const char* banda, float freq, int rssi) {
  debug.logf("SPECTRA: Banda=%s Freq=%.1f RSSI=%d dBm", banda, freq, rssi);
}

// Jamming detection structure
struct LinkMetric {
  uint32_t last_counter;
  uint32_t gaps;
  int snr_estimate;
  bool jamming_detected;
  unsigned long jamming_since;
};

LinkMetric link_metrics;

void monitorLinkQuality() {
  static uint32_t last_rx_counter = 0;
  uint32_t current = secProto.getRXCounter();

  if (current != last_rx_counter && current != 0) {
    uint32_t gap = current - last_rx_counter;
    if (gap > 0) {
      // Map gap to SNR estimate: smaller gap = better SNR
      link_metrics.snr_estimate = map(gap, 1, 100, 100, 0);
      link_metrics.gaps++;

      if (link_metrics.snr_estimate < 20) {
        if (!link_metrics.jamming_detected) {
          link_metrics.jamming_detected = true;
          link_metrics.jamming_since = millis();
          debug.logWarning("JAMMING DETECTED - SNR below threshold");
        }
      } else {
        if (link_metrics.jamming_detected) {
          link_metrics.jamming_detected = false;
          debug.log("Jamming condition cleared");
        }
      }
    }
  }
  last_rx_counter = current;
}

bool isJammingDetected() {
  return link_metrics.jamming_detected;
}

// === Serial Buffer Processing ===
void processSerialBuffer() {
  if (!SerialNode2) return;
  
  while (SerialNode2.available()) {
    char c = SerialNode2.read();
    if (c == '\n') {
      waitingSerialResponse = false;
    } else {
      serialBufferResponse += c;
    }
  }
}

// === HTTP Endpoints ===

// Login endpoint - defined as function
void handleLogin(AsyncWebServerRequest *request) {
    if (!request->hasParam("user", true) || !request->hasParam("pass", true)) {
      request->send(400, "text/plain", "Missing credentials");
      return;
    }
    String user = request->getParam("user", true)->value();
    String pass = request->getParam("pass", true)->value();
    
    if (secureCompare(user.c_str(), config.getCLIUsername()) &&
        secureCompare(pass.c_str(), config.getCLIPassword())) {
      cleanupHTTPSessions();
      
      String token = generateSessionToken();
      for (int i = 0; i < MAX_HTTP_SESSIONS; i++) {
        if (!http_sessions[i].active) {
          token.toCharArray(http_sessions[i].token, 33);
          http_sessions[i].ip = request->client()->remoteIP();
          http_sessions[i].last_activity = millis();
          http_sessions[i].created_at = millis();
          http_sessions[i].active = true;
          break;
        }
      }
      
      AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", "{\"token\":\"" + token + "\"}");
      resp->addHeader("Set-Cookie", "X-Hefestos-Token=" + token + "; HttpOnly; Path=/");
      resp->addHeader("Content-Security-Policy", "default-src 'self'");
      request->send(resp);
    } else {
      if (!rateLimiter.allowCommand(request->client()->remoteIP().toString().c_str())) {
        request->send(429, "text/plain", "Too many attempts");
      } else {
        request->send(401, "text/plain", "Invalid credentials");
      }
    }
}

// Logout endpoint - defined as function
void handleLogout(AsyncWebServerRequest *request) {
    String token = "";
    if (request->hasHeader("X-Hefestos-Token")) {
      token = request->getHeader("X-Hefestos-Token")->value();
    } else if (request->hasHeader("Cookie")) {
      String cookie = request->getHeader("Cookie")->value();
      int pos = cookie.indexOf("X-Hefestos-Token=");
      if (pos >= 0) {
        pos += 17;
        int end = cookie.indexOf(';', pos);
        if (end < 0) end = cookie.length();
        token = cookie.substring(pos, end);
      }
    }
    
    if (token.length() == 32) {
      for (int i = 0; i < MAX_HTTP_SESSIONS; i++) {
        if (http_sessions[i].active && secureCompare(http_sessions[i].token, token.c_str())) {
          http_sessions[i].active = false;
          break;
        }
      }
    }
    
    AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", "{\"ok\":true}");
    resp->addHeader("Set-Cookie", "X-Hefestos-Token=; HttpOnly; Path=/; Max-Age=0");
    request->send(resp);
}

// OTA Update endpoint - v4.1 (DISABLED - not implemented)
void handleOTA(AsyncWebServerRequest *request) {
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    
    debug.logWarning("OTA endpoint disabled - not implemented");
    AsyncWebServerResponse *resp = request->beginResponse(501, "application/json", 
      "{\"status\":\"disabled\",\"error\":\"OTA not implemented - use serial flashing\"}");
    resp->addHeader("Content-Security-Policy", "default-src 'self'");
    request->send(resp);
}

// Jamming status endpoint - v4.1
void handleJamming(AsyncWebServerRequest *request) {
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    
    String status = isJammingDetected() ? "DETECTADO" : "NORMAL";
    int snr = link_metrics.snr_estimate;
    
    char json[128];
    snprintf(json, sizeof(json),
      "{\"jamming\":\"%s\",\"snr\":%d,\"since\":%lu}", 
      status.c_str(), snr, link_metrics.jamming_since);
    
    AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", json);
    resp->addHeader("Content-Security-Policy", "default-src 'self'");
    request->send(resp);
}

// Dados endpoint
void handleDados(AsyncWebServerRequest *request) {
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    StaticJsonDocument<1024> doc;
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
}

// Sintonizar endpoint
void handleSintonizar(AsyncWebServerRequest *request) {
    if (!rateLimiter.allowCommand(request->client()->remoteIP().toString().c_str())) {
      request->send(429, "text/plain", "Rate limit exceeded");
      return;
    }
    
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    
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
}

// === V4.1: Dashboard Capture History Endpoints ===

String serialBufferResponse = "";
unsigned long serialRequestTime = 0;
bool waitingSerialResponse = false;

void solicitarUltimaCaptura() {
  if (SerialNode2 && !waitingSerialResponse) {
    SerialNode2.println("GET_CAPTURE");
    serialRequestTime = millis();
    waitingSerialResponse = true;
  }
}

void solicitarHistoricoCapturas() {
  if (SerialNode2 && !waitingSerialResponse) {
    SerialNode2.println("GET_HISTORICO");
    serialRequestTime = millis();
    waitingSerialResponse = true;
  }
}

// Endpoint: Última captura
void handleUltima(AsyncWebServerRequest *request) {
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    
    solicitarUltimaCaptura();
    
    unsigned long startWait = millis();
    while (waitingSerialResponse && (millis() - startWait < 200)) {
      delay(10);
      processSerialBuffer();
    }
    
    if (serialBufferResponse.length() > 0) {
      AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", serialBufferResponse);
      resp->addHeader("Content-Security-Policy", "default-src 'self'");
      serialBufferResponse = "";
      waitingSerialResponse = false;
      request->send(resp);
    } else {
      String fallback = "{\"tipo\":\"NONE\",\"dados\":\"No data from Node3\",\"timestamp\":" + String(millis()) + "}";
      AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", fallback);
      resp->addHeader("Content-Security-Policy", "default-src 'self'");
      waitingSerialResponse = false;
      request->send(resp);
    }
}

// Endpoint: Histórico de capturas
void handleHistorico(AsyncWebServerRequest *request) {
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    
    solicitarHistoricoCapturas();
    
    unsigned long startWait = millis();
    while (waitingSerialResponse && (millis() - startWait < 500)) {
      delay(10);
      processSerialBuffer();
    }
    
    if (serialBufferResponse.length() > 0) {
      AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", serialBufferResponse);
      resp->addHeader("Content-Security-Policy", "default-src 'self'");
      serialBufferResponse = "";
      waitingSerialResponse = false;
      request->send(resp);
    } else {
      String fallback = "{\"total_captures\":0,\"capture_history\":[]}";
      AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", fallback);
      resp->addHeader("Content-Security-Policy", "default-src 'self'");
      waitingSerialResponse = false;
      request->send(resp);
    }
}

// Endpoint: Limpar histórico
void handleClearHistorico(AsyncWebServerRequest *request) {
    if (!verifyHTTPSession(request)) {
      request->send(401, "text/plain", "Unauthorized");
      return;
    }
    
    if (SerialNode2) {
      SerialNode2.println("CLEAR_HISTORICO");
    }
    
    AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", "{\"status\":\"ok\"}");
    resp->addHeader("Content-Security-Policy", "default-src 'self'");
    request->send(resp);
}

void loop() {
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
          debug.logf("RX #%u: %s (GCM OK)", counter, targetMessage.c_str());
        }
      }
    } else {
      gcm_invalid_count++;
    }
  }
  
  // Barrida periódica de banda a cada 30 segundos - v4.1
  unsigned long now = millis();
  if (now - last_barrida_check > 30000) {
    last_barrida_check = now;
    barridaBanda();
  }
  
  monitorLinkQuality();
}

static bool secureCompare(const char* a, const char* b) {
  if (!a || !b) return false;
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  volatile uint8_t result = (len_a != len_b);
  size_t min_len = (len_a < len_b) ? len_a : len_b;
  for (size_t i = 0; i < min_len; i++) {
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

        if (secureCompare(telnet_state.username.c_str(), config.getCLIUsername()) &&
            secureCompare(telnet_state.auth_password.c_str(), config.getCLIPassword())) {
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

// === Dashboard HTML - Index Page ===
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="pt-br"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HEFESTOS SIGINT v4.0 Dashboard</title>
<style>
body{font-family:'Courier New',monospace;background:#050505;color:#0f0;margin:0;padding:20px}
.container{max-width:1200px;margin:0 auto}
.card{background:#111;border:1px solid #0f0;margin:15px 0;padding:20px;border-radius:8px}
.card h3{color:#0f0;margin-top:0}
.stats{color:#ffff00;font-size:0.9em;margin:10px 0}
.capture-item{padding:10px;border-top:1px solid #080;margin:5px 0}
.capture-item .time{color:#666;font-size:0.8em}
.capture-item .tipo{color:#ff0;font-weight:bold}
.capture-item .dados{color:#0ff}
.btn{padding:10px 16px;background:#0f0;color:#000;border:none;cursor:pointer;font-weight:bold;border-radius:4px;margin:5px}
.btn:hover{background:#0ff}
.btn-danger{background:#f00;color:#fff}
.btn-danger:hover{background:#f55}
.status-badge{padding:4px 8px;border-radius:4px;font-weight:bold}
.status-ok{background:#0f0;color:#000}
.status-error{background:#f00;color:#fff}
#ultima-captura{background:#1a1a1a;border:2px solid #0f0;padding:15px;margin:10px 0;border-radius:8px}
#ultima-captura .label{color:#666;font-size:0.8em}
#ultima-captura .value{color:#0ff;font-size:1.1em}
</style></head><body>
<div class="container">
<h1>[ HEFESTOS SIGINT v4.0 - DASHBOARD ]</h1>

<div class="card">
<h3>[+] Status Operacional</h3>
<p class="stats">RX: <span id="rx-count">0</span> | GCM OK: <span id="gcm-ok">0</span> | GCM FAIL: <span id="gcm-fail">0</span> | REPLAY: <span id="replay">0</span></p>
<p>Alvo: <span id="msg">--</span></p>
<p>RSSI: <span id="rssi">0</span> dBm <span id="rssi-status" class="status-badge status-ok">OK</span></p>
</div>

<div class="card">
<h3>[!] Última Captura</h3>
<div id="ultima-captura">
<div class="label">Tipo</div><div class="value" id="cap-tipo">--</div>
<div class="label">Dados</div><div class="value" id="cap-dados">Aguardando dados...</div>
<div class="label">Timestamp</div><div class="value" id="cap-time">-- ms</div>
</div>
</div>

<div class="card">
<h3>[~] Histórico de Capturas</h3>
<p class="stats">Total: <span id="total-captures">0</span> capturas</p>
<div id="historico-list">
<p>Aguardando dados...</p>
</div>
</div>

<div class="card">
<h3>[*] Controles</h3>
<button class="btn" onclick="atualizarTudo()">Atualizar Agora</button>
<button class="btn btn-danger" onclick="limparHistorico()">Limpar Histórico</button>
<p class="stats">Atualização automática: a cada 2 segundos</p>
</div>
</div>

<script>
let intervalId = null;

function atualizarTudo() {
  atualizarStatus();
  atualizarUltimaCaptura();
  atualizarHistorico();
}

function atualizarStatus() {
  fetch('/dados')
    .then(r => r.json())
    .then(d => {
      document.getElementById('rx-count').innerText = d.rx_count;
      document.getElementById('gcm-ok').innerText = d.gcm_ok;
      document.getElementById('gcm-fail').innerText = d.gcm_fail;
      document.getElementById('replay').innerText = d.replay_count;
      document.getElementById('msg').innerText = d.mensagem?.substring(0, 40) || '--';
      document.getElementById('rssi').innerText = d.rssi;
      
      const rssiStatus = document.getElementById('rssi-status');
      if (d.rssi > -80) {
        rssiStatus.className = 'status-badge status-ok';
        rssiStatus.innerText = 'FORTE';
      } else if (d.rssi > -100) {
        rssiStatus.className = 'status-badge status-ok';
        rssiStatus.innerText = 'BOM';
      } else {
        rssiStatus.className = 'status-badge status-error';
        rssiStatus.innerText = 'FRACO';
      }
    })
    .catch(e => console.error('Erro status:', e));
}

function atualizarUltimaCaptura() {
  fetch('/ultima')
    .then(r => r.json())
    .then(d => {
      document.getElementById('cap-tipo').innerText = d.tipo || 'NONE';
      document.getElementById('cap-dados').innerText = d.dados?.substring(0, 60) || 'Sem dados';
      document.getElementById('cap-time').innerText = d.timestamp ? d.timestamp + ' ms' : '--';
    })
    .catch(e => {
      document.getElementById('cap-tipo').innerText = 'ERRO';
      document.getElementById('cap-dados').innerText = 'Falha ao conectar';
    });
}

function atualizarHistorico() {
  fetch('/historico')
    .then(r => r.json())
    .then(d => {
      document.getElementById('total-captures').innerText = d.total_captures || 0;
      
      const list = document.getElementById('historico-list');
      if (!d.capture_history || d.capture_history.length === 0) {
        list.innerHTML = '<p style="color:#666">Nenhuma captura registrada</p>';
        return;
      }
      
      let html = '';
      d.capture_history.forEach((item, idx) => {
        html += '<div class="capture-item">';
        html += '<span class="tipo">[' + item.tipo + ']</span> ';
        html += '<span class="dados">' + (item.dados?.substring(0, 45) || '') + '</span>';
        html += '<span class="time"> - ' + (item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '--') + '</span>';
        html += '</div>';
      });
      list.innerHTML = html;
    })
    .catch(e => {
      document.getElementById('historico-list').innerHTML = '<p style="color:#f00">Erro ao carregar histórico</p>';
    });
}

function limparHistorico() {
  if (confirm('Tem certeza que deseja limpar o histórico de capturas?')) {
    fetch('/clear_historico', {method: 'POST'})
      .then(() => {
        atualizarHistorico();
        alert('Histórico limpo com sucesso');
      })
      .catch(e => alert('Erro ao limpar'));
  }
}

// Iniciar atualizações automáticas
intervalId = setInterval(atualizarTudo, 2000);
atualizarTudo();
window.addEventListener('beforeunload', () => { if (intervalId) clearInterval(intervalId); });
</script>
</body></html>)rawliteral";

// === Setup Function ===
void setup() {
  esp_task_wdt_init(10, true);
  esp_task_wdt_add(NULL);

  Serial.begin(115200);
  debug.begin(115200);
  debug.log("Node2 v4.0: Inicializando...");
  
  // Initialize serial for Node3 communication
  SerialNode2.begin(9600, SERIAL_8N1, N2_UART_RX, N2_UART_TX);

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
    if (!verifyHTTPSession(request)) {
      AsyncWebServerResponse *resp = request->beginResponse(401, "text/html", "<html><body><h1>401 Unauthorized</h1><p><a href='/login'>Login</a></p></body></html>");
      resp->addHeader("WWW-Authenticate", "Bearer");
      request->send(resp);
      return;
    }
    AsyncWebServerResponse *resp = request->beginResponse_P(200, "text/html", index_html);
    resp->addHeader("Content-Security-Policy", "default-src 'self'");
    resp->addHeader("X-Content-Type-Options", "nosniff");
    resp->addHeader("X-Frame-Options", "DENY");
    request->send(resp);
  });

  server.on("/login", HTTP_POST, handleLogin);
  server.on("/logout", HTTP_POST, handleLogout);
  server.on("/ota", HTTP_POST, handleOTA);
  server.on("/jamming", HTTP_GET, handleJamming);
  server.on("/dados", HTTP_GET, handleDados);
  server.on("/sintonizar", HTTP_GET, handleSintonizar);
  server.on("/ultima", HTTP_GET, handleUltima);
  server.on("/historico", HTTP_GET, handleHistorico);
  server.on("/clear_historico", HTTP_POST, handleClearHistorico);

  server.begin();
  debug.log("Node2 v4.0: Ready");
}