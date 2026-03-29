// Node 2: Servidor Base Hefestos (ESP32) - CLI Expandida
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LoRa.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <PU2CLR_SI4735.h>
#include <AESLib.h>
#include <HardwareSerial.h>

#define LORA_SS 5
#define LORA_RST 14
#define LORA_DIO0 26
#define RX_RST 12

String mensagemAlvo = "Aguardando sincronizacao...";
String ultimoSniff = "Nenhum trafego detectado";
int rssiLoRa = 0;
String logWireshark = ""; 
String logTerminal = "";  

// Variaveis de Rastreamento de Estado (Para o comando 'status')
String currentBand = "FM";
float currentFreq = 100.1;

AESLib aesLib;
char cleartext[256];
char ciphertext[512];
byte aes_key[] = "ChaveTatica12345"; 
byte aes_iv[]  = "VetorInicializacao"; 

SI4735 radioRX;
AsyncWebServer server(80);
HardwareSerial SerialArduino(2); 

WiFiServer shellServer(23); 
WiFiClient shellClient;

// Painel Grafico (HTML/CSS padronizado, sem emojis)
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML><html><head><title>Hefestos SIGINT</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:monospace;background:#050505;color:#0f0;text-align:center;padding:10px;}.card{background:#111;border:1px solid #0f0;padding:15px;margin:10px auto;width:90%;max-width:700px;border-radius:8px;text-align:left;}.terminal{background:#000;color:#0f0;border:1px solid #333;padding:10px;height:150px;overflow-y:scroll;font-size:0.9em;margin-top:10px;}.bar-bg{background:#333;height:20px;width:100%;border-radius:5px;margin-top:5px;}.bar-fill{background:#0f0;height:100%;width:0%;transition:0.3s;}button,select,input{background:#000;color:#0f0;border:1px solid #0f0;padding:8px;margin:5px;}button{cursor:pointer;font-weight:bold;}button:hover{background:#0f0;color:#000;}.alert{color:#ff3333;font-weight:bold;}</style></head><body><h2>[ PROJETO HEFESTOS (by xd-neo) ]</h2><div class="card"><h3>[+] Alvo Identificado</h3><p>Dados: <span id="msg">--</span></p><p>Sinal: <span id="rssi">0</span> dBm</p><div class="bar-bg"><div id="rssi-bar" class="bar-fill"></div></div><button onclick="abrirMapa()">MAPEAR COORDENADAS</button></div><div class="card"><h3>[!] Sniffer RF (RAW Data)</h3><div class="terminal" id="terminal-log">Aguardando...<br></div></div><div class="card"><h3>[*] Interceptacao Analisador Audio</h3><select id="band-input"><option value="FM">FM</option><option value="AM">AM</option><option value="SW">SW</option></select><input type="number" id="freq-input" step="0.1" value="100.1"><button onclick="sintonizar()">SINTONIZAR ALVO</button><p>Escuta Ativa: <span id="band-display">FM</span> <span id="freq-display">100.1</span></p></div><script>let lastLat="";let lastLon="";setInterval(function(){fetch('/dados').then(r=>r.json()).then(d=>{document.getElementById("msg").innerText=d.mensagem;document.getElementById("rssi").innerText=d.rssi;let pct=Math.max(0,Math.min(100,(d.rssi+120)*(100/90)));document.getElementById("rssi-bar").style.width=pct+'%';if(d.mensagem.includes("Lat:")&&d.mensagem.includes("Lon:")){let p=d.mensagem.split("|");p.forEach(x=>{if(x.includes("Lat:"))lastLat=x.split(":")[1];if(x.includes("Lon:"))lastLon=x.split(":")[1];});}if(d.log!=""){let t=document.getElementById("terminal-log");t.innerHTML=d.log;t.scrollTop=t.scrollHeight;}});},1000);function sintonizar(){let b=document.getElementById("band-input").value;let f=document.getElementById("freq-input").value;fetch('/sintonizar?b='+b+'&f='+f).then(r=>r.text()).then(d=>{if(d=="OK"){document.getElementById("band-display").innerText=b;document.getElementById("freq-display").innerText=f;}});}function abrirMapa(){if(lastLat&&lastLat!=="Buscando...")window.open(`http://googleusercontent.com/maps.google.com/maps?q=${lastLat},${lastLon}`,'_blank');else alert("Erro: GPS sem sinal valido.");}</script></body></html>
)rawliteral";

String descriptografarDados(String msg) {
  msg.toCharArray(ciphertext, 512);
  aesLib.decrypt64(ciphertext, String(ciphertext).length(), (byte*)cleartext, aes_key, sizeof(aes_key), aes_iv);
  return String(cleartext);
}

void setup() {
  Serial.begin(115200);
  SerialArduino.begin(9600, SERIAL_8N1, 16, 17); 
  
  WiFi.softAP("Hefestos-Network", "xdneo123");
  shellServer.begin(); 
  
  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  LoRa.begin(915E6); 
  LoRa.setSpreadingFactor(10); 
  LoRa.setSignalBandwidth(125E3);

  Wire.begin(21, 22);
  radioRX.setup(RX_RST, 1); 
  radioRX.setFM(8400, 10800, currentFreq*100, 10); 
  radioRX.setVolume(50);

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){ 
    request->send_P(200, "text/html", index_html); 
  });
  
  server.on("/dados", HTTP_GET, [](AsyncWebServerRequest *request){
    DynamicJsonDocument doc(1024); String jsonOutput;
    doc["mensagem"] = mensagemAlvo; 
    doc["rssi"] = rssiLoRa; 
    doc["log"] = logWireshark;
    serializeJson(doc, jsonOutput); 
    request->send(200, "application/json", jsonOutput);
  });
  
  server.on("/sintonizar", HTTP_GET, [](AsyncWebServerRequest *request){
    if (request->hasParam("b") && request->hasParam("f")) {
      String b = request->getParam("b")->value(); 
      float f = request->getParam("f")->value().toFloat();
      currentBand = b; currentFreq = f; // Sincroniza estado pro CLI
      
      if (b=="FM") radioRX.setFM(8400, 10800, f*100, 10);
      else if (b=="AM") radioRX.setAM(520, 1710, f, 10);
      else if (b=="SW") radioRX.setAM(2300, 30000, f*1000, 5); 
    }
    request->send(200, "text/plain", "OK");
  });
  
  server.begin();
}

void loop() {
  // === GESTAO DO KERNEL HEFESTOS (TELNET/CLI) ===
  if (shellServer.hasClient()) {
    if (!shellClient || !shellClient.connected()) {
      if (shellClient) shellClient.stop();
      shellClient = shellServer.available();
      
      shellClient.println("\r\n\033[1;32m"); 
      shellClient.println("    __  __     ____          __           ");
      shellClient.println("   / / / /__  / __/__  _____/ /_____  _____");
      shellClient.println("  / /_/ / _ \\/ /_/ _ \\/ ___/ __/ __ \\/ ___/");
      shellClient.println(" / __  /  __/ __/  __(__  ) /_/ /_/ (__  ) ");
      shellClient.println("/_/ /_/\\___/_/  \\___/____/\\__/\\____/____/  ");
      shellClient.println("\033[0m"); 
      shellClient.println("=============================================");
      shellClient.println(" PROJETO HEFESTOS SIGINT - KERNEL v1.5.0");
      shellClient.println(" Engenharia Base: xd-neo");
      shellClient.println("=============================================");
      shellClient.println("Acesso TCP restrito operante.");
      shellClient.println("Digite 'help' para listar os comandos do sistema.\r\n");
      shellClient.print("hefestos@base:~# ");
    } else {
      shellServer.available().stop(); 
    }
  }

  // === ROTEAMENTO DE COMANDOS (CLI ROUTER) ===
  if (shellClient && shellClient.connected() && shellClient.available()) {
    String cmd = shellClient.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) {
      
      if (cmd == "help") {
        shellClient.println("\r\n[ CAPACIDADES DO KERNEL HEFESTOS ]");
        shellClient.println("-- TELEMETRIA E RASTREAMENTO --");
        shellClient.println("  target   : Exibe as ultimas coordenadas decodificadas da chave (AES-128)");
        shellClient.println("  map      : Extrai coordenadas e gera um link satelital de rastreamento");
        shellClient.println("");
        shellClient.println("-- INTELIGENCIA DE SINAIS (SIGINT) --");
        shellClient.println("  sniff    : Exibe o ultimo pacote RAW interceptado (Modo Wireshark RF)");
        shellClient.println("  history  : Despeja o buffer da memoria RAM com as ultimas interceptacoes");
        shellClient.println("");
        shellClient.println("-- GUERRA ELETRONICA (EW) E AUDIO --");
        shellClient.println("  status   : Relatorio de hardware (Modulos ativos, AES e RSSI atual)");
        shellClient.println("  tune     : Sintoniza o radio. Sintaxe: 'tune <BANDA> <FREQ>' (Ex: tune FM 100.1)");
        shellClient.println("");
        shellClient.println("-- SISTEMA --");
        shellClient.println("  clear    : Limpa a saida visual do terminal");
        shellClient.println("  exit     : Encerra a conexao TCP/Telnet atual\r\n");
      } 
      else if (cmd == "status") {
        shellClient.println("\r\n[ DIAGNOSTICO DE HARDWARE ]");
        shellClient.println("- Cripto AES-128 : [ ONLINE ]");
        shellClient.println("- Rastreio LoRa  : [ ONLINE ] (915 MHz | " + String(rssiLoRa) + " dBm)");
        shellClient.println("- Modulo Escuta  : [ ONLINE ] (Sintonizado em: " + currentBand + " " + String(currentFreq) + ")\r\n");
      }
      else if (cmd == "target") {
        shellClient.println("\r\n[ PAYLOAD DO ALVO SEGURO ]");
        shellClient.println("Conteudo validado: " + mensagemAlvo + "\r\n");
      }
      else if (cmd == "map") {
        if(mensagemAlvo.indexOf("Lat:") > 0 && mensagemAlvo.indexOf("Buscando") == -1) {
          int latIndex = mensagemAlvo.indexOf("Lat:") + 4;
          int lonIndex = mensagemAlvo.indexOf("Lon:") + 4;
          int barIndex = mensagemAlvo.indexOf("|", latIndex);
          String lat = mensagemAlvo.substring(latIndex, barIndex);
          String lon = mensagemAlvo.substring(lonIndex);
          shellClient.println("\r\n[ RASTREAMENTO SATELITAL ]");
          shellClient.println("Link gerado: http://maps.google.com/maps?q=" + lat + "," + lon + "\r\n");
        } else {
          shellClient.println("\r\n[ ERRO ] Coordenadas GPS invalidas ou satelites nao sincronizados.\r\n");
        }
      }
      else if (cmd == "sniff") {
        shellClient.println("\r\n[ INTERCEPTACAO DE DADOS BRUTOS ]");
        shellClient.println("Ultimo trafego isolado: " + ultimoSniff + "\r\n");
      }
      else if (cmd == "history") {
        shellClient.println("\r\n[ BUFFER DE REDE RF ]");
        if(logTerminal == "") shellClient.println("Aguardando capturas no espectro...");
        else shellClient.println(logTerminal);
        shellClient.println("");
      }
      else if (cmd.startsWith("tune ")) {
        int firstSpace = cmd.indexOf(' ');
        int secondSpace = cmd.indexOf(' ', firstSpace + 1);
        if (secondSpace > 0) {
          String b = cmd.substring(firstSpace + 1, secondSpace);
          float f = cmd.substring(secondSpace + 1).toFloat();
          b.toUpperCase();
          
          if (b == "FM") { radioRX.setFM(8400, 10800, f*100, 10); currentBand = "FM"; currentFreq = f; shellClient.println("\r\n[!] Comando executado: Frequencia alterada para FM " + String(f) + " MHz\r\n"); }
          else if (b == "AM") { radioRX.setAM(520, 1710, f, 10); currentBand = "AM"; currentFreq = f; shellClient.println("\r\n[!] Comando executado: Frequencia alterada para AM " + String(f) + " kHz\r\n");}
          else if (b == "SW") { radioRX.setAM(2300, 30000, f*1000, 5); currentBand = "SW"; currentFreq = f; shellClient.println("\r\n[!] Comando executado: Frequencia alterada para SW " + String(f) + " MHz\r\n");}
          else { shellClient.println("\r\n[ ERRO ] Banda invalida. Utilize comandos como 'tune FM 100.1'.\r\n"); }
        } else {
           shellClient.println("\r\n[ ERRO ] Sintaxe incorreta. Utilize: tune <BANDA> <FREQUENCIA>\r\n");
        }
      }
      else if (cmd == "clear") {
        shellClient.print("\033[2J\033[H"); 
      }
      else if (cmd == "exit") { 
        shellClient.println("Sessao encerrada. Cortando link TCP..."); 
        shellClient.stop(); 
      }
      else {
        shellClient.println("-bash: " + cmd + ": comando nao encontrado. Digite 'help'.");
      }
      
      if (shellClient.connected()) shellClient.print("hefestos@base:~# ");
    }
  }

  // === MOTOR CORE: LORA (RF INTERCEPT) ===
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    String pacoteRAW = "";
    while (LoRa.available()) pacoteRAW += (char)LoRa.read();
    rssiLoRa = LoRa.packetRssi();
    ultimoSniff = pacoteRAW;

    String possivelAlvo = descriptografarDados(pacoteRAW);

    if (possivelAlvo.startsWith("ID:ALVO_01")) {
      mensagemAlvo = possivelAlvo;
      SerialArduino.println("ALVO|" + mensagemAlvo); 
    } else {
      logWireshark += "[RX " + String(rssiLoRa) + "dBm] RAW: <span class='alert'>" + pacoteRAW + "</span><br>";
      if(logWireshark.length() > 1000) logWireshark = logWireshark.substring(logWireshark.length() - 800); 
      
      logTerminal += "[SINAL " + String(rssiLoRa) + "dBm] -> " + pacoteRAW + "\r\n";
      if(logTerminal.length() > 1000) logTerminal = logTerminal.substring(logTerminal.length() - 800);

      SerialArduino.println("SNIFFER|" + pacoteRAW); 
    }
  }
}