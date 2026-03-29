# Projeto HEFESTOS: Estacao Tatica SIGINT Multi-Banda
**Desenvolvedor: xd-neo**

Hefestos e um sistema avancado de Inteligencia de Sinais (SIGINT), guerra eletronica e telemetria composto por uma arquitetura Master-Slave distribuida. Ele realiza rastreamento GPS criptografado (AES-128) via rede LoRa (Sub-GHz), transmissao de escuta ambiente via FM analogico, interceptacao de radio frequencias (AM/FM/SW) e retencao de dados forenses em Cartao SD.

## Arquitetura do Sistema
O projeto opera com 3 nos fisicos independentes:
1. **Node 1 (Transmissor/Alvo - ESP32):** Dispositivo de campo. Captura coordenadas GPS, aplica criptografia AES-128 e transmite via LoRa (915MHz). Atua como um transmissor FM local (Si4713) captando audio ambiente.
2. **Node 2 (Base Hefestos - ESP32):** Servidor central de comando. Intercepta pacotes LoRa, executa a rotina de descriptografia e hospeda dois servicos: um Painel Web Assincrono (HTTP) e um Servidor de Terminal Linux (Telnet/CLI) com controle ativo de radiofrequencia (Si4732).
3. **Node 3 (Caixa Preta - Arduino Uno/Nano):** Co-Processador de log. Recebe dados processados pelo Node 2 via UART, gera alertas fisicos (LED/Buzzer) e grava o historico da operacao em um arquivo CSV no cartao MicroSD.

## Pinagem de Hardware (Hardware Mapping)

**Node 1 (Transmissor ESP32):**
* LoRa SX1276: SCK(18), MISO(19), MOSI(23), CS(5), RST(14), DIO0(26).
* GPS NEO-6M: TX no RX2(16), RX no TX2(17).
* Transmissor FM Si4713: SDA(21), SCL(22), RST(32).

**Node 2 (Base ESP32):**
* LoRa SX1276: SCK(18), MISO(19), MOSI(23), CS(5), RST(14), DIO0(26).
* Radio Scanner Si4732: SDA(21), SCL(22), RST(12).
* Link Serial com Arduino: Pino TX2(17) do ESP32 conecta no Pino RX(2) do Arduino. (GND comum).

**Node 3 (Caixa Preta Arduino):**
* MicroSD Module (SPI): MISO(12), MOSI(11), SCK(13), CS(4).
* Link Serial com ESP32: O Pino RX(2) recebe os dados do ESP32.
* Alarmes Fisicos: LED Verde(7), LED Vermelho(8), Buzzer(9).

## Instrucoes de Operacao
1. Energize os modulos. O Arduino (Node 3) e quem se conecta fisicamente ao PC.
2. Acesse a rede Wi-Fi local gerada pelo Kernel: `Hefestos-Network` (Senha: `*********`).
3. Painel Grafico: Acesse `http://192.168.4.1` em seu navegador.
4. Terminal Tatico: Em seu Linux, execute `telnet 192.168.4.1`. Digite `help` para listar os modulos de operacao SIGINT.
