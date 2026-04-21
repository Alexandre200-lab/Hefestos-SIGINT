# HEFESTOS SIGINT v3.0 - Manual de Operação

## Acesso ao Sistema

### Dashboard Web
```
http://192.168.4.1
```

### CLI Telnet
```
telnet 192.168.4.1 23
user: hefestos    (v3.0 - novo default)
pass: [senha da EEPROM]
```

---

## Comandos CLI v3.0

### TELEMETRIA
```
target  - Exibe coordenadas do alvo
map     - Gera URL Google Maps
```

### STATUS
```
status  - Status hardware
```

### SISTEMA
```
help    - Lista comandos
exit    - Desconecta
```

---

## Dashboard v3.0

### Novos Counters
- **GCM OK**: Pacotes descriptografados com sucesso
- **GCM FAIL**: Falhas de descriptografia
- **REPLAY**: Replay attacks detectados

### JSON Endpoint
```json
{
  "mensagem": "ALVO_01|...",
  "rssi": -75,
  "rx_count": 1234,
  "gcm_ok": 1200,
  "gcm_fail": 34,
  "replay_count": 5
}
```

---

## Troubleshooting v3.0

### "REPLAY DETECTADO"
- Contador pacotes foi reutilizado
- Possível replay attack

### "GCM FAIL"
- Chave AES diferente entre Node1 e Node2
- Dados corrompidos

### Credenciais Padrão v3.0
```
User: hefestos
Pass: HefestosTactical@2024
```

---

## Versão

- **v3.0.0** - 2026-04-20