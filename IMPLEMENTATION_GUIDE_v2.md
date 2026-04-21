# HEFESTOS SIGINT v3.0 - Guia de Implementação

## Sumário v3.0

### Novas Bibliotecas de Segurança
- `crypto_gcm.h` - AES-GCM autenticado
- `secure_protocol.h` - Anti-Replay protocol
- `totp_auth.h` - 2FA TOTP
- `secure_storage.h` - Encrypt at rest

### Correções Críticas
| # | Problema | Solução |
|---|----------|---------|
| 1 | HMAC sobre ciphertext | AES-GCM |
| 2 | Replay attacks | Nonce + Counter |
| 3 | Rate limiter hash fixo | IP real |
| 4 | Username hardcoded | EEPROM config |

---

## Segurança

### ConfigManager (config.h v3.0)

```
EEPROM Layout (512 bytes):
├── 0x00-0x01:  Magic 0x4847 (v3.0)
├── 0x02:        Version 3
├── 0x04-0x13:  AES Key (16 bytes)
├── 0x14-0x23:  AES IV (16 bytes)
├── 0x24-0x43:  WiFi Pass (32 bytes)
├── 0x44-0x63:  CLI Pass (32 bytes)
├── 0x64-0x73:  CLI User (16 bytes)  ← NOVO v3.0
├── 0x84:        Flags
```

### AES-GCM (crypto_gcm.h)

```cpp
// Node1 TX
AESGCM aesgcm;
uint32_t counter = secProto.getNextCounter();
int len = aesgcm.encrypt(payload, len, output, counter);
LoRa.write(output, len);

// Node2 RX
int decLen = aesgcm.decrypt(buffer, len, decrypted, &counter);
if (decLen > 0) {
  if (!secProto.isValidCounter(counter)) {
    // REPLAY!
  }
}
```

### Rate Limiter (rate_limiter.h v3.0)

```cpp
// CORRIGIDO - IP real
RateLimiter rateLimiter;

// Aceita string IP diretamente
if (rateLimiter.allowCommand("192.168.4.2")) {
  // Execute command
}
```

---

## Autenticação 2FA (totp_auth.h)

```cpp
TOTPAuth totp;
totp.setSecret("JBSWY3DPEHPK3PXP");  // Base32 secret

// Verificar código
if (totp.verify("123456")) {
  // OK
}
```

---

## Deployment Checklist

### Compilação
```bash
# Node1
arduino-cli compile -b esp32:esp32:esp32 src/Node1_Transmissor_Alvo/

# Node2
arduino-cli compile -b esp32:esp32:esp32 src/Node2_Base_Hefestos/

# Node3
arduino-cli compile -b arduino:avr:uno src/Node3_Caixa_Preta_Arduino/
```

---

## Troubleshooting

### "REPLAY DETECTADO"
- Pacote duplicado ou replay attack
- Contador reiniciado em ambos os nós

### "Rate limit exceeded"
- Verificar se está usando IP correto
- Novo: rate limiter usa IP real

### "GCM FAIL"
- Verificar se chaves AES são idênticas
- Verificar sincronização de contadores

---

## Versão

- **v3.0.0** - 2026-04-20
- **Status**: Production-ready