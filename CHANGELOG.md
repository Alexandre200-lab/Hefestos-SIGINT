# CHANGELOG - HEFESTOS SIGINT v3.0

## Data: 2026-04-20
## Status: Security Update Complete

---

## v3.0 - Security Critical Update

### Novas Bibliotecas Criadas

| Biblioteca | Linhas | Descrição |
|------------|--------|-----------|
| `crypto_gcm.h` | ~180 | AES-GCM autenticado |
| `secure_protocol.h` | ~120 | Nonce/Counter anti-replay |
| `totp_auth.h` | ~180 | 2FA TOTP RFC 6238 |
| `secure_storage.h` | ~130 | Encrypt at rest |

### Correções de Segurança

| # | Vulnerabilidade | Correção |
|---|----------------|----------|
| 1 | HMAC sobre ciphertext | AES-GCM (AEAD) |
| 2 | Replay attacks | SecureProtocol counter |
| 3 | Rate limiter hash fixo | IP real por cliente |
| 4 | Username "admin" hardcoded | EEPROM configurável |
| 5 | Sem 2FA real | TOTP disponível |
| 6 | EEPROM texto puro | SecureStorage disponível |

### Arquivos Modificados

| Arquivo | Mudanças |
|---------|----------|
| `config.h` | +CLI_USER, v3.0 magic |
| `rate_limiter.h` | +allowCommand(IP real) |
| `Node1.ino` | AES-GCM + SecureProtocol |
| `Node2.ino` | AES-GCM + anti-replay detection |
| `Node3.ino` | Mantido (Arduino) |

### Documentação Atualizada

- `README.md` → v3.0
- `IMPLEMENTATION_GUIDE_v2.md` → v3.0
- `OPERATION_MANUAL_v2.md` → v3.0

---

## v2.1 - Anterior

### Melhorias
- HMAC-SHA256 real via mbedtls
- Verificação HMAC em Node2
- Chaves AES únicas no boot
- GPS validation

---

## v2.0 - Refactoring

### Melhorias
- EEPROM Config Manager
- WiFi forte (22 chars)
- Autenticação Telnet 2FA
- Rate Limiting
- CRC16 UART
- SD Card Recovery

---

## Versão

- **Atual**: 3.0.0
- **Data**: 2026-04-20