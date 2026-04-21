// rate_limiter.h - Command rate limiting for CLI and API endpoints
// Protege contra DoS e abusos
// CORRIGIDO v3.0: Suporta IP real do cliente

#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stdint.h>
#include <string.h>

#define MAX_CLIENTS 8            // Aumentado de 5 para 8
#define MAX_COMMANDS_PER_MINUTE 30
#define COMMAND_COOLDOWN_MS 100
#define IP_STRING_SIZE 16      // Tamanho max para string IP

struct ClientQuota {
  char ip_string[IP_STRING_SIZE];  // IP real como string (IPv4)
  uint32_t ip_hash;
  uint32_t command_count;
  unsigned long last_reset;
  unsigned long last_command;
  bool active;
};

class RateLimiter {
private:
  ClientQuota clients[MAX_CLIENTS];
  const unsigned long RESET_INTERVAL = 60000; // 1 minuto

public:
  RateLimiter() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
      clients[i].active = false;
      memset(clients[i].ip_string, 0, IP_STRING_SIZE);
    }
  }

  // Registra cliente novo ou atualiza existente - VERSÃO CORRIGIDA v3.0
  // Aceita string IP real ou hash
  uint32_t hashIP(const char* ip) {
    if (!ip) return 0;
    
    uint32_t hash = 5381;
    for (int i = 0; ip[i] != '\0' && i < IP_STRING_SIZE - 1; i++) {
      hash = ((hash << 5) + hash) + ip[i];
    }
    return hash;
  }

  // NOVO v3.0: Versão que aceita string IP diretamente
  bool allowCommand(const char* client_ip) {
    if (!client_ip) return false;
    return allowCommandByHash(hashIP(client_ip), client_ip);
  }

  // Overload com IP string - VERSÃO CORRIGIDA v3.0
  bool allowCommandByHash(uint32_t client_hash, const char* ip_string = NULL) {
    unsigned long now = millis();
    int slot = -1;
    
    // Procura cliente existente
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (clients[i].active && clients[i].ip_hash == client_hash) {
        slot = i;
        break;
      }
    }

    // Se cliente não existe, tenta registrar novo
    if (slot == -1) {
      for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
          slot = i;
          clients[i].ip_hash = client_hash;
          clients[i].active = true;
          clients[i].command_count = 0;
          clients[i].last_reset = now;
          clients[i].last_command = now;
          break;
        }
      }
    }

    if (slot == -1) {
      return false; // Sem slots disponíveis
    }

    ClientQuota* c = &clients[slot];

    // Reset contador se passou intervalo
    if (now - c->last_reset > RESET_INTERVAL) {
      c->command_count = 0;
      c->last_reset = now;
    }

    // Verifica cooldown entre comandos
    if (now - c->last_command < COMMAND_COOLDOWN_MS) {
      return false;
    }

    // Verifica limite de comandos
    if (c->command_count >= MAX_COMMANDS_PER_MINUTE) {
      return false;
    }

    c->command_count++;
    c->last_command = now;
    return true;
  }

  // Remove cliente (para libertar slot)
  void removeClient(uint32_t client_hash) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (clients[i].active && clients[i].ip_hash == client_hash) {
        memset(clients[i].ip_string, 0, IP_STRING_SIZE);
        clients[i].active = false;
        break;
      }
    }
  }

  // Limpa clientes inativos
  void cleanup() {
    unsigned long now = millis();
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (clients[i].active && now - clients[i].last_command > 300000) { // 5 minutos
        clients[i].active = false;
      }
    }
  }
};

#endif // RATE_LIMITER_H
