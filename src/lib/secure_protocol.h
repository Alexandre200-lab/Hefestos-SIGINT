// secure_protocol.h - Secure Protocol com Nonce/Counter Anti-Replay
// Gerencia contadores para previnir replay attacks
// Integração com AES-GCM para segurança completa

#ifndef SECURE_PROTOCOL_H
#define SECURE_PROTOCOL_H

#include <stdint.h>
#include <string.h>

#define SECURE_PROTOCOL_MAX_PAYLOAD 256
#define SECURE_PROTOCOL_MAGIC 0xHEF3  // Magic para v3.0

// Estrutura do pacote seguro
// [MAGIC(2)] [COUNTER(4)] [PAYLOAD(N)] [HMAC(8)]
typedef struct {
    uint16_t magic;
    uint32_t counter;
    uint8_t payload[SECURE_PROTOCOL_MAX_PAYLOAD];
    uint16_t payload_len;
    uint8_t hmac[8];
} SecurePacketData;

class SecureProtocol {
private:
    uint32_t tx_counter;
    uint32_t rx_counter;
    uint32_t last_valid_counter;
    unsigned long last_counter_reset;
    const unsigned long COUNTER_WINDOW = 60000;  // 1 minuto para reuse

public:
    SecureProtocol() : tx_counter(0), rx_counter(0), last_valid_counter(0), last_counter_reset(0) {}

    // Inicializa counter - deve ser chamado nos 2 nós com mesmo seed!
    void begin(uint32_t seed = 0) {
        if (seed == 0) {
            seed = millis() ^ 0xDEADBEEF;
        }
        tx_counter = seed;
        rx_counter = seed;
        last_valid_counter = seed;
        last_counter_reset = millis();
    }

    // Próximo counter para TX
    uint32_t getNextCounter() {
        return ++tx_counter;
    }

    // Verifica se counter é válido (maior que último válido)
    bool isValidCounter(uint32_t counter) {
        // Reset periódico para previnir overflow
        if (millis() - last_counter_reset > COUNTER_WINDOW) {
            last_valid_counter = rx_counter - 1;
            last_counter_reset = millis();
        }

        return counter > last_valid_counter;
    }

    // Atualiza último counter válido
    void updateValidCounter(uint32_t counter) {
        if (counter > last_valid_counter) {
            last_valid_counter = counter;
        }
    }

    // Marca counter como usado (para RX)
    void markCounter(uint32_t counter) {
        if (counter > rx_counter) {
            rx_counter = counter;
        }
    }

    // getters
    uint32_t getTXCounter() { return tx_counter; }
    uint32_t getRXCounter() { return rx_counter; }
    uint32_t getLastValidCounter() { return last_valid_counter; }

    // Reseta contadores (para nova sessão)
    void reset() {
        tx_counter = 0;
        rx_counter = 0;
        last_valid_counter = 0;
    }

    // Sincroniza contadores entre nós
    void syncCounters(uint32_t remote_counter) {
        if (remote_counter > tx_counter) {
            tx_counter = remote_counter;
        }
    }
};

// Buffer circular para últimos pacotes (detecção de duplicatas)
class PacketHistory {
private:
    static const int HISTORY_SIZE = 32;
    uint32_t counters[HISTORY_SIZE];
    int head;
    int count;

public:
    PacketHistory() : head(0), count(0) {
        memset(counters, 0, sizeof(counters));
    }

    // Adiciona counter ao histórico
    void add(uint32_t counter) {
        counters[head] = counter;
        head = (head + 1) % HISTORY_SIZE;
        if (count < HISTORY_SIZE) count++;
    }

    // Verifica se counter já foi usado
    bool isDuplicate(uint32_t counter) {
        for (int i = 0; i < count; i++) {
            if (counters[i] == counter) {
                return true;
            }
        }
        return false;
    }

    // Limpa histórico
    void clear() {
        memset(counters, 0, sizeof(counters));
        head = 0;
        count = 0;
    }
};

#endif // SECURE_PROTOCOL_H