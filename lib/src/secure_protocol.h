// secure_protocol.h - Anti-replay e integridade de sequencia - v5.0.0
//
// CORRECAO CRITICA (v5):
//   A v4.x aceitava QUALQUER contador antigo como "RESYNC" quando ele nao
//   estava dentro do PacketHistory de 256 entradas. Um atacante com uma
//   captura de SDR podia reinyectar um track valido antigo (posicao
//   obsoleta/falsificada) e o sistema o aceitava como novo. Comprovado por
//   simulacao do autômato da v4.
//
//   v5: a regra e' estrita e sem caminho de aceitacao por resync.
//     - contador <= maior_contador  -> REPLAY (sempre rejeitado)
//     - contador >  maior_contador + WINDOW -> REJECT_FAR
//     - epoch anterior -> REJECT_STALE
//   Janela deslizante de bits apenas para CONTAR quantos pacotes foram
//   perdidos (diagnostico), nunca para aceitar.
//
// O epoch (16 bits) muda a cada boot do emissor e e' autenticado pelo
// GCM (esta no AAD). Isso resolve o caso "emissor reiniciou e o contador
// voltou": o receptor aceita o novo epoch e zera a janela daquele par
// (epoch, contador).
#ifndef HEF_SECURE_PROTOCOL_H
#define HEF_SECURE_PROTOCOL_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"

enum LinkRxResult {
    LINK_RX_ACCEPT = 0,
    LINK_RX_REPLAY,          // contador ja visto -> rejeitar
    LINK_RX_STALE_EPOCH,     // epoch anterior -> rejeitar
    LINK_RX_FAR,             // salto grande demais -> rejeitar
    LINK_RX_UNKNOWN_PEER     // node_id nao enrolled -> rejeitar
};

class RxSequence {
private:
    uint16_t epoch_;
    uint32_t highest_;
    uint32_t window_[HEF_COUNTER_WINDOW / 32];
    uint32_t gaps_;
    bool     active_;

public:
    RxSequence() : epoch_(0), highest_(0), gaps_(0), active_(false) {
        memset(window_, 0, sizeof(window_));
    }

    void reset() {
        epoch_ = 0; highest_ = 0; gaps_ = 0; active_ = false;
        memset(window_, 0, sizeof(window_));
    }

    // Compara epochs de 16 bits com aritmetica de numero de serie.
    static bool epochIsNewer(uint16_t candidate, uint16_t current) {
        return (int16_t)(candidate - current) > 0;
    }

    // Avalia um frame recebido. `outLost` recebe a quantidade estimada de
    // pacotes perdidos (diagnostico).
    LinkRxResult accept(uint16_t epoch, uint32_t counter, uint32_t* outLost) {
        if (outLost) *outLost = 0;

        if (!active_) {
            epoch_ = epoch; highest_ = counter; gaps_ = 0;
            memset(window_, 0, sizeof(window_));
            setBit(counter);
            active_ = true;
            return LINK_RX_ACCEPT;
        }

        if (epoch != epoch_) {
            if (epochIsNewer(epoch, epoch_)) {
                // Nova sessao do emissor: reinicia a janela.
                epoch_ = epoch; highest_ = counter; gaps_ = 0;
                memset(window_, 0, sizeof(window_));
                setBit(counter);
                return LINK_RX_ACCEPT;
            }
            // Epoch antigo (possivel replay de sessao anterior).
            return LINK_RX_STALE_EPOCH;
        }

        if (counter <= highest_) {
            // JA FOI VISTO -> replay. Sem excecao, sem "resync".
            return LINK_RX_REPLAY;
        }

        uint32_t delta = counter - highest_;
        if (delta > HEF_COUNTER_WINDOW) {
            return LINK_RX_FAR;
        }

        if (delta > 1) {
            // salto dentro da janela: conta pacotes perdidos
            uint32_t lost = 0;
            for (uint32_t c = highest_ + 1; c < counter; c++) {
                if (!getBit(c)) lost++;
            }
            gaps_ += lost;
            if (outLost) *outLost = lost;
        }
        highest_ = counter;
        setBit(counter);
        return LINK_RX_ACCEPT;
    }

    uint32_t highest() const { return highest_; }
    uint16_t epoch()   const { return epoch_; }
    uint32_t gaps()    const { return gaps_; }

private:
    void setBit(uint32_t counter) {
        uint32_t idx = counter % HEF_COUNTER_WINDOW;
        window_[idx / 32] |= (1UL << (idx % 32));
    }
    bool getBit(uint32_t counter) const {
        uint32_t idx = counter % HEF_COUNTER_WINDOW;
        return (window_[idx / 32] & (1UL << (idx % 32))) != 0;
    }
};

// ---------------------------------------------------------------
// Emissor: mantem epoch + contador e persiste o par.
// ---------------------------------------------------------------
class TxSequence {
private:
    uint16_t epoch_;
    uint32_t counter_;

public:
    TxSequence() : epoch_(0), counter_(0) {}

    void begin(uint16_t epoch, uint32_t counter) {
        epoch_ = epoch;
        counter_ = counter;
    }

    // Novo epoch (boot do emissor). O epoch precisa ser sempre novo em
    // relacao ao receptor; deriva-se de entropia do hardware.
    void rollEpoch(uint16_t newEpoch) {
        epoch_ = newEpoch;
        counter_ = 0;
    }

    uint16_t epoch()   const { return epoch_; }
    uint32_t counter() const { return counter_; }

    uint32_t next() { return ++counter_; }

    void setCounter(uint32_t c) { counter_ = c; }
};

#endif // HEF_SECURE_PROTOCOL_H
