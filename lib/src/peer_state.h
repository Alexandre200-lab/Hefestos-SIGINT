// peer_state.h - Estado anti-replay persistido por par - v5.1.0
//
// OBJETIVO
//   Fechar a vulnerabilidade de replay pos-reboot do receptor.
//
//   O estado anti-replay (epoch + high-water do contador) vivia apenas em
//   RAM. Ate a v5.0.0, um frame capturado por SDR - com tag GCM
//   autentica e portanto criptograficamente valido - era ACEITO como
//   frame novo depois que o receptor reiniciava, porque a tabela de pares
//   voltava vazia e o par nao tinha epoch/contador known.
//
//   Este modulo concentration:
//     - o formato serializado do estado por par (independente de endian);
//     - a guarda de replay que sabe dizer se o estado precisa ser
//       persistido com urgencia (mudanca de epoch) ou pode esperar.
//
//   O modulo e' C++ puro, sem dependencia de Arduino/ESP, para poder ser
//   testado no HOST (tests/anti_replay_persistence.cpp).
//
// FORMATO SERIALIZADO
//   Registro fixo de 8 bytes por par, little-endian, sem padding:
//     +0..1  nodeId  u16 LE
//     +2..3  epoch   u16 LE
//     +4..7  counter u32 LE
//   O conteudo completo e' gravado dentro do vault cifrado (TLV
//   HEF_TLV_PEER_STATE), portanto o estado anti-replay fica protegido
//   pela mesma chave AES-256-GCM derivada do MAC do efuse.
#ifndef HEF_PEER_STATE_H
#define HEF_PEER_STATE_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"
#include "secure_protocol.h"

#define HEF_PEER_STATE_REC_LEN 8

struct HefPeerState {
    uint16_t nodeId;
    uint16_t epoch;
    uint32_t counter;
};

// ---------------------------------------------------------------------
// Armazenamento do estado por par (espelho em RAM do que esta no vault)
// ---------------------------------------------------------------------
class PeerStateStore {
private:
    HefPeerState items_[HEF_MAX_ENROLLMENTS];
    uint8_t      count_;

public:
    PeerStateStore() : count_(0) {
        memset(items_, 0, sizeof(items_));
    }

    void clear() {
        memset(items_, 0, sizeof(items_));
        count_ = 0;
    }

    uint8_t count() const { return count_; }

    bool get(uint16_t nodeId, uint16_t* epoch, uint32_t* counter) const {
        for (uint8_t i = 0; i < count_; i++) {
            if (items_[i].nodeId == nodeId) {
                if (epoch)   *epoch   = items_[i].epoch;
                if (counter) *counter = items_[i].counter;
                return true;
            }
        }
        return false;
    }

    bool getByIndex(uint8_t idx, uint16_t* nodeId, uint16_t* epoch,
                    uint32_t* counter) const {
        if (idx >= count_) return false;
        if (nodeId) *nodeId = items_[idx].nodeId;
        if (epoch)  *epoch  = items_[idx].epoch;
        if (counter)*counter= items_[idx].counter;
        return true;
    }

    // Insere ou atualiza o estado de um par. Retorna false apenas se o
    // limite de pares foi atingido (nunca descarta um estado existente).
    bool put(uint16_t nodeId, uint16_t epoch, uint32_t counter) {
        if (nodeId == 0) return false;
        for (uint8_t i = 0; i < count_; i++) {
            if (items_[i].nodeId == nodeId) {
                items_[i].epoch   = epoch;
                items_[i].counter = counter;
                return true;
            }
        }
        if (count_ >= HEF_MAX_ENROLLMENTS) return false;
        items_[count_].nodeId = nodeId;
        items_[count_].epoch  = epoch;
        items_[count_].counter= counter;
        count_++;
        return true;
    }

    bool remove(uint16_t nodeId) {
        for (uint8_t i = 0; i < count_; i++) {
            if (items_[i].nodeId == nodeId) {
                for (uint8_t k = i; k + 1 < count_; k++) {
                    items_[k] = items_[k + 1];
                }
                count_--;
                memset(&items_[count_], 0, sizeof(items_[count_]));
                return true;
            }
        }
        return false;
    }

    size_t serializedSize() const {
        return (size_t)count_ * HEF_PEER_STATE_REC_LEN;
    }

    // Serializa em little-endian, independente da arquitetura do host.
    size_t serialize(uint8_t* out, size_t cap) const {
        if (!out) return 0;
        size_t need = serializedSize();
        if (cap < need) return 0;
        for (uint8_t i = 0; i < count_; i++) {
            uint8_t* p = out + (size_t)i * HEF_PEER_STATE_REC_LEN;
            p[0] = (uint8_t)(items_[i].nodeId & 0xFF);
            p[1] = (uint8_t)(items_[i].nodeId >> 8);
            p[2] = (uint8_t)(items_[i].epoch & 0xFF);
            p[3] = (uint8_t)(items_[i].epoch >> 8);
            p[4] = (uint8_t)(items_[i].counter & 0xFF);
            p[5] = (uint8_t)((items_[i].counter >> 8) & 0xFF);
            p[6] = (uint8_t)((items_[i].counter >> 16) & 0xFF);
            p[7] = (uint8_t)((items_[i].counter >> 24) & 0xFF);
        }
        return need;
    }

    // Carrega a partir do blob serializado. Entradas corrompidas
    // (nodeId == 0) sao descartadas; um blob truncado e' aceito ate o
    // ultimo registro completo.
    bool deserialize(const uint8_t* in, size_t len) {
        clear();
        if (!in || len == 0) return false;
        size_t n = len / HEF_PEER_STATE_REC_LEN;
        if (n > HEF_MAX_ENROLLMENTS) n = HEF_MAX_ENROLLMENTS;
        for (size_t i = 0; i < n; i++) {
            const uint8_t* p = in + i * HEF_PEER_STATE_REC_LEN;
            uint16_t nodeId = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
            uint16_t epoch  = (uint16_t)(p[2] | ((uint16_t)p[3] << 8));
            uint32_t counter= (uint32_t)p[4] | ((uint32_t)p[5] << 8) |
                              ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
            if (nodeId == 0) continue;      // registro invalido
            if (!put(nodeId, epoch, counter)) break;
        }
        return true;
    }
};

// ---------------------------------------------------------------------
// Guarda anti-replay de um par: estado em RAM + indicacao de persistencia
// ---------------------------------------------------------------------
//
// Uso tipico (Node2):
//   PeerReplayGuard rx;
//   rx.hydrate(epochPersistido, contadorPersistido);   // no boot
//   ...
//   LinkRxResult r = rx.accept(epoch, contador, &lost);
//   if (r == LINK_RX_ACCEPT) {
//       vault.putPeerState(nodeId, rx.epoch(), rx.highest());  // RAM
//       if (rx.needsImmediatePersist()) vault.save();          // epoch novo
//   }
class PeerReplayGuard {
private:
    RxSequence seq_;
    bool dirty_;          // o estado avancou e ainda nao foi persistido
    bool sessionChanged_; // epoch mudou (ou primeiro contato): urgente

public:
    PeerReplayGuard() : dirty_(false), sessionChanged_(false) {}

    // Hidrata a partir de um estado persistido.
    void hydrate(uint16_t epoch, uint32_t counter) {
        seq_.hydrate(epoch, counter);
        dirty_ = false;
        sessionChanged_ = false;
    }

    LinkRxResult accept(uint16_t epoch, uint32_t counter, uint32_t* outLost) {
        bool wasActive    = seq_.isActive();
        uint16_t epochBefore = seq_.epoch();
        uint32_t resyncsBefore = seq_.resyncs();

        LinkRxResult r = seq_.accept(epoch, counter, outLost);

        if (r == LINK_RX_ACCEPT) {
            dirty_ = true;
            // Mudanca de sessao (epoch novo) ou primeiro contato: o estado
            // precisa estar no vault ANTES do proximo reinicio, senao um
            // frame capturado da sessao antiga volta a ser aceito.
            if (!wasActive || seq_.epoch() != epochBefore) {
                sessionChanged_ = true;
            }
            // Reancoragem por salto grande: tambem e' um evento de
            // seguranca relevante e deve ser persistido imediatamente.
            if (seq_.resyncs() != resyncsBefore) {
                sessionChanged_ = true;
            }
        }
        return r;
    }

    void exportState(uint16_t* epoch, uint32_t* counter) const {
        seq_.exportState(epoch, counter);
    }

    uint16_t epoch()   const { return seq_.epoch(); }
    uint32_t highest() const { return seq_.highest(); }
    uint32_t gaps()    const { return seq_.gaps(); }
    uint32_t resyncs() const { return seq_.resyncs(); }
    bool     isActive() const { return seq_.isActive(); }

    bool isDirty()             const { return dirty_; }
    bool needsImmediatePersist() const { return sessionChanged_; }

    // Chamado depois de uma gravacao bem-sucedida no vault.
    void clearPersistFlags() {
        dirty_ = false;
        sessionChanged_ = false;
    }

    void reset() {
        seq_.reset();
        dirty_ = false;
        sessionChanged_ = false;
    }
};

#endif // HEF_PEER_STATE_H
