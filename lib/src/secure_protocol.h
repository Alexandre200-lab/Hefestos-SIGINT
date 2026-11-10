// secure_protocol.h - Anti-replay e integridade de sequencia - v5.1.0
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
//     - contador >  maior_contador + MAX_GAP -> REJECT_FAR
//   Janela deslizante de bits apenas para CONTAR quantos pacotes foram
//   perdidos (diagnostico), nunca para aceitar.
//
// O epoch (16 bits) muda a cada boot do emissor e e' autenticado pelo
// GCM (esta no AAD). Isso resolve o caso "emissor reiniciou e o contador
// voltou": o receptor aceita o novo epoch e zera a janela daquele par
// (epoch, contador).
//
// v5.1.0 - PERSISTENCIA DO ESTADO (fecha a vuln. de replay pos-reboot):
//   Antes, o estado vivia so em RAM. Um frame capturado por SDR e'
//   replayado DEPOIS que o receptor reinicia: a tabela de pares volta
//   vazia, o par nao tem epoch/contador e o frame capturado - que tem uma
//   tag GCM legitimately valida - e' aceito como se fosse uma sessao nova.
//
//   Agora o par pode ser HIDRATADO no boot a partir de um estado
//   persistido (epoch + high-water). Com isso:
//     - epoch mais antigo que o persistido -> STALE_EPOCH (rejeitado)
//     - contador <= high-water persistido  -> REPLAY (rejeitado)
//   A hidratacao e' feita por hydrate()/exportState(), que nao aceitam
//   frames: apenas movem o estado Known -> Known.
//
//   Cuidado de projeto: hidratar o estado passa a exigir que o salto do
//   contador dentro da mesma epoch seja TRATADO. Antes, um receptor que
//   ficava horas sem receber frames rejeitava o frame seguinte como
//   LINK_RX_FAR e o enlace ficava morto ate o receptor reiniciar. Por isso
//   existe o segundo limite HEF_COUNTER_MAX_GAP: saltos maiores que a
//   janela de bits (que serve so para contar perdas) reancoram o
//   high-water; saltos maiores que MAX_GAP sao rejeitados (falha fechada).
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
    uint32_t resyncs_;
    bool     active_;

public:
    RxSequence() : epoch_(0), highest_(0), gaps_(0), resyncs_(0), active_(false) {
        memset(window_, 0, sizeof(window_));
    }

    void reset() {
        epoch_ = 0; highest_ = 0; gaps_ = 0; resyncs_ = 0; active_ = false;
        memset(window_, 0, sizeof(window_));
    }

    // Hidrata o estado a partir de um valor PERSISTIDO (boot do receptor).
    // Nao aceita frames: apenas reposiciona o par em "estado conhecido".
    // O high-water e' o ultimo contador ACEITO; o contador persistido e'
    // ele proprio, de modo que o reenvio do ultimo frame (retry do Node1
    // quando o ACK se perde) seja classificado como REPLAY - o Node2
    // reenvia o ACK sem reprocessar o track.
    void hydrate(uint16_t epoch, uint32_t counter) {
        epoch_   = epoch;
        highest_ = counter;
        gaps_    = 0;
        memset(window_, 0, sizeof(window_));
        setBit(counter);
        active_  = true;
    }

    // Exporta o estado para persistencia.
    void exportState(uint16_t* epoch, uint32_t* counter) const {
        if (epoch)   *epoch   = epoch_;
        if (counter) *counter = highest_;
    }

    bool isActive() const { return active_; }

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

        if (delta > HEF_COUNTER_MAX_GAP) {
            // Salto absurdo: falha fechada. So um epoch novo (emissor
            // reiniciado) ressincroniza o enlace.
            return LINK_RX_FAR;
        }

        if (delta > HEF_COUNTER_WINDOW) {
            // Salto maior que a janela de bits. O frame e' legitimo (tag
            // GCM valida => o contador foi really emitido pelo par), mas
            // o bitmap nao cobre o intervalo: reancora o high-water e
            // contabiliza a perda de forma aproximada.
            uint32_t lost = delta - 1;
            gaps_ += lost;
            if (outLost) *outLost = lost;
            highest_ = counter;
            memset(window_, 0, sizeof(window_));
            setBit(counter);
            resyncs_++;
            return LINK_RX_ACCEPT;
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
    uint32_t resyncs() const { return resyncs_; }

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
