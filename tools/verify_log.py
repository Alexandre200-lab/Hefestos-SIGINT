#!/usr/bin/env python3
"""
verify_log.py - Verificador OFFLINE da cadeia forense do Hefestos SIGINT

Verifica, sem o firmware e sem o cartao original, a integridade dos
arquivos de log do Node 3 (Caixa Preta):

  - HEFLOG.BIN / HEFLOGnnn.BIN  cadeia SHA-256 binaria (HLG5 legado e
                                HLG6 com continuidade entre rotacoes);
  - HEFCHK.BIN                  checkpoints (seq + cabeca da cadeia),
                                com CRC16 e distincao explicita entre
                                checkpoint ASSINADO e NAO assinado;
  - HEFLOG.MAN                  manifesto de rotacao (confere tamanho,
                                contagem, primeiro/ultimo seq e cabeca
                                de cada arquivo arquivado);
  - HEFLOG.JSONL + HEFLOG.HASH  exportacao interoperavel (estrutura,
                                contagem e cabeca final; os hashes sao
                                conferidos contra o binario quando os
                                dois estao presentes).

ESCOPO
  Ferramenta PASSIVA/defensiva: verifica evidencia produzida pelo proprio
  equipamento. Nao explora, nao altera e nao acessa equipamento alheio.

USO
  tools/verify_log.py --dir /caminho/do/cartao
  tools/verify_log.py HEFLOG.BIN HEFLOG000.BIN HEFLOG001.BIN
  tools/verify_log.py --dir /caminho/do/cartao --json
  tools/verify_log.py --selftest

CODIGO DE SAIDA
  0  tudo verificado
  1  violacao de integridade (cadeia, checkpoint, manifesto ou JSONL)
  2  erro de uso/IO (arquivo ausente, header invalido, etc.)

LIMITACAO DA v5.1.0
  Os checkpoints sao gravados SEM assinatura (o core Arduino 2.0.17 nao
  expoe Ed25519; a assinatura por dispositivo e' das fases 2/3.3 do
  plano). Um checkpoint NAO assinado NAO e' verificavel por terceiro:
  ele prova consistencia interna, nao autoria. O verificador NUNCA
  apresenta um checkpoint nao assinado como se fosse assinado.
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile

# ---------------------------------------------------------------------
# Constantes do formato (espelham lib/src/hefestos_pins.h e
# lib/src/field_log.h)
# ---------------------------------------------------------------------
HASH_LEN = 32
REC_FIXED = 11            # seq(4) + utc(4) + type(1) + len(2)
MAX_DATA = 192
HDR5_LEN = 38
HDR6_LEN = 70
CHK_MAGIC = b"HCP1"
CHK_FIXED = 52            # antes da assinatura
CHK_MAX_SIG = 512


def crc16(data):
    """CRC16/IBM (0xA001), o mesmo do protocolo serial do firmware."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


class VerifyError(Exception):
    pass


# ---------------------------------------------------------------------
# Leitura de um arquivo de log binario
# ---------------------------------------------------------------------
class LogFile:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.magic = None
        self.node_id = 0
        self.seed = b""
        self.prev_head = b""
        self.chain_base = b""
        self.records = 0
        self.first_seq = 0
        self.last_seq = 0
        self.head = b""
        self.size = 0
        self.hashes = {}      # seq -> hash (para cruzar com JSONL/checkpoints)

    @staticmethod
    def parse_header(data):
        if len(data) < 4:
            raise VerifyError("arquivo curto demais para ter header")
        if data[:4] == b"HLG5":
            if len(data) < HDR5_LEN:
                raise VerifyError("header HLG5 truncado")
            node = struct.unpack(">H", data[4:6])[0]
            seed = data[6:38]
            return "HLG5", node, seed, seed, HDR5_LEN
        if data[:4] == b"HLG6":
            if len(data) < HDR6_LEN:
                raise VerifyError("header HLG6 truncado")
            node = struct.unpack(">H", data[4:6])[0]
            seed = data[6:38]
            prev = data[38:70]
            return "HLG6", node, seed, prev, HDR6_LEN
        raise VerifyError("magic desconhecido: %r" % data[:4])


def verify_log_file(path, strict_tail=True):
    """Verifica a cadeia de um arquivo. Levanta VerifyError na 1a falha."""
    lf = LogFile(path)
    with open(path, "rb") as f:
        data = f.read()
    lf.size = len(data)

    lf.magic, lf.node_id, lf.seed, lf.chain_base, hdr_len = \
        LogFile.parse_header(data)
    lf.prev_head = lf.chain_base

    prev = lf.chain_base
    pos = hdr_len
    last_seq = None

    while pos < len(data):
        if pos + REC_FIXED > len(data):
            if strict_tail:
                raise VerifyError(
                    "%s: registro truncado no offset %d (faltam %d bytes "
                    "para o cabecalho fixo)" % (lf.name, pos, REC_FIXED))
            break
        fixed = data[pos:pos + REC_FIXED]
        seq = struct.unpack(">I", fixed[0:4])[0]
        utc = struct.unpack(">I", fixed[4:8])[0]
        rtype = fixed[8]
        ln = struct.unpack(">H", fixed[9:11])[0]
        if ln > MAX_DATA:
            raise VerifyError(
                "%s: len=%d > %d no seq %d (offset %d)" %
                (lf.name, ln, MAX_DATA, seq, pos))
        need = REC_FIXED + ln + HASH_LEN
        if pos + need > len(data):
            raise VerifyError(
                "%s: registro seq=%d truncado (precisa %d bytes, tem %d)" %
                (lf.name, seq, need, len(data) - pos))
        body = data[pos + REC_FIXED:pos + REC_FIXED + ln]
        stored = data[pos + REC_FIXED + ln:pos + need]

        calc = hashlib.sha256(prev + fixed + body).digest()
        if calc != stored:
            raise VerifyError(
                "%s: CADEIA VIOLADA no seq=%d (offset %d)\n"
                "  esperado: %s\n  gravado : %s" %
                (lf.name, seq, pos, calc.hex(), stored.hex()))

        if last_seq is not None and seq != last_seq + 1:
            raise VerifyError(
                "%s: seq fora de ordem: %d apos %d (buraco ou reuso)" %
                (lf.name, seq, last_seq))

        if lf.records == 0:
            lf.first_seq = seq
        lf.hashes[seq] = stored
        lf.records += 1
        lf.last_seq = seq
        lf.head = stored
        prev = stored
        last_seq = seq
        pos += need

    lf.utc_last = utc if lf.records else 0
    lf.type_last = rtype if lf.records else 0
    return lf


# ---------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------
def verify_checkpoints(path, logs_by_index, logs_by_seq):
    """Verifica HEFCHK.BIN. Retorna a lista de checkpoints lidos."""
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        data = f.read()

    out = []
    pos = 0
    while pos < len(data):
        if pos + CHK_FIXED > len(data):
            raise VerifyError("checkpoint truncado no offset %d" % pos)
        rec = data[pos:pos + CHK_FIXED]
        if rec[:4] != CHK_MAGIC:
            raise VerifyError("checkpoint com magic invalido no offset %d" % pos)
        file_index = struct.unpack(">H", rec[4:6])[0]
        seq = struct.unpack(">I", rec[6:10])[0]
        head = rec[10:10 + HASH_LEN]
        signer = rec[10 + HASH_LEN:10 + HASH_LEN + 8]
        sig_len = struct.unpack(">H", rec[10 + HASH_LEN + 8:CHK_FIXED])[0]
        if sig_len > CHK_MAX_SIG:
            raise VerifyError("checkpoint com sigLen=%d invalido" % sig_len)

        need = CHK_FIXED + sig_len + 2
        if pos + need > len(data):
            raise VerifyError("checkpoint truncado (assinatura) no offset %d" % pos)
        sig = data[pos + CHK_FIXED:pos + CHK_FIXED + sig_len]
        crc_stored = struct.unpack(">H", data[pos + CHK_FIXED + sig_len:pos + need])[0]
        crc_calc = crc16(data[pos:pos + CHK_FIXED + sig_len])
        if crc_stored != crc_calc:
            raise VerifyError(
                "checkpoint seq=%d com CRC16 invalido (esperado %04X, gravado %04X)" %
                (seq, crc_calc, crc_stored))

        # O checkpoint referencia (arquivo, seq, cabeca).
        ref = logs_by_seq.get(seq)
        if ref is not None:
            if ref["hash"] != head:
                raise VerifyError(
                    "checkpoint seq=%d nao bate com a cadeia do binario\n"
                    "  checkpoint: %s\n  binario   : %s" %
                    (seq, head.hex(), ref["hash"].hex()))
            if file_index != ref["file_index"] and ref["file_index"] is not None:
                # O checkpoint pode ter sido gravado ANTES da rotacao do
                # arquivo atual (indice ainda nao atribuido). Nesse caso
                # o indice do checkpoint e' o indice futuro, que coincide
                # com o do arquivo quando ele for arquivado.
                if file_index not in (ref["file_index"], ref["file_index"] + 1):
                    raise VerifyError(
                        "checkpoint seq=%d aponta arquivo %d, mas o seq esta "
                        "no arquivo %d" %
                        (seq, file_index, ref["file_index"]))
        # Se o arquivo referenciado nao esta presente, o checkpoint e'
        # apenas registrado (nao ha como conferir a cabeca).

        out.append({
            "file_index": file_index,
            "seq": seq,
            "head": head,
            "signed": sig_len > 0,
            "sig_len": sig_len,
            "signer": signer.hex() if sig_len else None,
            "sig": sig.hex() if sig_len else None,
        })
        pos += need
    return out


# ---------------------------------------------------------------------
# Manifesto de rotacao
# ---------------------------------------------------------------------
def verify_manifest(path, logs_by_name, strict=False):
    """Confere o manifesto contra os arquivos presentes.

    O manifesto NAO tem assinatura (v5.1.0): ele e' apenas uma
    declaracao. Mesmo assim, uma entrada que declara um arquivo
    AUSENTE e' evidencia de que algo foi removido do cartao — em modo
    estrito (--dir, cartao inteiro) isso e' violacao, nao aviso.
    """
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError as exc:
                raise VerifyError("manifesto linha %d: JSON invalido (%s)" %
                                  (lineno, exc))
            if not isinstance(e, dict):
                raise VerifyError("manifesto linha %d: nao e' um objeto JSON" %
                                  lineno)
            if e.get("event") != "rotate":
                continue
            name = e.get("name", "")
            if not isinstance(name, str):
                raise VerifyError("manifesto linha %d: 'name' invalido" % lineno)
            lf = logs_by_name.get(name)
            if lf is None:
                if strict:
                    raise VerifyError(
                        "manifesto declara %s, mas o arquivo NAO ESTA no "
                        "cartao (evidencia removida)" % name)
                out.append({"entry": e, "present": False})
                continue

            # O indice declarado tem de corresponder ao NOME do arquivo:
            # renomear HEFLOG005.BIN para HEFLOG000.BIN (para esconder
            # um prefixo) deixa de bater com o manifesto.
            try:
                if "index" in e and int(e["index"]) != index_of(name):
                    raise VerifyError(
                        "manifesto: %s declara index=%s, mas o nome diz %s" %
                        (name, e["index"], index_of(name)))
                if "node" in e and int(e["node"]) != lf.node_id:
                    raise VerifyError(
                        "manifesto: %s declara node=%s, arquivo e' do node %u" %
                        (name, e["node"], lf.node_id))
                checks = [
                    ("records", lf.records),
                    ("first_seq", lf.first_seq),
                    ("last_seq", lf.last_seq),
                    ("bytes", lf.size),
                ]
                for key, actual in checks:
                    if key in e and int(e[key]) != int(actual):
                        raise VerifyError(
                            "manifesto: %s declara %s=%s, arquivo tem %s" %
                            (name, key, e[key], actual))
            except (TypeError, ValueError):
                raise VerifyError("manifesto linha %d: valor numerico invalido" %
                                  lineno)

            # prev_head e' a BASE da cadeia do arquivo (o prevHead do
            # header HLG6, ou a semente no HLG5) — nao a cabeca dele.
            if "prev_head" in e:
                try:
                    declared = str(e["prev_head"]).lower()
                except (TypeError, ValueError):
                    raise VerifyError("manifesto linha %d: prev_head invalido" %
                                      lineno)
                if declared != lf.chain_base.hex():
                    raise VerifyError(
                        "manifesto: %s declara prev_head=%s, arquivo comeca em %s" %
                        (name, declared, lf.chain_base.hex()))

            if "head" in e and str(e["head"]).lower() != lf.head.hex():
                raise VerifyError(
                    "manifesto: %s declara head=%s, arquivo tem %s" %
                    (name, e["head"], lf.head.hex()))
            out.append({"entry": e, "present": True})
    return out


# ---------------------------------------------------------------------
# JSONL + HASH
# ---------------------------------------------------------------------
def verify_jsonl(jsonl_path, hash_path, logs_by_seq=None):
    if not os.path.exists(jsonl_path):
        return None
    count = 0
    last_seq = None
    last_hash = None
    seqs = set()
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError as exc:
                raise VerifyError("JSONL linha %d: JSON invalido (%s)" %
                                  (lineno, exc))
            for key in ("seq", "utc", "type", "data", "hash"):
                if key not in e:
                    raise VerifyError("JSONL linha %d: campo '%s' ausente" %
                                      (lineno, key))
            seq = int(e["seq"])
            if last_seq is not None and seq <= last_seq:
                raise VerifyError(
                    "JSONL linha %d: seq %d nao e' crescente (anterior %d)" %
                    (lineno, seq, last_seq))
            h = str(e["hash"]).lower()
            if len(h) != HASH_LEN * 2:
                raise VerifyError("JSONL linha %d: hash com tamanho invalido" %
                                  lineno)
            # Cruzamento com o binario: o hash do JSONL tem de ser o
            # mesmo do registro binario (o hash cobre os bytes crus; o
            # JSONL so sanitiza a apresentacao do campo data).
            if logs_by_seq is not None:
                ref = logs_by_seq.get(seq)
                if ref is not None and ref["hash"].hex() != h:
                    raise VerifyError(
                        "JSONL linha %d: hash do seq %d nao bate com o binario" %
                        (lineno, seq))
            last_seq = seq
            last_hash = h
            seqs.add(seq)
            count += 1

    meta = None
    if hash_path and os.path.exists(hash_path):
        with open(hash_path, "r", encoding="utf-8", errors="replace") as f:
            try:
                meta = json.load(f)
            except json.JSONDecodeError as exc:
                raise VerifyError("HEFLOG.HASH invalido (%s)" % exc)
        if int(meta.get("records", -1)) != count:
            raise VerifyError(
                "HEFLOG.HASH declara %s registros, JSONL tem %d" %
                (meta.get("records"), count))
        if last_hash is not None and \
           str(meta.get("chain_head", "")).lower() != last_hash:
            raise VerifyError(
                "HEFLOG.HASH: chain_head nao bate com o ultimo registro do JSONL")
        if meta.get("integrity") is not True:
            raise VerifyError("HEFLOG.HASH: exportacao marcada com integridade "
                              "VIOLADA")
    return {"records": count, "last_hash": last_hash, "meta": meta,
            "seqs": seqs}


# ---------------------------------------------------------------------
# Conjunto de arquivos (cartao inteiro)
# ---------------------------------------------------------------------
def discover(directory):
    names = []
    for name in os.listdir(directory):
        if not (name.startswith("HEFLOG") and name.endswith(".BIN")):
            continue
        # Apenas HEFLOG.BIN ou HEFLOGnnn.BIN: qualquer outro .BIN e'
        # corpo estranho e nao pode entrar na cadeia.
        if name != "HEFLOG.BIN" and not name[6:-4].isdigit():
            continue
        names.append(name)
    names.sort()
    return [os.path.join(directory, n) for n in names]


def index_of(name):
    """HEFLOG.BIN = atual (indice None); HEFLOGnnn.BIN = n."""
    if name == "HEFLOG.BIN":
        return None
    stem = name[len("HEFLOG"):-len(".BIN")]
    if stem.isdigit():
        return int(stem)
    return None


def verify_all(paths, check_jsonl=True, strict=False):
    logs = []
    for p in paths:
        logs.append(verify_log_file(p))

    # Ordena: arquivados por indice e o atual por ultimo.
    def key(lf):
        idx = index_of(lf.name)
        return (1 if idx is None else 0, idx if idx is not None else 0)
    logs.sort(key=key)

    if not logs:
        raise VerifyError("nenhum arquivo de log informado")

    # Todos os arquivos tem de ser do MESMO no'. Misturar arquivos de
    # dois equipamentos (ou de um cartao trocado) nao pode passar como
    # uma cadeia unica.
    node0 = logs[0].node_id
    for lf in logs:
        if lf.node_id != node0:
            raise VerifyError(
                "%s: node_id=%u difere do primeiro arquivo (node_id=%u)" %
                (lf.name, lf.node_id, node0))

    # ANCORA DO INICIO: o primeiro arquivo da serie tem de comecar no
    # seq 1 e, no HLG6, ter como prev_head a semente derivada do
    # node_id. Sem isso, remover o PREFIXO da cadeia (ou renomear
    # HEFLOG005.BIN para HEFLOG000.BIN) produziria uma serie
    # internamente consistente — e falsamente "integra".
    first = logs[0]
    if first.records:
        if first.first_seq != 1:
            raise VerifyError(
                "%s: primeiro seq=%d (esperado 1). O PREFIXO da cadeia "
                "foi removido ou o arquivo foi renomeado." %
                (first.name, first.first_seq))
        if first.magic == "HLG6":
            expected = hashlib.sha256(
                b"HLG6" + struct.pack(">H", first.node_id)).digest()
            if first.chain_base != expected:
                raise VerifyError(
                    "%s: prev_head do primeiro arquivo nao e' a semente do "
                    "node %u (cadeia comecou de outro ponto)" %
                    (first.name, first.node_id))

    # Continuidade entre arquivos.
    prev = None
    for lf in logs:
        if prev is not None:
            if lf.magic == "HLG6":
                if lf.prev_head != prev.head:
                    raise VerifyError(
                        "%s: prevHead nao bate com a cabeca de %s\n"
                        "  esperado: %s\n  gravado : %s" %
                        (lf.name, prev.name, prev.head.hex(),
                         lf.prev_head.hex()))
            if lf.records and lf.first_seq != prev.last_seq + 1:
                raise VerifyError(
                    "%s: primeiro seq %d nao continua %s (ultimo %d)" %
                    (lf.name, lf.first_seq, prev.name, prev.last_seq))
        prev = lf

    logs_by_index = {}
    logs_by_name = {}
    logs_by_seq = {}
    for lf in logs:
        idx = index_of(lf.name)
        if idx is not None:
            logs_by_index[idx] = lf
        logs_by_name[lf.name] = lf
        for seq, h in lf.hashes.items():
            logs_by_seq[seq] = {"hash": h, "file_index": idx, "name": lf.name}

    directory = os.path.dirname(os.path.abspath(paths[0])) if paths else "."
    checkpoints = verify_checkpoints(
        os.path.join(directory, "HEFCHK.BIN"), logs_by_index, logs_by_seq)
    manifest = verify_manifest(
        os.path.join(directory, "HEFLOG.MAN"), logs_by_name, strict=strict)

    # Ultimo registro de toda a serie (por seq, nao por nome).
    last_lf = None
    for lf in logs:
        if lf.records and (last_lf is None or lf.last_seq > last_lf.last_seq):
            last_lf = lf

    # Um checkpoint ancora um (seq, cabeca). Se ele aponta um seq que
    # nao existe em NENHUM arquivo presente, faltam registros (o fim da
    # cadeia foi removido). So da' para afirmar isso com o cartao
    # inteiro (--dir): num subconjunto de arquivos a ausencia e' normal.
    if strict and checkpoints:
        cp_max = max(c["seq"] for c in checkpoints)
        if last_lf is None or cp_max > last_lf.last_seq:
            raise VerifyError(
                "HEFCHK.BIN ancora o seq %d, mas o ultimo registro "
                "presente e' %s (fim da cadeia REMOVIDO)" %
                (cp_max, "-" if last_lf is None else last_lf.last_seq))

    jsonl = None
    if check_jsonl:
        jsonl = verify_jsonl(os.path.join(directory, "HEFLOG.JSONL"),
                             os.path.join(directory, "HEFLOG.HASH"),
                             logs_by_seq)
        if jsonl is not None:
            bin_seqs = set(logs_by_seq)
            missing = bin_seqs - jsonl["seqs"]
            extra = jsonl["seqs"] - bin_seqs
            jsonl["missing"] = len(missing)
            jsonl["extra"] = len(extra)
            # O conjunto de seqs e' interno (nao e' serializavel em JSON).
            jsonl.pop("seqs", None)
            if strict and (missing or extra):
                raise VerifyError(
                    "HEFLOG.JSONL nao cobre o binario: %d registro(s) do "
                    "binario ausente(s) na exportacao, %d registro(s) na "
                    "exportacao sem correspondencia no binario" %
                    (len(missing), len(extra)))

    return {
        "files": logs,
        "checkpoints": checkpoints,
        "manifest": manifest,
        "jsonl": jsonl,
        "strict": strict,
        "last_seq": last_lf.last_seq if last_lf else 0,
        "last_head": last_lf.head if last_lf else None,
    }


# ---------------------------------------------------------------------
# Relatorio
# ---------------------------------------------------------------------
def print_report(res, as_json=False):
    if as_json:
        payload = {
            "ok": True,
            "strict": res.get("strict", False),
            "last_seq": res.get("last_seq", 0),
            "last_head": (res["last_head"].hex()
                          if res.get("last_head") else None),
            "files": [{
                "name": lf.name, "magic": lf.magic, "node_id": lf.node_id,
                "records": lf.records, "first_seq": lf.first_seq,
                "last_seq": lf.last_seq, "bytes": lf.size,
                "head": lf.head.hex(), "prev_head": lf.prev_head.hex(),
            } for lf in res["files"]],
            "checkpoints": [{
                "file_index": c["file_index"], "seq": c["seq"],
                "signed": c["signed"], "sig_len": c["sig_len"],
                "signer": c["signer"],
            } for c in res["checkpoints"]],
            "manifest": res["manifest"],
            "jsonl": res["jsonl"],
        }
        print(json.dumps(payload, indent=2))
        return

    print("Arquivos de log:")
    total = 0
    for lf in res["files"]:
        total += lf.records
        print("  %-14s %s node=%u registros=%u seq=%u..%u bytes=%u" %
              (lf.name, lf.magic, lf.node_id, lf.records,
               lf.first_seq, lf.last_seq, lf.size))
        print("    cabeca: %s" % lf.head.hex())
    print("  TOTAL: %d registros em %d arquivo(s)" % (total, len(res["files"])))

    cps = res["checkpoints"]
    print("\nCheckpoints (HEFCHK.BIN): %d" % len(cps))
    for c in cps:
        if c["signed"]:
            # sigLen > 0 NAO prova assinatura: sem a chave publica nao
            # ha como verificar. Nunca apresentar como "verificado".
            print("  seq=%-8u arquivo=%u ASSINATURA PRESENTE (%d bytes, "
                  "signer=%s) - NAO VERIFICADA (sem chave publica)" %
                  (c["seq"], c["file_index"], c["sig_len"], c["signer"]))
        else:
            print("  seq=%-8u arquivo=%u NAO ASSINADO (consistencia interna; "
                  "nao verificavel por terceiro)" % (c["seq"], c["file_index"]))
    if cps and not any(c["signed"] for c in cps):
        print("  AVISO: nenhum checkpoint assinado. A v5.1.0 grava checkpoints")
        print("         sem assinatura (Ed25519 fica para as fases 2/3.3).")
        print("         Isto prova consistencia interna, NAO autoria.")

    man = res["manifest"]
    if man:
        print("\nManifesto de rotacao: %d entrada(s)" % len(man))
        for e in man:
            ent = e["entry"]
            estado = "presente" if e["present"] else "AUSENTE"
            print("  %s indice=%s registros=%s [%s]" %
                  (ent.get("name"), ent.get("index"),
                   ent.get("records"), estado))

    if res["jsonl"] is not None:
        j = res["jsonl"]
        print("\nJSONL: %d registros, hash final %s" %
              (j["records"], (j["last_hash"] or "-")[:16] + "..."))
        if j.get("missing"):
            print("  AVISO: exportacao PARCIAL - %d registro(s) do binario "
                  "nao estao no JSONL" % j["missing"])
        if j.get("extra"):
            print("  AVISO: %d registro(s) do JSONL nao existem no binario "
                  "(exportacao velha ou adulterada)" % j["extra"])

    if not res.get("strict"):
        print("\nNOTA: verificacao de SUBCONJUNTO de arquivos. Use --dir "
              "para verificar o cartao inteiro (evidencia ausente = falha).")

    print("\nRESULTADO: cadeia INTEGRA")
    print("  (integridade = consistencia da cadeia; NAO e' autoria. Sem")
    print("   assinatura por dispositivo, quem tem acesso de escrita ao")
    print("   cartao pode reconstruir a cadeia desde a semente publica.)")
    print("  LIMITE: remover o FIM da cadeia (ultimos registros/arquivos)")
    print("   nao e' detectavel sem uma ancora externa confiavel. Guarde")
    print("   o ultimo (seq, cabeca) fora do cartao e confira com")
    print("   --expect-last-seq/--expect-head.")


# ---------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------
def _rec(seq, utc, rtype, data, prev):
    fixed = struct.pack(">IIBH", seq, utc, rtype, len(data))
    h = hashlib.sha256(prev + fixed + data).digest()
    return fixed + data + h, h


def _hdr6(node, seed, prev):
    return b"HLG6" + struct.pack(">H", node) + seed + prev


def _chk(file_index, seq, head, sig=b"", signer=b"\x00" * 8):
    rec = CHK_MAGIC + struct.pack(">HI", file_index, seq) + head + \
          (signer if sig else b"\x00" * 8) + struct.pack(">H", len(sig))
    # O CRC16 cobre TUDO que o precede, inclusive a assinatura.
    body = rec + sig
    return body + struct.pack(">H", crc16(body))


def selftest():
    ok = 0
    fail = 0

    def check(cond, msg):
        nonlocal ok, fail
        if cond:
            ok += 1
            print("  [PASS] %s" % msg)
        else:
            fail += 1
            print("  [FAIL] %s" % msg)

    print("== selftest do verificador ==")
    with tempfile.TemporaryDirectory(prefix="hefverify_") as d:
        seed = hashlib.sha256(b"HLG6" + struct.pack(">H", 7)).digest()

        # Arquivo 0: 2 registros.
        r1, h1 = _rec(1, 1735689600, 0x11, b"primeiro", seed)
        r2, h2 = _rec(2, 1735689601, 0x11, b"segundo", h1)
        f0 = os.path.join(d, "HEFLOG000.BIN")
        with open(f0, "wb") as f:
            f.write(_hdr6(7, seed, seed) + r1 + r2)

        # Arquivo atual: continua a cadeia (prevHead = h2), seq 3..4.
        r3, h3 = _rec(3, 1735689602, 0x12, b"terceiro", h2)
        r4, h4 = _rec(4, 1735689603, 0x12, b"quarto", h3)
        fc = os.path.join(d, "HEFLOG.BIN")
        with open(fc, "wb") as f:
            f.write(_hdr6(7, seed, h2) + r3 + r4)

        # Manifesto do arquivo 0.
        with open(os.path.join(d, "HEFLOG.MAN"), "w") as f:
            f.write(json.dumps({
                "v": 1, "node": 7, "event": "rotate", "index": 0,
                "name": "HEFLOG000.BIN", "records": 2, "first_seq": 1,
                "last_seq": 2, "bytes": HDR6_LEN + len(r1) + len(r2),
                "prev_head": seed.hex(), "head": h2.hex(),
                "utc": 1735689601,
            }) + "\n")

        # Checkpoints: um nao assinado (seq 2) e um assinado (seq 4).
        with open(os.path.join(d, "HEFCHK.BIN"), "wb") as f:
            f.write(_chk(0, 2, h2))
            f.write(_chk(1, 4, h4, sig=b"\xAB" * 64, signer=b"\x01" * 8))

        res = verify_all([f0, fc])
        check(len(res["files"]) == 2, "2 arquivos lidos")
        check(res["files"][0].records == 2 and res["files"][1].records == 2,
              "4 registros no total")
        check(len(res["checkpoints"]) == 2, "2 checkpoints lidos")
        check(not res["checkpoints"][0]["signed"],
              "checkpoint sem assinatura identificado como NAO assinado")
        check(res["checkpoints"][1]["signed"],
              "checkpoint com assinatura identificado como ASSINADO")

        # Corrupcao de 1 byte no payload: a cadeia tem de falhar.
        bad = os.path.join(d, "HEFLOG_BAD.BIN")
        shutil.copyfile(f0, bad)
        with open(bad, "r+b") as f:
            f.seek(HDR6_LEN + REC_FIXED + 2)
            b = f.read(1)
            f.seek(HDR6_LEN + REC_FIXED + 2)
            f.write(bytes([b[0] ^ 0x01]))
        try:
            verify_log_file(bad)
            check(False, "corrupcao de 1 byte detectada")
        except VerifyError:
            check(True, "corrupcao de 1 byte detectada")

        # Truncamento do ultimo byte: falha.
        trunc = os.path.join(d, "HEFLOG_TRUNC.BIN")
        with open(fc, "rb") as f:
            blob = f.read()
        with open(trunc, "wb") as f:
            f.write(blob[:-1])
        try:
            verify_log_file(trunc)
            check(False, "truncamento detectado")
        except VerifyError:
            check(True, "truncamento detectado")

        # Checkpoint com CRC errado: falha.
        chk_bad = os.path.join(d, "HEFCHK_BAD.BIN")
        with open(chk_bad, "wb") as f:
            rec = bytearray(_chk(0, 2, h2))
            rec[-1] ^= 0xFF
            f.write(rec)
        try:
            verify_checkpoints(chk_bad, {}, {})
            check(False, "CRC16 de checkpoint verificado")
        except VerifyError:
            check(True, "CRC16 de checkpoint verificado")

        # Continuidade quebrada entre arquivos: falha.
        bad_prev = os.path.join(d, "HEFLOG001.BIN")
        with open(bad_prev, "wb") as f:
            f.write(_hdr6(7, seed, b"\x00" * 32) + r3 + r4)
        try:
            verify_all([f0, bad_prev])
            check(False, "prevHead incoerente detectado")
        except VerifyError:
            check(True, "prevHead incoerente detectado")

        # PREFIXO removido: a serie "comeca" no seq 3, mas a ancora do
        # inicio exige seq 1 (e a semente no prev_head). Sem isso,
        # bastava renomear HEFLOG005.BIN para HEFLOG000.BIN.
        pref = os.path.join(d, "HEFLOG009.BIN")
        with open(pref, "wb") as f:
            f.write(_hdr6(7, seed, h2) + r3 + r4)
        try:
            verify_all([pref])
            check(False, "prefixo removido detectado")
        except VerifyError:
            check(True, "prefixo removido detectado")

        # Evidencia declarada no manifesto mas AUSENTE do cartao: em
        # modo estrito (--dir) e' violacao, nao "aviso".
        with open(os.path.join(d, "HEFLOG.MAN"), "w") as f:
            f.write(json.dumps({
                "v": 1, "node": 7, "event": "rotate", "index": 77,
                "name": "HEFLOG777.BIN", "records": 10, "first_seq": 1,
                "last_seq": 10, "bytes": 999,
                "prev_head": seed.hex(), "head": h2.hex(), "utc": 1,
            }) + "\n")
        try:
            verify_all([f0, fc], strict=True)
            check(False, "manifesto com arquivo AUSENTE (strict) detectado")
        except VerifyError:
            check(True, "manifesto com arquivo AUSENTE (strict) detectado")
        # Em modo subconjunto (sem --dir) isso e' apenas reportado.
        res_abs = verify_all([f0, fc])
        check(res_abs["manifest"][0]["present"] is False,
              "manifesto com arquivo ausente reportado (modo subconjunto)")

        # JSONL coerente com o binario: passa.
        jsonl = os.path.join(d, "HEFLOG.JSONL")
        with open(jsonl, "w") as f:
            for seq, utc, t, data, h in [
                (1, 1735689600, 0x11, b"primeiro", h1),
                (2, 1735689601, 0x11, b"segundo", h2),
                (3, 1735689602, 0x12, b"terceiro", h3),
                (4, 1735689603, 0x12, b"quarto", h4),
            ]:
                f.write(json.dumps({
                    "seq": seq, "utc": utc, "type": t,
                    "data": data.decode(), "hash": h.hex(),
                }) + "\n")
        with open(os.path.join(d, "HEFLOG.HASH"), "w") as f:
            json.dump({"records": 4, "node_id": 7, "chain_head": h4.hex(),
                       "integrity": True}, f)
        try:
            j = verify_jsonl(jsonl, os.path.join(d, "HEFLOG.HASH"),
                             {1: {"hash": h1}, 2: {"hash": h2},
                              3: {"hash": h3}, 4: {"hash": h4}})
            check(j["records"] == 4, "JSONL coerente com o binario")
        except VerifyError as exc:
            check(False, "JSONL coerente com o binario (%s)" % exc)

        # JSONL com seq fora de ordem: falha.
        with open(jsonl, "a") as f:
            f.write(json.dumps({"seq": 4, "utc": 0, "type": 0,
                                "data": "", "hash": "00" * 32}) + "\n")
        try:
            verify_jsonl(jsonl, None, None)
            check(False, "JSONL com seq fora de ordem recusado")
        except VerifyError:
            check(True, "JSONL com seq fora de ordem recusado")

    print("\nselftest: %d verificacoes, %d falha(s)" % (ok, fail))
    return 0 if fail == 0 else 1


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Verificador offline da cadeia forense (Hefestos SIGINT)")
    ap.add_argument("files", nargs="*", help="arquivos HEFLOG*.BIN")
    ap.add_argument("--dir", help="diretorio do cartao (descobre HEFLOG*.BIN)")
    ap.add_argument("--json", action="store_true", help="saida em JSON")
    ap.add_argument("--selftest", action="store_true", help="teste do proprio verificador")
    ap.add_argument("--expect-last-seq", type=int,
                    help="ancora externa: seq do ULTIMO registro confiavel")
    ap.add_argument("--expect-head",
                    help="ancora externa: cabeca SHA-256 do ULTIMO registro confiavel")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    paths = list(args.files)
    if args.dir:
        paths.extend(discover(args.dir))
    if not paths:
        ap.error("informe arquivos ou --dir")
    for p in paths:
        if not os.path.exists(p):
            print("ERRO: arquivo nao encontrado: %s" % p, file=sys.stderr)
            return 2
    try:
        res = verify_all(paths, strict=bool(args.dir))
        # Ancoras externas: o unico jeito de detectar remocao do FIM da
        # cadeia e' comparar com um (seq, cabeca) guardado FORA do
        # cartao (livro de ocorrencias, e-mail, outro dispositivo).
        if args.expect_last_seq is not None and \
           res["last_seq"] != args.expect_last_seq:
            raise VerifyError(
                "ancora externa: ultimo seq presente=%d, esperado=%d "
                "(registros do fim foram removidos)" %
                (res["last_seq"], args.expect_last_seq))
        if args.expect_head:
            got = res["last_head"].hex() if res["last_head"] else "-"
            want = args.expect_head.lower()
            if want.startswith("0x"):
                want = want[2:]
            if got != want:
                raise VerifyError(
                    "ancora externa: cabeca presente=%s, esperada=%s" %
                    (got, want))
    except VerifyError as exc:
        print("RESULTADO: INTEGRIDADE VIOLADA", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print("ERRO de IO: %s" % exc, file=sys.stderr)
        return 2
    print_report(res, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
