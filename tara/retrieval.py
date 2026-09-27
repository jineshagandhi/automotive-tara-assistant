"""Hybrid retrieval over the knowledge base and uploaded project documents.

Lexical search (BM25) always runs. Dense search uses BGE embeddings from
fastembed stored in a FAISS index, and is enabled when the model can be
loaded (TARA_EMBEDDINGS=auto, the default) or disabled with TARA_EMBEDDINGS=off.
Both rankings are merged with reciprocal rank fusion.
"""

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from rank_bm25 import BM25Okapi

from tara import DATA_DIR, knowledge

log = logging.getLogger(__name__)

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
INDEX_DIR = DATA_DIR / "vector_index"

STOPWORDS = set("""
a an and are as at be by can could e.g for from has have in into is it its of on or
such that the their them there these this to use used using via was were which with
""".split())

# Automotive security vocabulary, so a query about 'spoofing' also finds
# 'impersonation' and a query about 'flooding' finds 'denial of service'
SYNONYMS = {
    "spoof": ["imperson", "fake", "forg"],
    "tamper": ["manipul", "modif", "falsif"],
    "manipul": ["tamper", "falsif", "modif"],
    "flood": ["denial", "servic", "disrupt"],
    "dos": ["denial", "servic", "disrupt"],
    "eavesdrop": ["intercept", "monitor", "disclos"],
    "leak": ["disclos", "breach", "extract"],
    "firmwar": ["softwar", "code"],
    "ota": ["updat", "air"],
    "can": ["bus", "intern", "messag"],
    "obd": ["diagnost", "dongl", "port"],
    "usb": ["media", "port", "extern"],
    "key": ["cryptograph", "kei"],
    "replay": ["replai", "session", "hijack"],
}


def _stem(word):
    for suffix in ("ations", "ation", "ing", "ies", "ied", "ed", "es", "s", "e"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def tokenize(text, expand=False):
    words = re.findall(r"[a-z0-9]+", text.lower())
    tokens = [_stem(w) for w in words if w not in STOPWORDS and len(w) > 1]
    if expand:
        for token in list(tokens):
            tokens.extend(SYNONYMS.get(token, []))
    return tokens


@dataclass
class Document:
    id: str
    kind: str          # r155_threat, r155_mitigation, control, project_doc
    title: str
    text: str
    citation: str
    meta: dict = field(default_factory=dict)

    @property
    def content(self):
        return "%s. %s" % (self.title, self.text)


@dataclass
class Hit:
    document: Document
    score: float         # fused score, 0-1 relative to the best hit
    lexical: float       # BM25 score normalised to the best hit
    dense: float | None  # cosine similarity, None if dense search is off


def knowledge_documents():
    docs = []
    for threat in knowledge.r155()["threats"]:
        docs.append(Document(
            id="R155-" + threat["id"],
            kind="r155_threat",
            title="R155 threat %s: %s" % (threat["id"], threat["high_level"]),
            text="%s. Category: %s" % (threat["text"], threat["category"]),
            citation=knowledge.r155_citation(threat["id"]),
            meta={"threat_id": threat["id"], "mitigations": threat["mitigations"]},
        ))
    for mitigation in knowledge.r155()["mitigations"]:
        docs.append(Document(
            id="R155-" + mitigation["id"],
            kind="r155_mitigation",
            title="R155 mitigation %s" % mitigation["id"],
            text=mitigation["text"],
            citation=knowledge.mitigation_citation(mitigation["id"]),
            meta={"mitigation_id": mitigation["id"]},
        ))
    for key, control in knowledge.controls().items():
        docs.append(Document(
            id="CTRL-" + key,
            kind="control",
            title="Control: %s" % control["name"],
            text="%s Implements R155 %s. Protects %s. Reference: %s" % (
                control["description"], ", ".join(control["r155"]),
                ", ".join(control["protects"]), control["reference"]),
            citation="Control catalogue: %s (%s)" % (control["name"], control["reference"]),
            meta={"control": key},
        ))
    return docs


class Embedder:
    """Wraps fastembed so the rest of the code does not depend on it."""

    def __init__(self):
        from fastembed import TextEmbedding

        # A short path outside the project: the Hugging Face cache layout is
        # deep, and a project cloned into a long folder would exceed the
        # 260 character path limit on Windows
        cache = os.environ.get("TARA_MODEL_DIR") or str(Path.home() / ".cache" / "automotive-tara")
        if any(Path(cache).glob("models--*bge-small-en-v1.5*")):
            try:
                # Use the cached model without touching the network
                self.model = TextEmbedding(EMBEDDING_MODEL, cache_dir=cache, local_files_only=True)
                return
            except Exception:
                pass
        self.model = TextEmbedding(EMBEDDING_MODEL, cache_dir=cache)

    def embed(self, texts, query=False):
        if query:
            vectors = list(self.model.query_embed(texts))
        else:
            vectors = list(self.model.passage_embed(texts))
        matrix = np.array(vectors, dtype="float32")
        matrix /= np.linalg.norm(matrix, axis=1, keepdims=True)
        return matrix


def load_embedder():
    mode = os.environ.get("TARA_EMBEDDINGS", "auto").lower()
    if mode == "off":
        return None
    try:
        return Embedder()
    except Exception as error:  # model download or onnxruntime not available
        log.warning("Dense retrieval disabled, using BM25 only: %s", error)
        return None


class KnowledgeBase:
    def __init__(self, documents=None, embedder="auto"):
        self.documents = list(documents if documents is not None else knowledge_documents())
        self.embedder = load_embedder() if embedder == "auto" else embedder
        self._build()

    @property
    def mode(self):
        return "Hybrid (BM25 + %s / FAISS)" % EMBEDDING_MODEL if self.index is not None else "BM25"

    def _build(self):
        self.bm25 = BM25Okapi([tokenize(doc.content) for doc in self.documents])
        self.index = None
        self.vectors = None
        if self.embedder is not None:
            self.index = self._dense_index()
            self.vectors = self.index.reconstruct_n(0, len(self.documents))

    def _dense_index(self):
        import faiss

        digest = hashlib.sha256(
            "\n".join(doc.id + doc.content for doc in self.documents).encode("utf-8")
        ).hexdigest()[:16]
        path = INDEX_DIR / ("%s.faiss" % digest)

        if path.exists():
            return faiss.read_index(str(path))

        vectors = self.embedder.embed([doc.content for doc in self.documents])
        index = faiss.IndexFlatIP(vectors.shape[1])
        index.add(vectors)
        try:
            INDEX_DIR.mkdir(parents=True, exist_ok=True)
            faiss.write_index(index, str(path))
        except OSError as error:
            log.warning("Could not persist vector index: %s", error)
        return index

    def search(self, query, k=5, kinds=None, rrf_k=60):
        lexical = np.array(self.bm25.get_scores(tokenize(query, expand=True)))
        lexical_norm = lexical / lexical.max() if lexical.max() > 0 else lexical

        dense = None
        if self.index is not None:
            query_vector = self.embedder.embed([query], query=True)
            scores, ids = self.index.search(query_vector, len(self.documents))
            dense = np.zeros(len(self.documents))
            dense[ids[0]] = scores[0]

        candidates = [
            i for i, doc in enumerate(self.documents)
            if kinds is None or doc.kind in kinds
        ]

        lexical_rank = {i: r for r, i in enumerate(sorted(candidates, key=lambda i: -lexical[i]))}
        fused = {i: 1 / (rrf_k + lexical_rank[i]) for i in candidates}
        if dense is not None:
            dense_rank = {i: r for r, i in enumerate(sorted(candidates, key=lambda i: -dense[i]))}
            for i in candidates:
                fused[i] += 1 / (rrf_k + dense_rank[i])

        ranked = sorted(candidates, key=lambda i: -fused[i])[:k]
        best = fused[ranked[0]] if ranked else 1

        return [
            Hit(
                document=self.documents[i],
                score=round(fused[i] / best, 4),
                lexical=round(float(lexical_norm[i]), 4),
                dense=None if dense is None else round(float(dense[i]), 4),
            )
            for i in ranked
        ]

    def similarity(self, query, doc_ids):
        """Absolute relevance of specific documents to a query, in 0-1.

        Used by the engine to score R155 candidates. The dense cosine is used
        when available, otherwise the normalised BM25 score.
        """
        position = {doc.id: i for i, doc in enumerate(self.documents)}
        lexical = np.array(self.bm25.get_scores(tokenize(query, expand=True)))
        top = lexical.max() or 1.0

        dense = None
        if self.vectors is not None:
            dense = self.vectors @ self.embedder.embed([query], query=True)[0]

        result = {}
        for doc_id in doc_ids:
            i = position[doc_id]
            lexical_score = float(lexical[i] / top)
            if dense is None:
                result[doc_id] = lexical_score
            else:
                # BGE cosine similarities cluster between about 0.5 and 0.9
                dense_score = float(np.clip((dense[i] - 0.5) / 0.35, 0, 1))
                result[doc_id] = 0.5 * lexical_score + 0.5 * dense_score
        return result


def chunk_text(text, source, max_words=180, overlap=40, page=None):
    """Split a project document into overlapping chunks with citations."""
    words = text.split()
    chunks, start, n = [], 0, 0
    while start < len(words):
        piece = " ".join(words[start:start + max_words])
        n += 1
        where = "p. %s" % page if page is not None else "chunk %d" % n
        chunks.append(Document(
            id="DOC-%s-%s-%d" % (re.sub(r"\W+", "_", source), page or 0, n),
            kind="project_doc",
            title="%s (%s)" % (source, where),
            text=piece,
            citation="%s, %s" % (source, where),
            meta={"source": source, "page": page},
        ))
        if start + max_words >= len(words):
            break
        start += max_words - overlap
    return chunks
