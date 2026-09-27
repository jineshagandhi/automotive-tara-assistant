"""Evaluate UN R155 Annex 5 retrieval on a labelled query set.

Usage:
    python eval/retrieval_eval.py            # BM25 and hybrid, writes eval/results.md

Metrics over the Annex 5 threat documents only:
    Hit@1, Hit@3  share of queries with a correct threat in the top 1 or 3
    MRR           mean reciprocal rank of the first correct threat
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tara.retrieval import KnowledgeBase, load_embedder  # noqa: E402

QUERIES = yaml.safe_load((Path(__file__).with_name("queries.yaml")).read_text(encoding="utf-8"))


def evaluate(kb):
    hit1 = hit3 = rr = 0.0
    misses = []
    for item in QUERIES:
        hits = kb.search(item["query"], k=10, kinds={"r155_threat"})
        ranked = [h.document.meta["threat_id"] for h in hits]
        rank = next((i for i, tid in enumerate(ranked, 1) if tid in item["expected"]), None)
        if rank == 1:
            hit1 += 1
        if rank and rank <= 3:
            hit3 += 1
        else:
            misses.append((item["query"], item["expected"], ranked[:3]))
        rr += 1 / rank if rank else 0
    n = len(QUERIES)
    return {"hit1": hit1 / n, "hit3": hit3 / n, "mrr": rr / n, "misses": misses}


def main():
    rows = [("BM25 with automotive synonyms", evaluate(KnowledgeBase(embedder=None)))]
    embedder = load_embedder()
    if embedder is not None:
        rows.append(("Hybrid: BM25 + BGE-small (FAISS), RRF", evaluate(KnowledgeBase(embedder=embedder))))

    lines = [
        "# Retrieval evaluation: UN R155 Annex 5",
        "",
        "%d paraphrased engineering queries, each labelled with the correct Annex 5 threat(s). "
        "Search runs over the 70 Annex 5 threat entries." % len(QUERIES),
        "",
        "| Retriever | Hit@1 | Hit@3 | MRR |",
        "|---|---|---|---|",
    ]
    for name, m in rows:
        lines.append("| %s | %.0f%% | %.0f%% | %.2f |" % (name, 100 * m["hit1"], 100 * m["hit3"], m["mrr"]))
    best_name, best = rows[-1]
    lines += ["", "Queries outside the top 3 for %s:" % best_name, ""]
    for query, expected, got in best["misses"] or [("none", [], [])]:
        lines.append("- %s (expected %s, got %s)" % (query, ", ".join(expected), ", ".join(got)))

    report = "\n".join(lines) + "\n"
    (Path(__file__).with_name("results.md")).write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
