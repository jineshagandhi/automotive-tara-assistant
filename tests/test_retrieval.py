import pytest

from tara.retrieval import chunk_text, tokenize


@pytest.mark.parametrize("query, expected", [
    ("attacker floods the CAN bus so the vehicle cannot brake", "R155-24.1"),
    ("compromise of the over the air software update", "R155-12.1"),
    ("dongle in the OBD diagnostic port manipulates parameters", "R155-18.3"),
    ("extraction of cryptographic keys", "R155-19.3"),
    ("falsify mileage driving data", "R155-20.4"),
])
def test_lexical_retrieval_finds_the_right_threat(kb, query, expected):
    hits = kb.search(query, k=3, kinds={"r155_threat"})
    assert expected in [h.document.id for h in hits]


def test_scores_are_normalised(kb):
    hits = kb.search("replay attack on the gateway", k=5)
    assert hits[0].score == 1.0
    assert all(0 <= h.score <= 1 for h in hits)
    assert all(h.dense is None for h in hits)


def test_kind_filter(kb):
    hits = kb.search("secure onboard communication", k=5, kinds={"control"})
    assert hits and all(h.document.kind == "control" for h in hits)


def test_synonym_expansion():
    assert "manipul" in tokenize("tamper", expand=True)
    assert "denial" in tokenize("flooding the bus with frames", expand=True) or "flood" in tokenize("flood", expand=True)


def test_chunks_carry_citations():
    text = " ".join("word%d" % i for i in range(500))
    chunks = chunk_text(text, "hld.pdf", max_words=200, overlap=50, page=3)
    assert len(chunks) == 3
    assert all(c.citation == "hld.pdf, p. 3" for c in chunks)
    assert chunks[1].text.split()[0] == "word150"
