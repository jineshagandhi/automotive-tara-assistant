# Retrieval evaluation: UN R155 Annex 5

30 paraphrased engineering queries, each labelled with the correct Annex 5 threat(s). Search runs over the 70 Annex 5 threat entries.

| Retriever | Hit@1 | Hit@3 | MRR |
|---|---|---|---|
| BM25 with automotive synonyms | 70% | 83% | 0.77 |
| Hybrid: BM25 + BGE-small (FAISS), RRF | 80% | 83% | 0.83 |

Queries outside the top 3 for Hybrid: BM25 + BGE-small (FAISS), RRF:

- Someone sits between the car and the cloud and hijacks the session (expected 6.2, got 31.1, 3.2, 8.2)
- A disgruntled employee at the OEM misuses admin rights on the server (expected 1.1, 3.1, got 3.5, 12.4, 3.4)
- The ECU still uses an outdated cipher that is being phased out (expected 26.3, 26.2, got 6.3, 3.1, 3.5)
- The driver is tricked into installing malicious software (expected 15.1, got 22.2, 12.4, 17.1)
- Listening to unencrypted telematics traffic (expected 7.1, got 16.2, 16.3, 16.1)
