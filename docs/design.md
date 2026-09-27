# Design notes

This document records how the design was reached: the product iterations, the decisions behind the engine, and the calibration issues found while testing it.

## 1. Product iterations

### Iteration 1: RAG chatbot over the standards (rejected)
Upload ISO/SAE 21434 and UN R155, then ask questions about them.
- Rejected because it doesn't produce a TARA. It only explains one.
- Many capstone projects already take this "chat with PDF" shape, so it wouldn't stand out.

### Iteration 2: LLM-generated TARA (rejected)
Describe the vehicle, and let the model write threats, ratings and goals.
- The same input gives different ratings each run, so the result can't be reproduced.
- The model can invent threat IDs and mitigations that don't exist.
- A risk value can't be defended in a review ("why 4?"), and there's no traceability.
- It needs a large model and sends engineering data to a third party.

### Iteration 3: evidence-grounded TARA workbench (built)
The central idea is to **separate what must be deterministic from what benefits from language**.

| Concern | Technique |
|---|---|
| Which attack paths exist | Graph search over the modelled architecture |
| How severe and how feasible | Rules from a replaceable methodology profile |
| Which regulatory threats apply | Hybrid retrieval over the official text, plus explainable priors |
| Which controls to deploy | Search over the control catalogue, scored by the risk engine |
| Understanding documents and questions | Optional LLM, always grounded and always reviewed |

The case study's non-functional requirements then map directly onto features:
- **Citations** → R155 matches with a table and item reference
- **Confidence indicators** → match scores with reasons
- **Audit logs** → SQLite audit table
- **Human approval** → review workflow
- **Local hosting** → Ollama
- **FastAPI and Streamlit** → both provided

## 2. Engine decisions

- **Scenario granularity.** One damage scenario and one threat scenario per asset and cybersecurity property (STRIDE by property). This is the usual TARA spreadsheet layout, so the Excel export looks familiar to reviewers.
- **Attack paths.** Nodes are interfaces, components and buses. A path never passes through a second interface.
  - Receive-only radio links (GNSS, TPMS, key fob) only reach the assets they feed, because they can inject data but can't be used to take over an ECU.
  - Each ECU after the entry component raises elapsed time by one level.
- **Controls** change specific attack potential factors by a number of levels. They only apply when:
  - they sit on the path,
  - they protect the compromised property,
  - their optional filters match (entry type, asset type, bus type).

  So SecOC lowers the risk of brake message manipulation but not the risk of brake message loss.
- **Risk** uses the most feasible path. All paths are kept for review.
- **R155 matching.** The score combines 0.55 × text similarity with three explainable priors of 0.15 each: compromised property, asset type, and typical threats of the entry interfaces. Matches are diversified to at most one per high-level threat. Back-end threats are only offered when a back-end is on the path.
- **Treatment planner.** Greedy set selection. The objective is the sum of risk above the target over **all paths**, not over scenarios. With a per-scenario objective, a control that closes one of two equally easy paths shows no gain, and the search stalls.

## 3. Calibration log

The first end-to-end run produced a TARA that an expert would reject. The issues found and fixed:

| Observation in the first run | Root cause | Fix |
|---|---|---|
| Every risk was 4 or 5 | Moving from the entry ECU to the target cost nothing. The TPMS radio could "reach" the door locks | Hop cost per ECU; receive-only interfaces only reach their target assets |
| Vehicle theft rated as fleet-level financial damage | One rule for all theft-related assets | Separate rules: single-vehicle theft is Major, fleet-wide key compromise is Severe |
| R155 threat 18.x (USB/OBD) matched almost every scenario | The query contained every interface in the car, and the priors added up across all of them | Query and priors use the three most feasible paths only; one match per high-level threat |
| Charging security recommended for the brake ECU | Control placement matched any ECU | Applicability filters in the control catalogue (entries, asset types, bus types) |
| Signed OTA didn't help when the back-end was compromised | The control was limited to the OTA entry | Signature verification on the vehicle protects firmware whatever the path |
| The gateway bypass finding was reported 8 times | One finding per entry and target pair | Findings grouped by bridging ECU |
| Back-end denial of service could never be reduced | No availability control existed for the back-end | Added a back-end resilience control (R155 M3, M13) |
| Diagram unreadable (a very tall or very flat strip) | Graphviz ranked every bus before every ECU | Layers computed by breadth-first search from the back-end, so the diagram reads like an E/E drawing |
| Copilot answered about adaptive cruise control when asked about the brake control unit | Matching on any long word ("control") | Distinctive-word overlap, ignoring generic and stop words; a regression test was added |

A second, expert-style review pass found and fixed:

| Observation | Fix |
|---|---|
| The OBD port was rated a Physical attack vector | In ISO/SAE 21434, OBD and USB access from the cabin is Local. Physical means access to the ECU itself (JTAG, desoldering) |
| Brake message spoofing matched threat 4.1, which is about external V2X and GNSS messages | Threats 4.1, 4.2, 8.2 and 11.2 are only offered when the attack enters over one of those radio links |
| An HSM on the gateway was recommended for keys stored in the digital key module | Controls that protect stored data (HSM, encryption, debug lock) only count on the ECU that stores the asset |
| Secure boot was recommended against fake TPMS radio data | Secure boot is excluded for data injected over receive-only links |
| Analyst decisions were stored against running numbers (TS-004), so adding an asset silently moved them to another scenario | Decisions are stored against the stable key asset/property, e.g. `A_BRAKE/Integrity` |
| The database location depended on the folder the app was started from | Anchored to `<project>/data` |
| The embedding model cache in the project folder hit the Windows 260-character path limit when cloned deep | Model cached once in `~/.cache/automotive-tara` |

After calibration, the sample vehicle has 30 scenarios, 27 of them initially above risk 3, which is realistic for a concept phase with almost no controls. The planner proposes 12 controls, leaving 1 scenario above risk 3.

## 4. Sources and licensing of content

- **UN R155**: the Annex 5 text comes from the EUR-Lex publication, which may be reused with acknowledgement. The library stores the parsed tables and the source reference.
- **ISO/SAE 21434**: copyrighted, and not reproduced. The profile uses the widely published example values, and the tool expects organisations to supply their own.
- **Sample vehicle and HLD**: written for this project and fictional.
