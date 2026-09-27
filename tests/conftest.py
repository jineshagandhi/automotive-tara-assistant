import os
import tempfile

# Deterministic and offline: lexical retrieval only, no language model,
# and a throwaway data directory
os.environ.setdefault("TARA_EMBEDDINGS", "off")
os.environ.setdefault("TARA_LLM_PROVIDER", "none")
os.environ.setdefault("TARA_DATA_DIR", tempfile.mkdtemp(prefix="tara-test-"))

import pytest  # noqa: E402

from tara.engine import TaraEngine  # noqa: E402
from tara.io import example_path, load_architecture  # noqa: E402
from tara.methodology import load_methodology  # noqa: E402
from tara.retrieval import KnowledgeBase  # noqa: E402


@pytest.fixture(scope="session")
def kb():
    return KnowledgeBase(embedder=None)


@pytest.fixture(scope="session")
def method():
    return load_methodology()


@pytest.fixture(scope="session")
def engine(kb, method):
    return TaraEngine(kb, method)


@pytest.fixture()
def architecture():
    return load_architecture(example_path())


@pytest.fixture(scope="session")
def result(engine):
    return engine.run(load_architecture(example_path()))


def scenario(result, asset_id, prop):
    return next(t for t in result.threat_scenarios if t.asset_id == asset_id and t.property == prop)
