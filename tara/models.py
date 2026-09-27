"""Domain model for an ISO/SAE 21434 TARA.

The input is an Architecture (the item under analysis). The engine turns it
into a TaraResult: damage scenarios, threat scenarios, attack paths, risk
values, treatment decisions, cybersecurity goals and control recommendations.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field

Property = Literal["Confidentiality", "Integrity", "Availability", "Authenticity"]

ComponentType = Literal["telematics", "infotainment", "gateway", "ecu", "sensor", "backend"]

AssetType = Literal[
    "message", "function", "firmware", "key", "personal_data",
    "configuration", "diagnostic", "log", "service",
]


# ---------------------------------------------------------------- architecture

class Component(BaseModel):
    id: str
    name: str
    type: ComponentType
    zone: str = Field(description="Network domain, e.g. connectivity, chassis, body")
    asil: Literal["QM", "A", "B", "C", "D"] = "QM"
    description: str = ""


class Bus(BaseModel):
    id: str
    name: str
    type: Literal["CAN", "CAN-FD", "LIN", "FlexRay", "Ethernet", "Cellular", "Internal"]
    members: list[str] = Field(description="Component ids connected to the bus")


class Interface(BaseModel):
    """An external interface, i.e. an entry point for an attacker."""
    id: str
    type: str = Field(description="Key from knowledge/interfaces.yaml")
    component: str = Field(description="Component id that exposes the interface")
    name: str = ""
    targets: list[str] = Field(
        default_factory=list,
        description="For receive-only links (GNSS, TPMS, key fob): asset ids fed by the link",
    )


class Asset(BaseModel):
    id: str
    name: str
    type: AssetType
    component: str
    properties: list[Property]
    asil: Literal["QM", "A", "B", "C", "D"] = "QM"
    personal_data: Literal["none", "personal", "sensitive"] = "none"
    tags: list[str] = Field(default_factory=list, description="e.g. theft, fraud, fleet, fire")
    description: str = ""


class AppliedControl(BaseModel):
    control: str = Field(description="Key from knowledge/controls.yaml")
    target: str = Field(description="Component, bus or interface id the control is deployed on")
    status: Literal["existing", "proposed"] = "existing"


class Architecture(BaseModel):
    name: str
    description: str = ""
    version: str = "0.1"
    components: list[Component]
    buses: list[Bus]
    interfaces: list[Interface]
    assets: list[Asset]
    controls: list[AppliedControl] = Field(default_factory=list)


# ---------------------------------------------------------------- analysis

class ImpactRating(BaseModel):
    category: str
    level: str
    rationale: str
    overridden: bool = False


class DamageScenario(BaseModel):
    id: str
    key: str = Field(description="Stable key 'asset id/property' used for analyst decisions")
    asset_id: str
    property: Property
    description: str
    impacts: list[ImpactRating]
    impact: str = Field(description="Highest impact level over all categories")


class R155Match(BaseModel):
    threat_id: str
    text: str
    high_level: str
    category: Optional[str]
    mitigations: list[str]
    score: float
    confidence: Literal["High", "Medium", "Low"]
    reasons: list[str]


class AttackStep(BaseModel):
    node: str
    kind: Literal["interface", "component", "bus"]
    label: str


class AttackPath(BaseModel):
    id: str
    entry_interface: str
    entry_type: str
    attack_vector: str
    steps: list[AttackStep]
    factors: dict[str, str] = Field(description="Attack potential factor -> level name")
    controls_on_path: list[str]
    attack_potential: int
    feasibility: str


class ControlRecommendation(BaseModel):
    control: str
    name: str
    target: str
    target_label: str
    r155: list[str]
    residual_feasibility: str
    residual_risk: int
    risk_reduction: int


class ThreatScenario(BaseModel):
    id: str
    key: str = Field(description="Stable key 'asset id/property' used for analyst decisions")
    damage_scenario_id: str
    asset_id: str
    property: Property
    stride: str
    description: str
    r155: list[R155Match]
    paths: list[AttackPath]
    feasibility: str
    attack_vector: str
    impact: str
    risk: int
    treatment: str
    treatment_note: str
    cal: Optional[str]
    recommendations: list[ControlRecommendation]


class CybersecurityGoal(BaseModel):
    id: str
    threat_scenario_id: str
    text: str
    cal: Optional[str]


class Finding(BaseModel):
    """Architecture level observation, e.g. a path that bypasses the gateway."""
    id: str
    severity: Literal["High", "Medium", "Low"]
    title: str
    detail: str
    r155: list[str]
    nodes: list[str] = Field(default_factory=list, description="Nodes to highlight in the diagram")


class CoverageItem(BaseModel):
    threat_id: str
    text: str
    category: Optional[str]
    status: Literal["Addressed", "CSMS process", "Not applicable", "Open"]
    scenarios: list[str]
    note: str = ""
    suggested: Optional[str] = Field(default=None, description="Closest threat scenario for an open threat")


class TaraResult(BaseModel):
    architecture: str
    profile: str
    damage_scenarios: list[DamageScenario]
    threat_scenarios: list[ThreatScenario]
    goals: list[CybersecurityGoal]
    findings: list[Finding]
    coverage: list[CoverageItem]
