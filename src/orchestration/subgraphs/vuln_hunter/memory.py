from pydantic import BaseModel, Field


class VulnHunterMemory(BaseModel):
    """7-dimensional memory for constraint-driven PoC generation with anti-forgetting."""

    target_info: str = Field(description="Vulnerability target: service, version, CVE")
    code_paths: list[str] = Field(
        default_factory=list,
        description="Possible attack code paths to explore",
    )
    negative_evidence: list[str] = Field(
        default_factory=list,
        description="Explicitly recorded failed paths — prevents revisiting",
    )
    constraints: list[str] = Field(
        default_factory=list,
        description="Accumulated constraints from Linter + execution feedback",
    )
    poc_candidates: list[str] = Field(
        default_factory=list,
        description="Historical PoC candidate code for comparison",
    )
    iteration_count: int = Field(default=0, description="Current iteration round (0-10)")
    final_poc: str | None = Field(default=None, description="Successfully verified PoC")

    def add_constraint(self, constraint: str) -> None:
        if constraint not in self.constraints:
            self.constraints.append(constraint)

    def add_negative_evidence(self, evidence: str) -> None:
        if evidence not in self.negative_evidence:
            self.negative_evidence.append(evidence)

    def increment_iteration(self) -> None:
        self.iteration_count += 1
