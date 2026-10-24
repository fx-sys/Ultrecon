from __future__ import annotations

from core.module_base import ModuleBase
from core.orchestrator import load_module_class
from core.registry import all_phase_numbers


def test_every_registered_phase_implements_the_module_contract() -> None:
    for phase in all_phase_numbers():
        module = load_module_class(phase)
        assert issubclass(module, ModuleBase)
        assert module.phase == phase
        assert module.name
        assert callable(module().run)
