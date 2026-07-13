# CloudSecure Rule Engine — OPA-based policy evaluation
from .input_builder import build_opa_input
from .opa_client import evaluate, load_all_rules, load_policy

__all__ = [
    "load_all_rules",
    "load_policy",
    "evaluate",
    "build_opa_input",
    "evaluate_resource",
]


def __getattr__(name: str):
    if name == "evaluate_resource":
        from .evaluator import evaluate_resource

        return evaluate_resource
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
