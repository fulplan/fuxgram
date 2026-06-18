from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Type


@dataclass
class Param:
    name: str
    type: Type
    required: bool = True
    default: Any = None
    help: str = ""
    validator: Callable[[Any], bool] | None = None

    def validate(self, value: Any) -> Any:
        try:
            coerced = self.type(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"[{self.name}] cannot cast to {self.type.__name__}: {exc}") from exc
        if self.validator and not self.validator(coerced):
            raise ValueError(f"[{self.name}] failed custom validator")
        return coerced


@dataclass
class ParamSchema:
    params: list[Param] = field(default_factory=list)

    def add(self, *params: Param) -> "ParamSchema":
        self.params.extend(params)
        return self

    def parse(self, raw: dict) -> dict:
        out: dict = {}
        for p in self.params:
            if p.name not in raw:
                if p.required:
                    raise ValueError(f"Missing required param: {p.name}")
                out[p.name] = p.default
            else:
                out[p.name] = p.validate(raw[p.name])
        return out
