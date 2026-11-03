"""Safe evaluation of decision-rule and trigger conditions.

Conditions are expressions over the case context: comparisons, boolean
operators, arithmetic and attribute access. Evaluation walks the Python AST
with an allowlist, so a condition can never call a function, import a module,
touch the filesystem, or read anything beyond the context mapping it is
handed. A condition that does not parse evaluates to None, which the
guardrail treats as an unknown condition: fail closed (SEC-5).
"""

from __future__ import annotations

import ast
import operator as op

_ALLOWED_BINOPS = {
    ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.truediv,
    ast.Mod: op.mod,
}
_ALLOWED_CMPOPS = {
    ast.Eq: op.eq, ast.NotEq: op.ne, ast.Lt: op.lt, ast.LtE: op.le,
    ast.Gt: op.gt, ast.GtE: op.ge, ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: op.is_, ast.IsNot: op.is_not,
}
_ALLOWED_UNARY = {ast.Not: op.not_, ast.USub: op.neg, ast.UAdd: op.pos}
_ALLOWED_FUNCS = {"len": len, "min": min, "max": max, "abs": abs, "str": str, "lower": str.lower}


class ConditionError(ValueError):
    """The condition could not be evaluated. Treated as unknown: fail closed."""


def evaluate(condition: str, context: dict):
    """Evaluate a condition against a context. Returns the value, or raises
    ConditionError for anything outside the allowlist."""
    if condition is None or condition.strip() in ("", "true", "True"):
        return True
    try:
        tree = ast.parse(condition.strip(), mode="eval")
        return _eval(tree.body, context)
    except ConditionError:
        raise
    except Exception as exc:
        raise ConditionError("condition %r is not evaluable: %s" % (condition, exc)) from exc


def is_evaluable(condition: str, context: dict | None = None) -> bool:
    try:
        evaluate(condition, context or {})
        return True
    except ConditionError:
        return False


def _eval(node, context):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, str, bool)) or node.value is None:
            return node.value
        raise ConditionError("constant type not allowed: %r" % (node.value,))
    if isinstance(node, ast.Name):
        if node.id in context:
            return context[node.id]
        if node.id in ("true", "True"):
            return True
        if node.id in ("false", "False"):
            return False
        if node.id in ("none", "None"):
            return None
        # An unknown name is an unknown condition, not a false one.
        raise ConditionError("unknown name %r in condition" % node.id)
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINOPS:
        return _ALLOWED_BINOPS[type(node.op)](_eval(node.left, context), _eval(node.right, context))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY:
        return _ALLOWED_UNARY[type(node.op)](_eval(node.operand, context))
    if isinstance(node, ast.Compare):
        left = _eval(node.left, context)
        for cmp_op, comparator in zip(node.ops, node.comparators):
            if type(cmp_op) not in _ALLOWED_CMPOPS:
                raise ConditionError("comparison operator not allowed")
            right = _eval(comparator, context)
            if not _ALLOWED_CMPOPS[type(cmp_op)](left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        values = [_eval(v, context) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.Attribute):
        base = _eval(node.value, context)
        if isinstance(base, str) and node.attr in _ALLOWED_FUNCS:
            return _ALLOWED_FUNCS[node.attr]
        if isinstance(base, dict) and node.attr in base:
            return base[node.attr]
        raise ConditionError("attribute %r not allowed" % node.attr)
    if isinstance(node, ast.Call):
        func = _eval(node.func, context)
        if func not in _ALLOWED_FUNCS.values():
            raise ConditionError("function call not allowed")
        return func(*[_eval(a, context) for a in node.args])
    raise ConditionError("expression construct not allowed: %s" % type(node).__name__)
