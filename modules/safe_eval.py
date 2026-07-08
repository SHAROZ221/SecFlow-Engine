"""
safe_eval.py
A secure evaluation module for SOAR playbook step conditions.
Parses condition strings using Python's Abstract Syntax Tree (AST) to verify
safety and evaluate them without calling insecure `eval()`.
"""

import ast

class SecurityException(ValueError):
    """Raised when an illegal syntax node is detected in a condition expression."""
    pass

def safe_eval_condition(expression: str, context: dict) -> bool:
    """
    Safely evaluate a comparison expression string against a variable context.
    
    Only permits:
      - Comparison operators (==, !=, <, <=, >, >=, in, not in)
      - Boolean operators (and, or, not)
      - Variable names resolved against the context (e.g. severity)
      - Basic literal constants (strings, integers, floats, booleans, None)
      - Containers of constants (lists, tuples)
    
    Raises:
      SecurityException if any unsupported/malicious operations are attempted.
    """
    if not expression or not isinstance(expression, str):
        return True
        
    try:
        # Parse the expression in eval mode (expression-only parsing)
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as e:
        raise ValueError(f"Invalid condition syntax: {e}")

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
            
        elif isinstance(node, ast.Compare):
            left_val = _eval(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right_val = _eval(comparator)
                
                if isinstance(op, ast.Eq):
                    if left_val != right_val:
                        return False
                elif isinstance(op, ast.NotEq):
                    if left_val == right_val:
                        return False
                elif isinstance(op, ast.Lt):
                    if not (left_val < right_val):
                        return False
                elif isinstance(op, ast.LtE):
                    if not (left_val <= right_val):
                        return False
                elif isinstance(op, ast.Gt):
                    if not (left_val > right_val):
                        return False
                elif isinstance(op, ast.GtE):
                    if not (left_val >= right_val):
                        return False
                elif isinstance(op, ast.In):
                    try:
                        if left_val not in right_val:
                            return False
                    except TypeError:
                        return False
                elif isinstance(op, ast.NotIn):
                    try:
                        if left_val in right_val:
                            return False
                    except TypeError:
                        return False
                else:
                    raise SecurityException(f"Unsupported comparison operator: {type(op).__name__}")
            return True
            
        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(_eval(val) for val in node.values)
            elif isinstance(node.op, ast.Or):
                return any(_eval(val) for val in node.values)
            else:
                raise SecurityException(f"Unsupported boolean operator: {type(node.op).__name__}")
                
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return not _eval(node.operand)
            else:
                raise SecurityException(f"Unsupported unary operator: {type(node.op).__name__}")
                
        elif isinstance(node, ast.Name):
            # Resolve variable name from context
            if node.id in context:
                return context[node.id]
            # Check for standard boolean/None names in case they are not Constant nodes (python < 3.8 style)
            if node.id == "True":
                return True
            elif node.id == "False":
                return False
            elif node.id == "None":
                return None
            
            # Predefined playbook values fallback
            if node.id in ["critical", "high", "medium", "low", "enrichment_failed", "unknown_requires_review"]:
                return node.id
                
            return None  # Default undefined variable to None
            
        elif isinstance(node, ast.Constant):
            return node.value
            
        elif isinstance(node, ast.List):
            return [_eval(el) for el in node.elts]
            
        elif isinstance(node, ast.Tuple):
            return tuple(_eval(el) for el in node.elts)
            
        # Explicitly deny other AST nodes (e.g. Call, Attribute, Subscript, BinOp, Import)
        else:
            raise SecurityException(
                f"Security block: Node type '{type(node).__name__}' is forbidden in playbook conditions."
            )

    try:
        return bool(_eval(tree))
    except SecurityException:
        raise
    except Exception as e:
        raise ValueError(f"Error evaluating condition: {e}")
