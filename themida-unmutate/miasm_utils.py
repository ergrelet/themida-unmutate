import miasm.expression.expression as m2_expr


def expr_int_to_int(expr: m2_expr.ExprInt) -> int:
    int_size = expr.size
    is_signed = expr.arg >= 2**(int_size - 1)
    if is_signed:
        result = -(2**int_size - expr.arg)
    else:
        result = expr.arg

    return result
