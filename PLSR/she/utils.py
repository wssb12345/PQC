import numpy as np


# def crange(coeffs, q):
#     coeffs = np.where((coeffs >= 0) & (coeffs <= q//2),
#                       coeffs,
#                       coeffs - q)
#
#     return coeffs
def crange(coeffs, q):
    return np.where(coeffs > q // 2, coeffs - q, coeffs)