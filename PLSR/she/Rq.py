import numpy as np
from .utils import crange


class Rq(object):
    '''
    Ring-Polynomial: Fq[x] / (x^n + 1)
        range of the reminder is set to (−q/2, q/2]
    '''
    def __init__(self, coeffs, q):
        '''
        # Args
            coeffs: coefficients array of a polynomial
            q: modulus
        '''
        self.original_coeffs = coeffs  # 保存原始系数
        n = len(coeffs)  # degree of a polynomial

        f = np.zeros((n+1), dtype=np.int64)  # x^n + 1
        f[0] = f[-1] = 1
        f = np.poly1d(f)
        self.f = f

        self.q = q
        coeffs = np.array(coeffs, dtype=np.int64) % q
        coeffs = crange(coeffs, q)
        self.poly = np.poly1d(np.array(coeffs, dtype=np.int64))



    def __repr__(self):
        # template = 'Rq: {} (mod {}), reminder range: ({}, {}]'
        # return template.format(self.poly.__repr__(), self.q,
        #                        -self.q//2, self.q//2)
        return f"[{','.join(map(str, self.original_coeffs))}],{self.q}"
    def __len__(self):
        return len(self.poly)  # degree of a polynomial

    def __add__(self, other):
        coeffs = np.polyadd(self.poly, other.poly).coeffs
        return Rq(coeffs, self.q)

    def __sub__(self, other):
        # 使用 np.polysub 进行多项式的逐项相减
        coeffs = np.polysub(self.poly, other.poly).coeffs
        # 返回一个新的 Rq 对象，带有减法结果和相同的模数 q
        return Rq(coeffs, self.q)

    def __mul__(self, other):
        q, r = np.polydiv(np.polymul(self.poly, other.poly), self.f)
        coeffs = r.coeffs
        return Rq(coeffs, self.q)

    def __rmul__(self, integer):
        coeffs = (self.poly.coeffs * integer)
        return Rq(coeffs, self.q)

    def __pow__(self, integer):
        if integer == 0:
            return Rq([1], self.q)
        ret = self
        for i in range(integer-1):
            ret *= ret
        return ret

    def to_hex_string(self):
        """
        将 Rq 对象转换为 16 进制字符串
        """
        # 使用 original_coeffs 或 poly.coeffs 转换为整数
        coeffs = self.original_coeffs  # 或者使用 self.poly.coeffs
        hex_coefficients = [hex(int(c) & 0xFFFF)[2:] for c in coeffs]
        # 拼接为一个连续的十六进制字符串
        return ''.join(hex_coefficients)

    # def __getstate__(self):
    #     """
    #     定义对象的序列化状态
    #     """
    #     state = {
    #         'original_coeffs': self.original_coeffs,  # 使用原始系数
    #         'q': self.q  # 模数
    #     }
    #     return state
    #
    # def __setstate__(self, state):
    #     """
    #     从序列化状态恢复对象
    #     """
    #     self.original_coeffs = state['original_coeffs']
    #     self.q = state['q']
    #     # 恢复其他动态属性
    #     self.poly = np.poly1d(np.array(self.original_coeffs, dtype=np.int64) % self.q)
    def __getstate__(self):
        # 保存所有必要的状态
        state = {
            'original_coeffs': self.original_coeffs,
            'q': self.q
        }
        return state

    def __setstate__(self, state):
        # 恢复状态
        self.original_coeffs = state['original_coeffs']
        self.q = state['q']
        # 手动恢复动态属性
        n = len(self.original_coeffs)
        f = np.zeros((n + 1), dtype=np.int64)  # x^n + 1
        f[0] = f[-1] = 1
        self.f = np.poly1d(f)
        coeffs = np.array(self.original_coeffs, dtype=np.int64) % self.q
        self.poly = np.poly1d(np.array(coeffs, dtype=np.int64))
    def __reduce__(self):
        # 返回类、构造函数参数和状态
        return (self.__class__, (self.original_coeffs, self.q))