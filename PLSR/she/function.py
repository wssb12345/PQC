import hashlib
import hmac
from she.function import *
import numpy as np
from she import RLWE, Rq
import re
import pickle
from she.lattice import LatticeParameters, Polynomial
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

def parse_rq_string(rq_str):
    match = re.match(r'\[(.*?)\],(\d+)', rq_str)
    if not match:
        raise ValueError(f"Invalid format for Rq string: {rq_str}")
    coeffs_str, q_str = match.groups()

    # 将字符串中的小数转换为整数（通过四舍五入）
    coeffs = list(map(lambda x: int(round(float(x))), coeffs_str.split(',')))
    q = int(q_str)
    return coeffs, q

# 序列化类对象为字节流
def serialize_object(obj):
    return pickle.dumps(obj)

# 反序列化字节流为类对象
def deserialize_object(byte_data):
    return pickle.loads(byte_data)


# 转换类
def create_rq_from_string(rq_str):
    coeffs, q = parse_rq_string(rq_str)
    return Rq(coeffs, q)



# # 高斯取样
# def discrete_gaussian(n, q, mean=0., std=3.192):
#     coeffs = np.round(std * np.random.randn(n))
#     x = Rq(coeffs, q)
#     return  create_polynomial_from_input(x.poly.coeffs.tolist(), q)


# 高斯取样
def discrete_gaussian(n, q, mean=0., std=3.192):
    # coeffs = np.round(std * np.random.randn(n))
    coeffs = np.round(std * np.random.randn(n) + mean) % q
    return coeffs

# 用于将生成的系数进行采样并返回多项式
def get_Polynomial(n, q, coeffs):
    # 创建 Rq 对象
    x = Rq(coeffs, q)
    # 将生成的多项式系数转换为列表，并返回
    return create_polynomial_from_input(x.poly.coeffs.tolist(), q)

# 鲁棒提取器
# def robust_extractor(x, sigma, q):
#     return ((x + sigma * (q - 1) // 2) % q) % 2


def robust_extractor(x: Polynomial, sigma: int, q: int) -> list:
    """
    Robust extractor for a Polynomial object with slight errors, applying the formula to all coefficients.

    :param x: Input Polynomial object with coefficients subject to slight errors.
    :param sigma: A single signal value (0 or 1) corresponding to all coefficients.
    :param q: Modulus for the coefficients.
    :return: A list of extracted binary coefficients (0 or 1) for all coefficients.
    """
    # 获取多项式的 NTT 表示，假设其与系数直接对应
    coef_rep = x.ntt_representation  # 使用 NTT 表示直接获取系数

    # 对每个系数应用鲁棒提取公式，并返回所有系数的提取值
    extracted_values = [
        ((coef + sigma * (q - 1) // 2) % q) % 2  # 对每个系数应用 robust extractor 公式
        for coef in coef_rep
    ]

    # return extracted_values[0]
    return extracted_values


def signal_function(poly: Polynomial) -> int:
    """
    Optimized version of the signal function for a Polynomial object.
    Processes the coefficients to return a single signal value (0 or 1).

    :param poly: Input Polynomial object.
    :return: A single signal value (0 or 1).
    """
    q = poly.lp.modulus  # 提取模数 q

    # 使用更高效的直接系数获取方式，避免解码复杂性
    coef_rep = poly.ntt_representation  # 假设 NTT 表示与系数直接对应

    # 预计算边界值，避免重复计算
    lower_bound = -q // 4
    upper_bound = q // 4

    # 使用 NumPy 向量化操作，批量计算信号函数
    import numpy as np
    coef_array = np.array(coef_rep, dtype=int)  # 转换为 NumPy 数组
    signal_result = np.where((coef_array >= lower_bound) & (coef_array < upper_bound), 0, 1)

    # 这里可以选择返回信号列表中的第一个值
    return signal_result[0]  # 返回第一个信号值（即信号函数对第一个系数的输出）




# def signal_function(x, q):
#     if -q // 4 <= x < q // 4:
#         return 0
#     else:
#         return 1

    # 格基参数（固定）

n = 512
q = 12289
length = 1
std = 3.192


# 创建 LatticeParameters 对象
lp = LatticeParameters(n, length, q)


# Rq类转Polynomial 对象
# Rq对象转：polynomial = create_polynomial_from_input(对象_coeffs.tolist(), q)
# 高斯采样的Rq类对象转：polynomial2 = create_polynomial_from_input(对象.poly.coeffs.tolist(), q)
def create_polynomial_from_input(coefficients_list, q_input):
    """
    从固定格式的输入数据创建 Polynomial 对象。

    输入数据格式为 ([系数列表], 模数)

    :param coefficients_list: 系数列表
    :param modulus_input: 模数
    :return: Polynomial 对象
    """
    # 打印输入数据，帮助调试
    # print(f"收到的系数列表: {coefficients_list}, 模数: {q_input}")

    if not isinstance(coefficients_list, list) or not isinstance(q_input, int):
        raise ValueError("输入格式必须为 [系数列表], 模数，例如 [1, 2, 3], 12289")

    # 校验模数是否与固定的 modulus 一致
    if q_input != q:
        raise ValueError(f"输入的模数 ({q_input}) 与固定模数 ({q}) 不一致。")

    # 解析系数为字典形式
    coefficients = {i: coef for i, coef in enumerate(coefficients_list)}

    # 创建 Polynomial 对象
    return Polynomial(lp, coefficients)




# 用法：变量 = 对象.add2(poly1.lp, p1)
def to_Polynomial(lp, ntt_representation, apply_mod_correction=True):
    """
    将 add_new 返回的 ntt_representation 处理成一个完整的 Polynomial 对象。

    :param lp: LatticeParameters 对象
    :type lp: LatticeParameters
    :param ntt_representation: add_new 返回的 ntt_representation
    :type ntt_representation: list
    :param apply_mod_correction: 是否应用模运算修正
    :type apply_mod_correction: bool
    :return: 一个完整的 Polynomial 对象
    :rtype: Polynomial
    """
    # 如果需要模运算修正，则处理每个元素
    if apply_mod_correction:
        corrected_ntt = [
            (val % lp.modulus) - (lp.modulus if val % lp.modulus > lp.halfmod else 0)
            for val in ntt_representation
        ]
    else:
        corrected_ntt = ntt_representation

    # 创建新的 Polynomial 对象
    result = Polynomial(lp, {})
    result.ntt_representation = corrected_ntt
    return result


# 把多项式乘常数分为先乘，后还原两步：scalar_multiply 和 to_Polynomial
def scalar_multiply(poly, scalar):
    """
    对 Polynomial 对象的 ntt_representation 进行标量乘法，返回新的 ntt_representation。

    :param poly: Polynomial 对象
    :type poly: Polynomial
    :param scalar: 标量
    :type scalar: int
    :return: 标量乘法后的 ntt_representation 列表
    :rtype: list
    """
    if not isinstance(poly, Polynomial):
        raise TypeError("First argument must be a Polynomial object")
    if not isinstance(scalar, int):
        raise TypeError("Second argument must be an integer")

    # 点对点标量乘积
    return [x * scalar for x in poly.ntt_representation]

def Gen(w):
    """
    输入:
    w: 字符串（噪音随机源的一次采样）
    输出:
    R: 固定的密钥 '1234123412341234'
    P: 公开的帮助串，模拟为 w 的长度
    """
    sigma_i = '1234123412341234' # 固定密钥
    P = len(w) # 帮助串，用 w 的长度作为示例
    return P, sigma_i
def MAC16(key, message):
    # 使用 HMAC-SHA256 生成哈希值
    full_mac = hmac.new(key, message, hashlib.sha256).digest()
    # 截取前 16 位（2 字节）
    mac16 = full_mac[:2]
    return mac16


# 再生算法 Rep
def Rep(w_prime, P):
    """
    输入:
    w_prime: 字符串（噪音随机源的另一次采样）
    P: 帮助串，模拟为 w 的长度
    输出:
    R': 再生的密钥，固定为 '1234123412341234'
    """
    # 模拟使用帮助串 P 校正 w_prime 的过程（这里直接略过）
    sigma_i1 = '1234123412341234' # 再生的密钥，与生成密钥相同
    return sigma_i1


def calculate_16bit_binary_sha256(hex_input):
    """
    计算 SHA-256 哈希值并将其转换为固定 16 位的二进制
    """
    # 计算 SHA-256 哈希值
    sha256_hash = hashlib.sha256(hex_input.encode('utf-8')).hexdigest()

    # 提取前 2 个十六进制字符 (16 位二进制 = 2 字节十六进制)
    short_hex = sha256_hash[:4]

    # 转换为二进制并补齐为 16 位
    binary_16bit = bin(int(short_hex, 16))[2:].zfill(16)

    return binary_16bit


def to_hex_string(self):
        """
        将 Polynomial 对象转换为 16 位二进制字符串
        """
        # 获取 NTT 表示的系数
        coeffs = self.ntt_representation

        # 将每个系数转换为 16 位二进制并拼接为一个字符串
        bin_coefficients = [bin(c & 0xFFFF)[2:].zfill(16) for c in coeffs]  # 每个系数转换为16位二进制

        # 拼接所有二进制字符串
        bin_string = ''.join(bin_coefficients)

        # 截取或填充至16位
        return bin_string[:16].ljust(16, '0')