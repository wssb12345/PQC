import socket
import numpy as np
from she import RLWE, Rq
from she.function import *
import re
import time
import random
import hashlib
import pickle
import struct
import Encrypted_communications as EC

# 创建一个TCP套接字
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
user = EC.E_C(256, ip="192.168.1.104", port=6666)
# 连接服务器
# print("Connecting to server...")
client_socket.connect(('192.168.1.104', 6666))
# print("Connected to server.")
# 发送数据
message = "Registration request"
client_socket.send(message.encode('utf-8'))
# print("Sent registration request.")

def Hash_1(message):
    hash_hex = user.sha256(message)

    # 将十六进制哈希值转换为整数数组（每个字符当作一个 16 进制数字）
    coeffs = [int(c, 16) for c in hash_hex[:32]]  # 取前 32 个字符作为系数

    # 设置模数 q，与程序其他部分保持一致
    q = 12289

    # 返回一个 Rq 对象
    return Rq(coeffs, q)



# =====================================初始化、注册阶段=====================================

# 发送注册请求
message = "Registration request"
ID_Ui = '1111111111111111'
ID_i = '2222222222222222'
PW_i = '1111111111111111'
Bio_i = '1231321111111111'
Bio_i1 = '1231321111111111'
T1 = "2024112300000000"

n = 512
q = 12289
# n = 256
# q = 7681
std = 3.192
length = 1
lp = LatticeParameters(n, length, q)
rlwe = RLWE(n, q, 2, std)
e_i_coef = discrete_gaussian(n, q, std=std)
s_i_coef = discrete_gaussian(n, q, std=std)
alpha_coef = discrete_gaussian(n, q, std=std)
alpha_Ui = '1231321111111111'
c_coef = discrete_gaussian(n, q, std=std)

e_i = get_Polynomial(n,q,e_i_coef)
s_i = get_Polynomial(n,q,s_i_coef)
alpha = get_Polynomial(n,q,alpha_coef)
c = get_Polynomial(n,q,c_coef)

rn_Ui = random.randint(0, 2**16 - 1) #随机生成16比特的随机数
eirmul2=scalar_multiply(e_i,2)
eirmul2=to_Polynomial(lp,eirmul2)
P_i = alpha*s_i + eirmul2
P_i = to_Polynomial(lp ,P_i)



RID_Ui = calculate_16bit_binary_sha256(ID_Ui + str(alpha_Ui))
G_u = calculate_16bit_binary_sha256(ID_i + PW_i)
m1 = user.xor(G_u, rn_Ui)
# print(f"发送出去的RID_Ui：{RID_Ui}")
# print(f"发送出去的G_u异或rn_Ui：{m1}")
# ===== 开始第一次发送========
RID_Ui = serialize_object(RID_Ui)#序列化
m1 = serialize_object(m1)

# 计算两个字节流的长度
RID_Ui_length = len(RID_Ui)
m1_length = len(m1)
# 将总长度（p_A_length + u_A_length）和 p_A_length 打包
lengths = struct.pack('!II', RID_Ui_length + m1_length, RID_Ui_length)
client_socket.sendall(lengths)  # 发送长度信息
client_socket.sendall(RID_Ui+m1)# 发送合并后的字节流
# print("=========第一次消息（RID_Ui、G_u异或rn_Ui）发送成功==========")
m1 = deserialize_object(m1)  # 之前为了发送而序列化，现在进行还原
RID_Ui = deserialize_object(RID_Ui)


# 开始接收G2
# 首先接收数据长度
G2_length = int(client_socket.recv(1024).decode('utf-8'))
client_socket.sendall(b'ACK')  # 发送确认信息
# 然后接收指定长度的数据
message_G2 = b''
while len(message_G2) < G2_length:
    message_G2 += client_socket.recv(1024)

G2 = deserialize_object(message_G2)
# print(f"收到的的G2是{G2}")
# print("=========第二次消息（G2）接收成功==========")
G1 = user.xor(G2, m1)
alpha_star_Ui = user.xor(alpha_Ui, calculate_16bit_binary_sha256(str(G_u) + str(G1)))
G_v = calculate_16bit_binary_sha256(ID_Ui + PW_i + str(G1) + alpha_Ui)
G2_new = user.xor(G2, rn_Ui)


# =====================================登录、认证阶段=====================================
T_ha1 = time.perf_counter()
G_u = calculate_16bit_binary_sha256(ID_Ui + PW_i)
T_ha2 = time.perf_counter()
T_hash1 = T_ha2-T_ha1  # 第一次哈希时间

G1_new = user.xor(G2, G_u)


T_ha3 = time.perf_counter()
x = ID_Ui + PW_i + str(G1_new) + alpha_Ui
h11 = calculate_16bit_binary_sha256(G_u + str(G1_new))
RID_Ui = calculate_16bit_binary_sha256(ID_Ui + alpha_Ui)
G_v_new = calculate_16bit_binary_sha256(x)
T_ha4 = time.perf_counter()
T_hash2 = T_ha4-T_ha3  # 第2、3、4次哈希时间
alpha_Ui = user.xor(str(alpha_star_Ui), h11)


T_samp1 = time.perf_counter()
r_i_coef = discrete_gaussian(n, q, std=std)
f_i_coef = discrete_gaussian(n, q, std=std)
T_samp2 = time.perf_counter()
print(f"U端2次高斯采样：{(T_samp2-T_samp1)* 1e3:.5f}ms")

r_i = get_Polynomial(n,q,r_i_coef)
f_i = get_Polynomial(n,q,f_i_coef)

t1 = time.perf_counter()
cmulr = c * r_i
t2 = time.perf_counter()
T_mul1 = t2-t1

T3 = time.perf_counter()
firul2 = scalar_multiply(f_i, 2)
T4 = time.perf_counter()
T_rul1 = T4-T3
print(f"U端1次标量乘：{(T_rul1)* 1e3:.5f}ms")
firul2 = to_Polynomial(lp, firul2)


T5 = time.perf_counter()
X_u = cmulr+firul2
T6 = time.perf_counter()
T_add1 = T6-T5
X_u = to_Polynomial(lp, X_u)
print(f"U端1次多项式加法：{(T_add1)* 1e3:.5f}ms")

T7 = time.perf_counter()
K_u = r_i * P_i
T8 = time.perf_counter()
T_mul2 = T8-T7


T_c1 = time.perf_counter()
C_u = signal_function(K_u)
T_c2 = time.perf_counter()
T_Cha = T_c2-T_c1
print(f"U端1次信号函数：{(T_Cha)* 1e3:.5f}ms")


T_m1 = time.perf_counter()
M_u = robust_extractor(K_u, C_u, q)
T_m2 = time.perf_counter()
T_mod1 = T_m2-T_m1 # 第一次模2计时
M_u = to_Polynomial(lp, M_u)


# 异或前置准备，类对象转成16进制字符串
M_u_str = to_hex_string(M_u)
X_u_str = to_hex_string(X_u)

T_ha5 = time.perf_counter()
h22 = calculate_16bit_binary_sha256(M_u_str + X_u_str)
T_ha51 = time.perf_counter()
G3 = user.xor(RID_Ui, h22)
x2 = str(G3) + X_u_str + M_u_str + RID_Ui+T1
T_ha52 = time.perf_counter()
G_w = calculate_16bit_binary_sha256(x2)
T_ha6 = time.perf_counter()
T_hash3 = (T_ha6-T_ha52)+(T_ha51 - T_ha5)  # 第5、6次哈希时间


G_w_1 = G_w
C_u_1 = C_u


# =======开始发送5条消息=========
# 序列化 5 个变量
X_u = serialize_object(X_u)
G_w_1 = serialize_object(G_w_1)
G3 = serialize_object(G3)
C_u_1 = serialize_object(C_u_1)
T1 = serialize_object(T1)

# 计算每个变量的字节流长度
X_u_length = len(X_u)
G_w_1_length = len(G_w_1)
G3_length = len(G3)
C_u_1_length = len(C_u_1)
T1_length = len(T1)

# 打包 5 个长度信息
lengths = struct.pack('!IIIII', X_u_length, G_w_1_length, G3_length, C_u_1_length, T1_length)

client_socket.sendall(lengths)  # 发送长度信息
T_co1=time.perf_counter()
# 发送合并后的字节流
client_socket.sendall(X_u + G_w_1 + G3 + C_u_1 + T1)  # 合并并发送所有变量
T_co2=time.perf_counter()
T_com1=T_co2-T_co1


X_u = deserialize_object(X_u)
G3 = deserialize_object(G3)
T1 = "2024112300000000"
# print(f"发送的 X_u: {X_u}")
# print(f"发送的 G_w: {G_w}")
# print(f"发送的 G3: {G3}")
# print(f"发送的 C_u: {C_u}")
# print(f"发送的 T1: {T1}")
# print(f"c{c}")
# print("=========登录认证第一次5条消息发送成功==========")
#
# 开始接收消息
# 接收 4 个变量的长度信息（每个 4 字节，共 16 字节）
lengths = b''
T_co3=time.perf_counter()
while len(lengths) < 16:  # 16 = 4 个整数，每个 4 字节
    more = client_socket.recv(16 - len(lengths))
    if not more:
        raise RuntimeError("Socket connection broken while receiving lengths.")
    lengths += more
T_co4=time.perf_counter()


# 解包长度信息
G_z_length, C_s_length, X_s_length, T2_length = struct.unpack('!IIII', lengths)

# 计算总长度
total_length = G_z_length + C_s_length + X_s_length + T2_length

# 接收打包的消息
received_message = b''
T_co5 = time.perf_counter()
while len(received_message) < total_length:
    more = client_socket.recv(min(1024, total_length - len(received_message)))
    if not more:
        raise RuntimeError("Socket connection broken while receiving packed data.")
    received_message += more
T_co6 = time.perf_counter()
T_com2 = T_co6-T_co5

# 根据长度拆分消息
received_G_z = received_message[:G_z_length]
received_C_s = received_message[G_z_length:G_z_length + C_s_length]
received_X_s = received_message[G_z_length + C_s_length:G_z_length + C_s_length + X_s_length]
received_T2 = received_message[G_z_length + C_s_length + X_s_length:]

# 反序列化 4 条消息
G_z = deserialize_object(received_G_z)
C_s = deserialize_object(received_C_s)
X_s = deserialize_object(received_X_s)
T2 = deserialize_object(received_T2)

# 打印接收到的变量
# print(f"Received G_z_send: {G_z}")
# print(f"Received C_s_send: {C_s}")
# print(f"Received X_s_send: {X_s}")
# print(f"Received T2_send: {T2}")
#
# print("=========登录认证第二次4条消息接收成功==========")
#
T9 = time.perf_counter()
K_s_new = r_i * X_s
T10 = time.perf_counter()
T_mul3 = T10-T9
print(f"u端3次多项式乘法：{(T_mul3+T_mul1+T_mul2)* 1e3:.5f}ms")

T_m3 = time.perf_counter()
M_s_new = robust_extractor(K_s_new, C_s, q)
T_m4 = time.perf_counter()
T_mod2 = T_m4-T_m3  # 第2次模2计时
# print(f"U端模2计算：{(T_mod2+T_mod1)* 1e3:.5f}ms")



X_s_str = to_hex_string(X_s)
x3 = str(G1) + X_u_str+X_s_str+M_u_str+str(M_s_new)+T1+str(T2)
x4 = str(G1)+X_s_str+str(M_s_new)+M_u_str+str(T2)
T_ha7 = time.perf_counter()
SK_new = calculate_16bit_binary_sha256(x3)
G_z_new = calculate_16bit_binary_sha256(SK_new + x4)
T_ha8 = time.perf_counter()
T_hash4 = T_ha8-T_ha7  # 第7、8次哈希时间
print(f"U端8次hash：{(T_hash1+T_hash2+T_hash3+T_hash4)* 1e3:.5f}ms")

print("=================================")
print(f"total_U:{((T_hash1+T_hash2+T_hash3+T_hash4)+(T_mul3+T_mul1+T_mul2)+T_Cha+T_add1+T_rul1+(T_samp2-T_samp1))* 1e3:.5f}ms")
print("=================================")


print("通信时间1",T_com1*1e3)
print("通信时间2",T_com2*1e3)
print(f"U端2次通信总时间为：{(T_com1+T_com2)* 1e3:.5f}ms")
# print(f"S端计算出来的会话秘钥为：{SK_new}")
# print("T_mul",T_mul3+T_mul1+T_mul2)
# print("T_add",T_add1)
# print("T_rmul",T_rul1)
# T_compute=T_mul3+T_mul1+T_mul2+T_rul1+T_add1+T_mod2+T_mod1+T_hash1+T_hash2+T_hash3+T_hash4
# print(T_compute)

# 通信时间1 0.03780000000008776
# 通信时间2 0.0450999999999091
# U端3次通信总时间为：0.08290ms
client_socket.close()
