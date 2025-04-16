import socket
import numpy as np
from she import RLWE, Rq
import re
import time
from she.function import *
import hashlib
import pickle
import struct
import Encrypted_communications as EC
# 创建一个TCP套接字
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = EC.E_C(256, ip="192.168.1.104", port=6666)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# 绑定主机和端口
server_socket.bind(('1192.168.1.104', 6666))

# 监听连接
server_socket.listen()

# print("Server is listening for incoming connections...")

# 接受客户端连接
# print("Waiting to accept a connection...")
client_socket, client_address = server_socket.accept()
# print(f"Connection established with {client_address}")

# 接收数据
data = client_socket.recv(1024)
# print(f"已收到注册请求: {data.decode('utf-8')}")

# 消息发送过程中需要将String和类对象不停转换，可以用repr将对象转字符串，以下两个函数可以将字符串恢复对象
def Hash_1(message):
    hash_hex = server.sha256(message)

    # 将十六进制哈希值转换为整数数组（每个字符当作一个 16 进制数字）
    coeffs = [int(c, 16) for c in hash_hex[:32]]  # 取前 32 个字符作为系数

    # 设置模数 q，与程序其他部分保持一致
    q = 12289

    # 返回一个 Rq 对象
    return Rq(coeffs, q)



    #=====================================初始化、注册阶段=====================================


n = 512
q = 12289
# n = 256
# q = 7681
std = 3.192
length = 1
lp = LatticeParameters(n, length, q)
rlwe = RLWE(n, q, 2, std)
ID_Ui = '1111111111111111'
P_ID='1212121212121212'
T2 = "2024112300000000"
e_j_coef = discrete_gaussian(n, q, std=std)
s_j_coef = discrete_gaussian(n, q, std=std)
alpha_coef = discrete_gaussian(n, q, std=std)
x_coef = discrete_gaussian(n, q, std=std) # 论文中没说怎么来的，这是S端的主密钥
c_coef = discrete_gaussian(n, q, std=std)

e_j = get_Polynomial(n,q,e_j_coef)
s_j = get_Polynomial(n,q,s_j_coef)
alpha = get_Polynomial(n,q,alpha_coef)
x = get_Polynomial(n,q,x_coef)
c = get_Polynomial(n,q,c_coef)

ejrmul2=scalar_multiply(e_j,2)
ejrmul2=to_Polynomial(lp,ejrmul2)
PK_j = alpha*s_j + ejrmul2
PK_j=to_Polynomial(lp,PK_j)



strs_j=repr(s_j)
KU_i=calculate_16bit_binary_sha256(server.sha256(P_ID+str(s_j)))
au='1111111111111111'


# =================开始第一次接收===================
# 先接收 8 个字节（总长度和PID的长度）
lengths = b''
while len(lengths) < 8:
    more = client_socket.recv(8 - len(lengths))
    if not more:
        raise RuntimeError("Socket connection broken")
    lengths += more

# 使用 struct.unpack 解包长度信息
total_length, RID_Ui_length = struct.unpack('!II', lengths)

# 接收合并后的字节流
received_message1 = b''
while len(received_message1) < total_length:
    more = client_socket.recv(min(1024, total_length - len(received_message1)))
    if not more:
        raise RuntimeError("Socket connection broken")
    received_message1 += more

# 拆分
received_RID_Ui = received_message1[:RID_Ui_length]
received_m1 = received_message1[RID_Ui_length:]

# 反序列化
RID_Ui = deserialize_object(received_RID_Ui)
m1 = deserialize_object(received_m1)

# print(f"Received RID_Ui: {RID_Ui}")
# print(f"Received G_u异或rn_Ui {m1}")
# print("=========第一次消息（RID_Ui、G_u异或rn_Ui）接收成功==========")

G1 = calculate_16bit_binary_sha256(str(RID_Ui) + str(x))
G2 = server.xor(G1, m1)

# S端发送G2
# 将G2序列化成为字节流，先发送数据长度
# print(f"发走的G2是{G2}")
message_G2 = serialize_object(G2)
G2_length = len(message_G2)
client_socket.sendall(str(G2_length).encode('utf-8'))  # 发送数据长度
ack = client_socket.recv(16)  # 等待确认
# 发送数据m
client_socket.sendall(message_G2)
# print("=========第二次消息（G2）发送成功==========")

# =====================================登录、认证阶段=====================================
# =======开始接收5条消息=========
# 接收 5 个变量的长度信息（每个 4 字节，共 20 字节）
lengths = b''
while len(lengths) < 20:  # 20 = 5 个整数，每个 4 字节
    more = client_socket.recv(20 - len(lengths))
    if not more:
        raise RuntimeError("Socket connection broken while receiving lengths.")
    lengths += more
T_co2 = time.perf_counter()


# 解包长度信息
X_u_length, G_w_length, G3_length, C_u_length, T1_length = struct.unpack('!IIIII', lengths)

# 计算总长度
total_length = X_u_length + G_w_length + G3_length + C_u_length + T1_length

# 接收打包的消息
received_message = b''
T_co3 = time.perf_counter()
while len(received_message) < total_length:
    more = client_socket.recv(min(1024, total_length - len(received_message)))
    if not more:
        raise RuntimeError("Socket connection broken while receiving packed data.")
    received_message += more
T_co4 = time.perf_counter()
T_com1 = T_co4 - T_co3

# 根据长度拆分消息
received_X_u = received_message[:X_u_length]
received_G_w = received_message[X_u_length:X_u_length + G_w_length]
received_G3 = received_message[X_u_length + G_w_length:X_u_length + G_w_length + G3_length]
received_C_u = received_message[X_u_length + G_w_length + G3_length:X_u_length + G_w_length + G3_length + C_u_length]
received_T1 = received_message[X_u_length + G_w_length + G3_length + C_u_length:]

# 反序列化 5 条消息
X_u = deserialize_object(received_X_u)
G_w = deserialize_object(received_G_w)
G3 = deserialize_object(received_G3)
C_u = deserialize_object(received_C_u)
T1 = deserialize_object(received_T1)

# 打印接收到的变量
# print(f"Received X_u: {X_u}")
# print(f"Received G_w: {G_w}")
# print(f"Received G3: {G3}")
# print(f"Received C_u: {C_u}")
# print(f"Received T1: {T1}")
#
# print("=========登录认证第一次5条消息接收成功==========")

t1 = time.perf_counter()
K_u_new = x * X_u
t2 = time.perf_counter()
T_mul1 = t2-t1

T_m1 = time.perf_counter()
M_u_new = robust_extractor(K_u_new, C_u, q)
T_m2 = time.perf_counter()
T_mod1 = T_m2-T_m1  # 第一次模2计时\

M_u_new = to_Polynomial(lp, M_u_new)
M_u_str = to_hex_string(M_u_new)
X_u_str = to_hex_string(X_u)


T_ha1 = time.perf_counter()
RID_Ui = server.xor(G3, calculate_16bit_binary_sha256(str(server.xor(M_u_str, X_u_str))))
G_w_star = calculate_16bit_binary_sha256(str(G3) + X_u_str + M_u_str + str(RID_Ui)+str(T1))
T_ha2 = time.perf_counter()
T_hash1 = T_ha2-T_ha1  # 第1、2次哈希时间

T_samp1 = time.perf_counter()
r_s_coef = discrete_gaussian(n, q, std=std)
f_s_coef = discrete_gaussian(n, q, std=std)
T_samp2 = time.perf_counter()
print(f"S端2次高斯采样：{(T_samp2-T_samp1)* 1e3:.5f}ms")

r_s = get_Polynomial(n,q,r_s_coef)
f_s = get_Polynomial(n,q,f_s_coef)

T3 = time.perf_counter()
cmuls = c * r_s
T4 = time.perf_counter()
T_mul2 = T4-T3

T5 = time.perf_counter()
firul2 = scalar_multiply(f_s, 2)
T6 = time.perf_counter()
T_rul1 = T6-T5 # 标量乘计时
print(f"S端1次标量乘：{(T6-T5)* 1e3:.5f}ms")
firul2 = to_Polynomial(lp, firul2)


T7 = time.perf_counter()
X_s = cmuls + firul2
T8 = time.perf_counter()
T_add1 = T6-T5
X_s = to_Polynomial(lp, X_s)
print(f"S端1次多项式加法：{(T_add1)* 1e3:.5f}ms")

T9 = time.perf_counter()
K_s = r_s * X_u
T10 = time.perf_counter()
T_mul3 = T10 - T9
print(f"S端3次多项式乘法：{(T_mul3+T_mul2+T_mul1)* 1e3:.5f}ms")

T_c1 = time.perf_counter()
C_s = signal_function(K_s)
T_c2 = time.perf_counter()
T_Cha = T_c2-T_c1
print(f"S端1次信号值计算：{(T_Cha)* 1e3:.5f}ms")

T_m3 = time.perf_counter()
M_s = robust_extractor(K_s, C_s, q)
T_m4 = time.perf_counter()
T_mod2 = T_m4-T_m3  # 第2次模2计时
# print(f"S端两次模2计算总时间为：{(T_mod2+T_mod1)* 1e3:.5f}ms")

x_str = to_hex_string(x)

T_ha3 = time.perf_counter()
G1 = calculate_16bit_binary_sha256(str(ID_Ui) + x_str)
T_ha4 = time.perf_counter()
T_hash2 = T_ha4 - T_ha3


X_s_str = to_hex_string(X_s)
SK = G1+X_u_str+X_s_str+M_u_str+str(M_s)+T1+T2

T_ha5 = time.perf_counter()
G_z = calculate_16bit_binary_sha256(str(SK) + str(G1)+str(X_s_str)+str(M_u_str)+str(M_u_str)+str(T2))
T_ha6 = time.perf_counter()
T_hash3 = T_ha6 - T_ha5
print(f"S端4次哈希：{(T_hash3+T_hash2+T_hash1)* 1e3:.5f}ms")
print("=================================")
print(f"total_S:{((T_hash3+T_hash2+T_hash1)+T_Cha+(T_mul3+T_mul2+T_mul1)+T_add1+(T6-T5)+(T_samp2-T_samp1))* 1e3:.5f}ms")
print("=================================")

# 开始认证阶段的第2次消息发送
# 序列化 4 个变量
G_z_send = serialize_object(G_z)
C_s_send = serialize_object(C_s)
X_s_send = serialize_object(X_s)
T2_send = serialize_object(T2)

# 计算每个变量的字节流长度
G_z_length = len(G_z_send)
C_s_length = len(C_s_send)
X_s_length = len(X_s_send)
T2_length = len(T2_send)

# 打包 4 个长度信息
lengths = struct.pack('!IIII', G_z_length, C_s_length, X_s_length, T2_length)

client_socket.sendall(lengths)  # 发送长度信息
T_co5=time.perf_counter()
# 发送合并后的字节流
client_socket.sendall(G_z_send + C_s_send + X_s_send + T2_send)  # 合并并发送所有变量
T_co6=time.perf_counter()
T_com2=T_co6-T_co5

# print(f"发送的 G_z: {G_z}")
# print(f"发送的 C_s: {C_s}")
# print(f"发送的 X_s: {X_s}")
# print(f"发送的 T2: {T2}")
#
# print("=========登录认证第二次4条消息发送成功==========")
print("通信时间1",T_com1*1e3)
print("通信时间2",T_com2*1e3)
print(f"S2次通信总时间为：{(T_com1+T_com2)* 1e3:.5f}ms")

# 通信时间1 0.04300000000023729
# 通信时间2 0.037599999999748945
# 总通信时间 0.08059999999998624
client_socket.close()


