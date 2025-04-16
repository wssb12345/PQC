# coding: utf-8
import socket
import time

import ecc.elliptic
from ecc.elliptic import mulp, add, neg
from encryption import sha256,sha384,md5,aes_decode,aes_encode,base64_e,base64_d
from ecc.Key import Key
from ecc.ecdsa import randkey
import base64
from Crypto.Cipher import AES  # 注：python3 安装 Crypto 是 pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple pycryptodome<br><br>
import hashlib
# prearranged=1#服务器随所能允许的中断数，实验里协议肯定要跑通所以这里设置为1
DOMAINS = {
    # Bits : (p, order of E(GF(P)), parameter b, base point x, base point y)
    192: (0xfffffffffffffffffffffffffffffffeffffffffffffffff,
          0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
          0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
          0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
          0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811),

    224: (0xffffffffffffffffffffffffffffffff000000000000000000000001,
          0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
          0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
          0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
          0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34),

    256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
          0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
          0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
          0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),

    384: (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
          0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
          0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
          0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
          0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),

    521: (
        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
        0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
}
class E_C:

    def __init__(self,curve,ip,port):
        p, n, B, G_x, G_y = DOMAINS[curve]
        self.A = 0x3
        self.B = p-B
        self.P = p
        self.N = n
        self.G = [G_x,G_y]
        self.curve = curve
        self.ip=ip
        self.port=port

    def key(self):
        # 生成密钥对
        keypair = Key.generate(self.curve)
        Q_x = keypair._pub[1][0]
        Q_y = keypair._pub[1][1]
        Q = (Q_x, Q_y)
        private_key = keypair._priv[1]
        return(private_key,Q)

    def bulid_connection_s(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 左中右对应family这里选的是IPV4，type这里选择的是流式socket应用于TCP，后面的参数默认即可
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.ip, self.port))
        # 绑定地址(HOST,PORT)到套接字，在IPV4下该套接字表示接口号
        s.listen(10)
        # 开启监听，操作系统最大的挂起连接量，参数值至少为1
        connection, address = s.accept()
        # 被动接受TCP客户端连接,(阻塞式)等待连接的到来。
        # connection是套接字对象类型，用以进行后面的信息传递，address为客户端的地址和端口号的套接字
        return connection
    def bulid_connection_u(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1)
        # 如果flag为0，则将套接字设为非阻塞模式，否则将套接字设为阻塞模式（默认值）。
        # 非阻塞模式下，如果调用recv()没有发现任何数据，或send()调用无法立即发送数据，那么将引起socket.error异常。
        s.connect((self.ip, self.port))
        # 主动初始化TCP服务器连接，一般address的格式为元组（hostname,port），如果连接出错，返回socket.error错误。
        return s
    def send_s(self,message,connection):
        message=message.encode()
        connection.send(message)
    def recv_s(self,connection):
        message=(connection.recv(2048)).decode()
        return message
    def send_u(self,message,s):
        message=message.encode()
        s.send(message)
    def recv_u(self,s):
        message=(s.recv(2048)).decode()
        return message
    def sha256(self,message):
        h = hashlib.sha256()
        h.update(message.encode('utf-8'))
        return h.hexdigest()
    def sha384(self,message):
        h = hashlib.sha384()
        h.update(message.encode('utf-8'))
        return h.hexdigest()
    def md5(self,message):
        h = hashlib.md5()
        h.update(message.encode('utf-8'))
        return h.hexdigest()
    def aes_decode(self,data, key):
        aes = AES.new(str.encode(key), AES.MODE_ECB)  # 初始化加密器
        decrypted_text = aes.decrypt(base64.decodebytes(bytes(data, encoding='utf8'))).decode("utf8")  # 解密
        decrypted_text = decrypted_text[:-ord(decrypted_text[-1])]  # 去除多余补位
        return decrypted_text
    def aes_encode(self,data, key):
        while len(data) % 16 != 0:  # 补足字符串长度为16的倍数
            data += (16 - len(data) % 16) * chr(16 - len(data) % 16)
        data = str.encode(data)
        aes = AES.new(str.encode(key), AES.MODE_ECB)  # 初始化加密器
        return str(base64.encodebytes(aes.encrypt(data)), encoding='utf8').replace('\n', '')  # 加密
    def base64_e(self,data):
        data = str.encode(data)
        message = base64.encodebytes(data)
        return message
    def base64_d(self,data):
        data = str.encode(data)
        message = base64.decodebytes(data)
        return message
    def rand(self):
        return randkey(self.curve,self.P)
    def mul(self,key):
        key=key%int(self.P)
        print(key)
        return mulp(self.A, self.B, self.P, self.G, key)
    def mul_public(self, key,public):
        key=key%int(self.P)
        print(key)
        return mulp(self.A, self.B, self.P, public, key)
    def neg(self,pkux,pkuy):
        return neg((pkux,pkuy),self.P)
    def gen(self,B_u):
        sigma_u=md5(B_u)
        tau_u=sha256(B_u)
        return sigma_u,tau_u
    def xor(self,x,y):
        if(type(x)==int):
            x = x
        if(type(x)==str):
            for i in range(0,len(x)):
                if(x[i].isalpha()):
                    x=int(x,16)
                    break
                if i==len(x)-1:
                    x=int(x)
        if (type(y) == int):
            y = y
        if (type(y) == str):
            for i in range(0,len(y)):
                if (y[i].isalpha()):
                    y = int(y,16)
                    break
                if i == len(y)-1:
                    y = int(y)
        return(x^y)
    def verify(self,x,y):
        if(x==y):
            return 1
        else:
            return 0
    def add(self,x,y):
        return list(add(self.A, self.B, self.P,x,y))

