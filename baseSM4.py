import os
import struct
from typing import List

#SM常量定义
SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
]

#S盒
SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]


class SM4:
    def __init__(self):
        # 初始化T表
        self._init_t_tables()

    def _init_t_tables(self):
        # 初始化T表用于优化
        self.T1 = [0] * 256
        self.T2 = [0] * 256
        self.T3 = [0] * 256
        self.T4 = [0] * 256

        for i in range(256):
            # 计算S盒输出
            s = SM4_SBOX[i]

            # 计算T1表 - 用于加密轮函数
            t = self._l_transform(s << 24)
            self.T1[i] = t

            # 计算T2表 - 用于密钥扩展
            t = self._l_prime_transform(s << 24)
            self.T2[i] = t

            # 计算T3和T4表 - 用于加密轮函数
            self.T3[i] = t >> 8
            self.T4[i] = t >> 16

    def _sbox(self, x: int) -> int:
        # S盒替换
        return SM4_SBOX[x & 0xFF]

    def _l_transform(self, x: int) -> int:
        # 线性变换L
        return x ^ ((x << 2) | (x >> 30)) ^ ((x << 10) | (x >> 22)) ^ ((x << 18) | (x >> 14)) ^ ((x << 24) | (x >> 8))

    def _l_prime_transform(self, x: int) -> int:
        # 线性变换L' - 用于密钥扩展
        return x ^ ((x << 13) | (x >> 19)) ^ ((x << 23) | (x >> 9))

    def _round_function(self, x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
        # 轮函数
        # 计算S盒输入
        tmp = x1 ^ x2 ^ x3 ^ rk

        # 四个S盒并行处理
        b0 = self._sbox(tmp >> 24)
        b1 = self._sbox((tmp >> 16) & 0xFF)
        b2 = self._sbox((tmp >> 8) & 0xFF)
        b3 = self._sbox(tmp & 0xFF)

        # 线性变换L
        return x0 ^ self._l_transform((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)

    def _key_expansion(self, key: bytes) -> List[int]:
        # 密钥扩展算法
        # 初始密钥处理
        k = list(struct.unpack(">IIII", key))
        k = [k[i] ^ SM4_FK[i] for i in range(4)]

        # 轮密钥
        rk = [0] * 32

        # 生成32轮密钥
        for i in range(32):
            # 计算S盒输入
            tmp = k[1] ^ k[2] ^ k[3] ^ SM4_CK[i]

            # 四个S盒并行处理
            b0 = self._sbox(tmp >> 24)
            b1 = self._sbox((tmp >> 16) & 0xFF)
            b2 = self._sbox((tmp >> 8) & 0xFF)
            b3 = self._sbox(tmp & 0xFF)

            # 线性变换L'
            k_new = k[0] ^ self._l_prime_transform((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)

            # 更新轮密钥和密钥状态
            rk[i] = k_new
            k = k[1:] + [k_new]

        return rk

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        # 加密单个数据块(16字节)
        # 检查输入长度
        if len(plaintext) != 16 or len(key) != 16:
            raise ValueError("Plaintext and key must be 16 bytes long")

        # 解析输入为四个32位整数
        x = list(struct.unpack(">IIII", plaintext))

        # 密钥扩展
        rk = self._key_expansion(key)

        # 32轮加密
        for i in range(32):
            x.append(self._round_function(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]))

        # 最终变换
        ciphertext = x[32:]
        ciphertext.reverse()

        # 转换为字节
        return struct.pack(">IIII", *ciphertext)

    def decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        # 解密单个数据块(16字节)
        # 解密与加密过程相同，只是轮密钥顺序相反
        rk = self._key_expansion(key)
        rk.reverse()
        return self.encrypt_block(ciphertext, key)

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
        # 加密数据（ECB模式）
        # 检查密钥长度
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")

        # 填充数据到16字节的倍数
        padded_plaintext = self._pkcs7_padding(plaintext)

        # 分块加密
        ciphertext = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i + 16]
            ciphertext += self.encrypt_block(block, key)

        return ciphertext

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        # 解密数据（ECB模式）
        # 检查密钥长度和密文长度
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")

        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16")

        # 分块解密
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            plaintext += self.decrypt_block(block, key)

        # 去除填充
        return self._pkcs7_unpadding(plaintext)

    def _pkcs7_padding(self, data: bytes) -> bytes:
        # PKCS#7填充
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length]) * padding_length
        return data + padding

    def _pkcs7_unpadding(self, data: bytes) -> bytes:
        # PKCS#7去填充
        padding_length = data[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding")
        for i in range(1, padding_length + 1):
            if data[-i] != padding_length:
                raise ValueError("Invalid padding")
        return data[:-padding_length]

if __name__ == "__main__":
    sm4 = SM4()

    # 128位密钥和明文
    key = os.urandom(16)
    plaintext = b"Hello, SM4 encryption!"

    # 加密
    ciphertext = sm4.encrypt(plaintext, key)
    print(f"明文: {plaintext}")
    print(f"密文: {ciphertext.hex()}")

    # 解密
    decrypted = sm4.decrypt(ciphertext, key)
    print(f"解密后: {decrypted}")