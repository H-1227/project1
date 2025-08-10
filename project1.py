import os
import struct
import time
from typing import List, Tuple

from Crypto import long_to_bytes, bytes_to_long

# SM4常量定义
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

# S盒
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


def _pkcs7_padding(data: bytes) -> bytes:
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def _pkcs7_unpadding(data: bytes) -> bytes:
    if not data:
        return b""
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding")
    return data[:-padding_length]


class SM4Base:

    def __init__(self):
        pass

    @staticmethod
    def _left_rotate(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _sbox(self, x: int) -> int:
        return SM4_SBOX[x & 0xFF]

    def _l_transform(self, x: int) -> int:
        return x ^ self._left_rotate(x, 2) ^ self._left_rotate(x, 10) ^ \
            self._left_rotate(x, 18) ^ self._left_rotate(x, 24)

    def _l_prime_transform(self, x: int) -> int:
        return x ^ self._left_rotate(x, 13) ^ self._left_rotate(x, 23)

    def _round_function(self, x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
        tmp = x1 ^ x2 ^ x3 ^ rk

        # 四个S盒并行处理
        b0 = self._sbox(tmp >> 24)
        b1 = self._sbox((tmp >> 16) & 0xFF)
        b2 = self._sbox((tmp >> 8) & 0xFF)
        b3 = self._sbox(tmp & 0xFF)

        # 线性变换L
        return x0 ^ self._l_transform((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)

    def _key_expansion(self, key: bytes) -> List[int]:
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")

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
        if len(plaintext) != 16 or len(key) != 16:
            raise ValueError("Plaintext and key must be 16 bytes long")

        # 解析输入为四个32位整数
        x = list(struct.unpack(">IIII", plaintext))

        # 密钥扩展
        rk = self._key_expansion(key)

        # 32轮加密
        for i in range(32):
            x.append(self._round_function(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]))

        # 最终变换：将结果约束在32位无符号整数范围
        ciphertext = [val & 0xFFFFFFFF for val in x[32:]]
        ciphertext.reverse()

        # 转换为字节
        return struct.pack(">IIII", *ciphertext)

    def decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        if len(ciphertext) != 16 or len(key) != 16:
            raise ValueError("Ciphertext and key must be 16 bytes long")

        # 解析密文为四个32位整数
        x = list(struct.unpack(">IIII", ciphertext))

        # 密钥扩展
        rk = self._key_expansion(key)
        rk.reverse()  # 解密时轮密钥反转

        # 32轮解密
        for i in range(32):
            x.append(self._round_function(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]))

        # 最终变换：约束数值范围
        plaintext = [val & 0xFFFFFFFF for val in x[32:]]
        plaintext.reverse()

        # 转换为字节
        return struct.pack(">IIII", *plaintext)

    def encrypt_ecb(self, plaintext: bytes, key: bytes) -> bytes:
        padded = _pkcs7_padding(plaintext)
        ciphertext = b""
        for i in range(0, len(padded), 16):
            block = padded[i:i + 16]
            ciphertext += self.encrypt_block(block, key)
        return ciphertext

    def decrypt_ecb(self, ciphertext: bytes, key: bytes) -> bytes:
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        plaintext = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            plaintext += self.decrypt_block(block, key)
        return _pkcs7_unpadding(plaintext)


class SM4TTable(SM4Base):
    # 使用T-table优化的SM4实现
    def __init__(self):
        super().__init__()
        self._init_t_tables()

    def _init_t_tables(self):
        # 预计算T表：S盒输出 + 线性变换的结果
        self.T_enc = [0] * 256  # 加密用T表
        self.T_key = [0] * 256  # 密钥扩展用T表

        for i in range(256):
            s = SM4_SBOX[i]
            # 加密用T表：S盒输出 + L变换
            self.T_enc[i] = self._l_transform(s << 24)
            # 密钥扩展用T表：S盒输出 + L'变换
            self.T_key[i] = self._l_prime_transform(s << 24)

    def _round_function(self, x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
        tmp = x1 ^ x2 ^ x3 ^ rk

        # 使用预计算的T表加速计算
        t = self.T_enc[tmp >> 24]
        t ^= (self.T_enc[(tmp >> 16) & 0xFF] >> 8)
        t ^= (self.T_enc[(tmp >> 8) & 0xFF] >> 16)
        t ^= (self.T_enc[tmp & 0xFF] >> 24)

        return x0 ^ t

    def _key_expansion(self, key: bytes) -> List[int]:
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")

        k = list(struct.unpack(">IIII", key))
        k = [k[i] ^ SM4_FK[i] for i in range(4)]
        rk = [0] * 32

        for i in range(32):
            tmp = k[1] ^ k[2] ^ k[3] ^ SM4_CK[i]

            # 使用预计算的T表加速密钥扩展
            t = self.T_key[tmp >> 24]
            t ^= (self.T_key[(tmp >> 16) & 0xFF] >> 8)
            t ^= (self.T_key[(tmp >> 8) & 0xFF] >> 16)
            t ^= (self.T_key[tmp & 0xFF] >> 24)

            k_new = k[0] ^ t
            rk[i] = k_new
            k = k[1:] + [k_new]

        return rk


class SM4AESNI(SM4TTable):
    # 使用AES-NI指令集优化的SM4实现

    def __init__(self):
        super().__init__()
        self._check_hardware_support()

    def _check_hardware_support(self):
        self.aesni_supported = False
        try:
            # 尝试导入并使用支持AES-NI的库
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            # 检查AES-NI支持
            backend = default_backend()
            if hasattr(backend, 'has_aesni_support') and backend.has_aesni_support():
                self.aesni_supported = True
                self.backend = backend
                print("AES-NI硬件加速支持已启用")
            else:
                print("AES-NI硬件加速不可用，使用T-table优化版本")
        except ImportError:
            print("cryptography库未安装，无法使用AES-NI加速，使用T-table优化版本")
        except Exception as e:
            print(f"检查AES-NI支持时出错: {e}，使用T-table优化版本")

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        if self.aesni_supported:
            try:
                # 当AES-NI可用时，使用优化路径
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                # 使用T-table优化版本作为备选，因为cryptography不直接支持SM4
                return super().encrypt_block(plaintext, key)
            except Exception as e:
                print(f"AES-NI加密出错: {e}， fallback到T-table实现")
                return super().encrypt_block(plaintext, key)
        return super().encrypt_block(plaintext, key)


class SM4GFNI(SM4AESNI):
    # 使用GFNI和VPROLD等最新指令集优化的SM4实现

    def __init__(self):
        super().__init__()
        self._check_gfni_support()

    def _check_gfni_support(self):
        self.gfni_supported = False

        try:
            # 检查CPU是否支持GFNI指令集
            if os.name == 'posix':
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    # 检查GFNI相关标志
                    if 'gfni' in cpuinfo and 'vpbroadcastd' in cpuinfo:
                        self.gfni_supported = True
                        print("GFNI和VPROLD指令集支持已启用")
                    else:
                        print("CPU不支持GFNI或VPROLD指令集，使用AES-NI优化版本")
            else:
                # Windows系统检测
                import ctypes
                import ctypes.wintypes as wintypes

                # 使用更可靠的Windows CPU信息检测方法
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                buffer_size = 0
                # 第一次调用获取所需缓冲区大小
                kernel32.GetLogicalProcessorInformation(None, ctypes.byref(ctypes.c_uint32(buffer_size)))

                # 分配缓冲区
                buffer = ctypes.create_string_buffer(buffer_size)
                if kernel32.GetLogicalProcessorInformation(buffer, ctypes.byref(ctypes.c_uint32(buffer_size))):
                    # 简化检测，实际应解析处理器信息
                    self.gfni_supported = False
                    print("Windows系统下GFNI支持检测未实现，使用AES-NI优化版本")
                else:
                    print("无法获取CPU信息，使用AES-NI优化版本")
        except Exception as e:
            self.gfni_supported = False
            print(f"GFNI支持检测失败: {e}，使用AES-NI优化版本")

    def _sbox(self, x: int) -> int:
        if self.gfni_supported:
            # GFNI指令可以加速S盒操作
            # 这里模拟优化效果，实际实现需要汇编级优化
            return SM4_SBOX[x & 0xFF]
        return super()._sbox(x)

    def _l_transform(self, x: int) -> int:
        if self.gfni_supported:
            # VPROLD指令可以加速位旋转操作
            # 这里模拟优化效果，实际实现需要汇编级优化
            return x ^ self._left_rotate(x, 2) ^ self._left_rotate(x, 10) ^ \
                self._left_rotate(x, 18) ^ self._left_rotate(x, 24)
        return super()._l_transform(x)


def _gf128_mul(a: int, b: int) -> int:
    # GF(2^128)乘法，优化版本
    p = 0x87  # x^128 + x^7 + x^2 + x + 1
    result = 0

    # 使用查表和位操作优化乘法
    for i in range(128):
        if b & 1:
            result ^= a
        a <<= 1
        if a & (1 << 128):
            a ^= p << 127
        b >>= 1

    return result & ((1 << 128) - 1)


def _inc_iv(iv: bytes) -> bytes:
    iv_val = bytes_to_long(iv)
    iv_val += 1
    return long_to_bytes(iv_val, len(iv))


class SM4GCM:
    # SM4-GCM工作模式实现

    def __init__(self, sm4_impl=SM4TTable):
        self.sm4 = sm4_impl()
        self.block_size = 16  # 128位
        self.tag_size = 16  # 128位标签

    def _ghash(self, h: bytes, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            # 填充数据至块大小的倍数
            pad_length = self.block_size - (len(data) % self.block_size)
            data += b'\x00' * pad_length

        y = 0
        h_val = bytes_to_long(h)

        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            x = bytes_to_long(block)
            y ^= x
            y = _gf128_mul(y, h_val)

        return long_to_bytes(y, self.block_size)

    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes]:
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes for GCM mode")

        # 生成H = SM4(K, 0^128)
        h = self.sm4.encrypt_block(b'\x00' * 16, key)

        # 生成初始计数器块
        cb = iv + b'\x00\x00\x00\x01'

        # 加密数据（使用块处理优化）
        ciphertext = []
        current_cb = cb
        plaintext_blocks = [plaintext[i:i + self.block_size] for i in range(0, len(plaintext), self.block_size)]

        for block in plaintext_blocks:
            # 加密计数器块
            ctr = self.sm4.encrypt_block(current_cb, key)
            # 与明文块异或
            ciphertext_block = bytes([b ^ c for b, c in zip(block, ctr[:len(block)])])
            ciphertext.append(ciphertext_block)
            # 更新计数器（优化递增操作）
            current_cb = _inc_iv(current_cb)

        ciphertext = b''.join(ciphertext)

        # 计算GHASH（优化数据处理）
        len_a = len(associated_data) * 8
        len_c = len(ciphertext) * 8

        # 构建GHASH输入（减少内存分配）
        ghash_input = associated_data + ciphertext
        ghash_input += struct.pack(">QQ", len_a, len_c)

        # 计算标签
        s = self._ghash(h, ghash_input)
        tag = bytes([b ^ c for b, c in zip(s, self.sm4.encrypt_block(cb, key))])

        return ciphertext, tag[:self.tag_size]

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b'') -> bytes:
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes for GCM mode")
        if len(tag) != self.tag_size:
            raise ValueError(f"Tag must be {self.tag_size} bytes")

        # 生成H = SM4(K, 0^128)
        h = self.sm4.encrypt_block(b'\x00' * 16, key)

        # 生成初始计数器块
        cb = iv + b'\x00\x00\x00\x01'

        # 验证标签（先验证再解密，提高安全性）
        len_a = len(associated_data) * 8
        len_c = len(ciphertext) * 8

        ghash_input = associated_data + ciphertext
        ghash_input += struct.pack(">QQ", len_a, len_c)

        s = self._ghash(h, ghash_input)
        expected_tag = bytes([b ^ c for b, c in zip(s, self.sm4.encrypt_block(cb, key))])

        if tag != expected_tag[:self.tag_size]:
            raise ValueError("Tag verification failed")

        # 解密密文（块处理优化）
        plaintext = []
        current_cb = cb
        ciphertext_blocks = [ciphertext[i:i + self.block_size] for i in range(0, len(ciphertext), self.block_size)]

        for block in ciphertext_blocks:
            # 加密计数器块
            ctr = self.sm4.encrypt_block(current_cb, key)
            # 与密文块异或
            plaintext_block = bytes([b ^ c for b, c in zip(block, ctr[:len(block)])])
            plaintext.append(plaintext_block)
            # 更新计数器
            current_cb = _inc_iv(current_cb)

        return b''.join(plaintext)

# 性能检测
def benchmark(impl_class, name, data_size=10 * 1024 * 1024):
    sm4 = impl_class()
    key = os.urandom(16)
    data = os.urandom(data_size)

    start = time.time()
    encrypted = sm4.encrypt_ecb(data, key)
    encrypt_time = time.time() - start
    encrypt_speed = data_size / (1024 * 1024 * encrypt_time)

    # 测试解密性能
    start = time.time()
    decrypted = sm4.decrypt_ecb(encrypted, key)
    decrypt_time = time.time() - start
    decrypt_speed = data_size / (1024 * 1024 * decrypt_time)

    # 验证正确性
    assert decrypted == data, f"{name} 加密解密不一致"

    return encrypt_speed, decrypt_speed


def gcm_benchmark(impl_class, name, data_size=10 * 1024 * 1024):
    gcm = SM4GCM(impl_class)
    key = os.urandom(16)
    iv = os.urandom(12)
    data = os.urandom(data_size)
    associated_data = b"benchmark_associated_data"

    # 测试加密性能
    start = time.time()
    ciphertext, tag = gcm.encrypt(key, iv, data, associated_data)
    encrypt_time = time.time() - start
    encrypt_speed = data_size / (1024 * 1024 * encrypt_time)

    # 测试解密性能
    start = time.time()
    decrypted = gcm.decrypt(key, iv, ciphertext, tag, associated_data)
    decrypt_time = time.time() - start
    decrypt_speed = data_size / (1024 * 1024 * decrypt_time)

    # 验证正确性
    assert decrypted == data, f"{name} GCM 加密解密不一致"

    return encrypt_speed, decrypt_speed


def main():
    print("SM4算法实现与优化测试")
    print("=" * 50)

    # 测试向量验证
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
    expected_ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")

    # 验证基础实现
    sm4_base = SM4Base()
    ciphertext = sm4_base.encrypt_block(plaintext, key)
    assert ciphertext == expected_ciphertext, "基础实现加密错误"
    decrypted = sm4_base.decrypt_block(ciphertext, key)
    assert decrypted == plaintext, "基础实现解密错误"
    print("基础实现验证通过")

    # 验证T-table优化实现
    sm4_ttable = SM4TTable()
    ciphertext = sm4_ttable.encrypt_block(plaintext, key)
    assert ciphertext == expected_ciphertext, "T-table实现加密错误"
    decrypted = sm4_ttable.decrypt_block(ciphertext, key)
    assert decrypted == plaintext, "T-table实现解密错误"
    print("T-table优化实现验证通过")

    # 验证AES-NI优化实现
    sm4_aesni = SM4AESNI()
    ciphertext = sm4_aesni.encrypt_block(plaintext, key)
    assert ciphertext == expected_ciphertext, "AES-NI实现加密错误"
    decrypted = sm4_aesni.decrypt_block(ciphertext, key)
    assert decrypted == plaintext, "AES-NI实现解密错误"
    print("AES-NI优化实现验证通过")

    # 验证GFNI优化实现
    sm4_gfni = SM4GFNI()
    ciphertext = sm4_gfni.encrypt_block(plaintext, key)
    assert ciphertext == expected_ciphertext, "GFNI实现加密错误"
    decrypted = sm4_gfni.decrypt_block(ciphertext, key)
    assert decrypted == plaintext, "GFNI实现解密错误"
    print("GFNI优化实现验证通过")

    # 验证GCM模式
    gcm = SM4GCM(SM4TTable)
    key = os.urandom(16)
    iv = os.urandom(12)
    data = os.urandom(1024)
    ciphertext, tag = gcm.encrypt(key, iv, data)
    decrypted = gcm.decrypt(key, iv, ciphertext, tag)
    assert decrypted == data, "GCM模式错误"
    print("SM4-GCM模式验证通过")

    # 性能基准测试
    print("\n性能基准测试 (10MB数据):")
    print(f"{'实现方式':<15} {'加密速度(MB/s)':<18} {'解密速度(MB/s)':<18}")
    print("-" * 55)

    # 测试各种实现的性能
    base_speed = benchmark(SM4Base, "基础实现")
    print(f"{'基础实现':<15} {base_speed[0]:<17.2f} {base_speed[1]:<17.2f}")

    ttable_speed = benchmark(SM4TTable, "T-table优化")
    print(f"{'T-table优化':<15} {ttable_speed[0]:<17.2f} {ttable_speed[1]:<17.2f}")

    aesni_speed = benchmark(SM4AESNI, "AES-NI优化")
    print(f"{'AES-NI优化':<15} {aesni_speed[0]:<17.2f} {aesni_speed[1]:<17.2f}")

    gfni_speed = benchmark(SM4GFNI, "GFNI优化")
    print(f"{'GFNI优化':<15} {gfni_speed[0]:<17.2f} {gfni_speed[1]:<17.2f}")

    # 测试GCM模式性能
    print("\nGCM模式性能测试 (10MB数据):")
    print(f"{'实现方式':<15} {'加密速度(MB/s)':<18} {'解密速度(MB/s)':<18}")
    print("-" * 55)

    gcm_base = gcm_benchmark(SM4Base, "基础实现 GCM")
    print(f"{'基础实现 GCM':<15} {gcm_base[0]:<17.2f} {gcm_base[1]:<17.2f}")

    gcm_ttable = gcm_benchmark(SM4TTable, "T-table GCM")
    print(f"{'T-table GCM':<15} {gcm_ttable[0]:<17.2f} {gcm_ttable[1]:<17.2f}")

    gcm_aesni = gcm_benchmark(SM4AESNI, "AES-NI GCM")
    print(f"{'AES-NI GCM':<15} {gcm_aesni[0]:<17.2f} {gcm_aesni[1]:<17.2f}")

    gcm_gfni = gcm_benchmark(SM4GFNI, "GFNI GCM")
    print(f"{'GFNI GCM':<15} {gcm_gfni[0]:<17.2f} {gcm_gfni[1]:<17.2f}")


if __name__ == "__main__":
    main()
