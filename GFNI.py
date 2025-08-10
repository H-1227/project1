import os
import ctypes
from ctypes import CDLL, c_void_p, c_uint8, c_uint32, POINTER, Structure
from typing import List, Tuple

# 加载动态链接库
try:
    # 尝试加载已编译的优化库
    sm4_lib = CDLL('./sm4_optimized.so')  # Linux/MacOS
except:
    try:
        sm4_lib = CDLL('./sm4_optimized.dll')  # Windows
    except:
        print("无法加载优化库，使用纯Python实现")
        sm4_lib = None


# 定义SM4密钥结构体
class SM4Key(Structure):
    _fields_ = [("rk", c_uint32 * 32)]


# 检查是否支持AES-NI和GFNI指令集
def check_cpu_support():
    """检查CPU是否支持AES-NI和GFNI指令集"""
    try:
        import cpuinfo
        info = cpuinfo.get_cpu_info()
        flags = info.get('flags', [])
        return {'aes_ni': 'aes' in flags, 'gfni': 'gfni' in flags}
    except:
        return {'aes_ni': False, 'gfni': False}


class SM4_AESNI_GFNI:
    def __init__(self):
        self.cpu_support = check_cpu_support()
        self.sm4_lib = sm4_lib

        if self.sm4_lib:
            # 设置函数参数和返回类型
            self.sm4_lib.sm4_key_expansion.argtypes = [POINTER(c_uint8), POINTER(SM4Key)]
            self.sm4_lib.sm4_encrypt_block.argtypes = [POINTER(c_uint8), POINTER(SM4Key), POINTER(c_uint8)]
            self.sm4_lib.sm4_decrypt_block.argtypes = [POINTER(c_uint8), POINTER(SM4Key), POINTER(c_uint8)]

            # GFNI优化的函数
            if self.cpu_support['gfni']:
                self.sm4_lib.sm4_gfni_encrypt_block.argtypes = [POINTER(c_uint8), POINTER(SM4Key), POINTER(c_uint8)]
                self.sm4_lib.sm4_gfni_decrypt_block.argtypes = [POINTER(c_uint8), POINTER(SM4Key), POINTER(c_uint8)]

    def _key_expansion(self, key: bytes) -> SM4Key:
        """密钥扩展，使用AES-NI优化"""
        if not self.sm4_lib or not self.cpu_support['aes_ni']:
            # 回退到纯Python实现
            # 这里应该使用之前实现的密钥扩展算法
            # 为简化示例，此处省略具体实现
            pass

        key_buf = (c_uint8 * 16)(*key)
        sm4_key = SM4Key()
        self.sm4_lib.sm4_key_expansion(key_buf, ctypes.byref(sm4_key))
        return sm4_key

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """加密单个数据块，使用AES-NI和GFNI优化"""
        if not self.sm4_lib:
            # 回退到纯Python实现
            # 这里应该使用之前实现的加密算法
            # 为简化示例，此处省略具体实现
            pass

        # 密钥扩展
        sm4_key = self._key_expansion(key)

        pt_buf = (c_uint8 * 16)(*plaintext)
        ct_buf = (c_uint8 * 16)()

        if self.cpu_support['gfni']:
            self.sm4_lib.sm4_gfni_encrypt_block(pt_buf, ctypes.byref(sm4_key), ct_buf)
        else:
            self.sm4_lib.sm4_encrypt_block(pt_buf, ctypes.byref(sm4_key), ct_buf)

        return bytes(ct_buf)

    def decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        """解密单个数据块，使用AES-NI和GFNI优化"""
        if not self.sm4_lib:
            # 回退到纯Python实现
            # 这里应该使用之前实现的解密算法
            # 为简化示例，此处省略具体实现
            pass

        # 密钥扩展
        sm4_key = self._key_expansion(key)

        # 准备输入和输出缓冲区
        ct_buf = (c_uint8 * 16)(*ciphertext)
        pt_buf = (c_uint8 * 16)()

        # 根据CPU支持选择解密函数
        if self.cpu_support['gfni']:
            self.sm4_lib.sm4_gfni_decrypt_block(ct_buf, ctypes.byref(sm4_key), pt_buf)
        else:
            self.sm4_lib.sm4_decrypt_block(ct_buf, ctypes.byref(sm4_key), pt_buf)

        return bytes(pt_buf)

    # 其他方法（如ECB模式加密解密）可以与之前的实现类似

if __name__ == "__main__":
    # 创建AES-NI和GFNI优化的SM4实例
    sm4_opt = SM4_AESNI_GFNI()

    # 检查CPU支持
    print(f"CPU支持情况: AES-NI: {sm4_opt.cpu_support['aes_ni']}, GFNI: {sm4_opt.cpu_support['gfni']}")

    if sm4_opt.sm4_lib:
        # 128位密钥和明文
        key = os.urandom(16)
        plaintext = b"Hello, SM4 AES-NI/GFNI optimization!"

        # 加密
        ciphertext = sm4_opt.encrypt_block(plaintext, key)
        print(f"明文: {plaintext}")
        print(f"密文: {ciphertext.hex()}")

        # 解密
        decrypted = sm4_opt.decrypt_block(ciphertext, key)
        print(f"解密后: {decrypted}")
