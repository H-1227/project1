import os
from typing import Tuple


class SM4_GCM:
    def __init__(self, sm4_instance):
        self.sm4 = sm4_instance
        self.block_size = 16  # 128位块大小

    def _inc_32(self, block: bytes) -> bytes:
        """递增最后32位"""
        last_int = int.from_bytes(block[-4:], 'big')
        new_last_int = (last_int + 1) % (1 << 32)

        # 组合新的块
        return block[:-4] + new_last_int.to_bytes(4, 'big')

    def _ghash(self, h: bytes, data: bytes) -> bytes:
        n = len(data) // self.block_size
        y = bytes([0]) * self.block_size

        for i in range(n):
            block = data[i * self.block_size: (i + 1) * self.block_size]
            # XOR with Y
            y = bytes(a ^ b for a, b in zip(y, block))
            # Multiply by H in GF(2^128)
            y = self._gcm_mult(y, h)

        return y

    def _gcm_mult(self, x: bytes, y: bytes) -> bytes:
        #在GF(2^128)上的乘法运算#
        z = [0] * 16
        v = list(y)

        for i in range(128):
            bit = (x[i // 8] >> (7 - (i % 8))) & 1
            if bit:
                z = [a ^ b for a, b in zip(z, v)]

            # 检查是否需要约简
            carry = v[0] & 0x80
            # 左移一位
            for j in range(15):
                v[j] = ((v[j] << 1) & 0xFF) | ((v[j + 1] >> 7) & 0x01)
            v[15] = (v[15] << 1) & 0xFF

            # 如果carry为1，应用约简多项式
            if carry:
                v[15] ^= 0x87

        return bytes(z)

    def _generate_subkey(self, key: bytes) -> bytes:
        """生成H和J0子密钥"""
        # H是SM4加密全零块的结果
        zero_block = bytes([0]) * self.block_size
        h = self.sm4.encrypt_block(zero_block, key)
        return h

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """SM4-GCM加密"""
        if len(iv) != 12:  # 96位IV
            raise ValueError("IV must be 12 bytes (96 bits) long")

        # 生成H和J0
        h = self._generate_subkey(key)
        j0 = iv + b'\x00\x00\x00\x01'

        # 生成计数器块
        ctr = j0

        # 加密
        ciphertext = b''
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]
            # 加密计数器块
            encrypted_ctr = self.sm4.encrypt_block(ctr, key)
            # XOR with plaintext
            cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_ctr[:len(block)]))
            ciphertext += cipher_block
            # 递增计数器
            ctr = self._inc_32(ctr)

        # 计算认证标签
        al = (len(aad) * 8).to_bytes(8, 'big')
        cl = (len(ciphertext) * 8).to_bytes(8, 'big')
        data_to_hash = aad + bytes((-len(aad)) % self.block_size) + \
                       ciphertext + bytes((-len(ciphertext)) % self.block_size) + \
                       al + cl

        s = self._ghash(h, data_to_hash)

        # 生成认证标签
        tag_input = self.sm4.encrypt_block(j0, key)
        tag = bytes(a ^ b for a, b in zip(s, tag_input))

        return ciphertext, tag[:16]  # 返回128位标签

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """SM4-GCM解密和验证"""
        if len(iv) != 12:  # 96位IV
            raise ValueError("IV must be 12 bytes (96 bits) long")

        # 生成H和J0
        h = self._generate_subkey(key)
        j0 = iv + b'\x00\x00\x00\x01'

        # 生成计数器块
        ctr = j0

        # 解密
        plaintext = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            # 加密计数器块
            encrypted_ctr = self.sm4.encrypt_block(ctr, key)
            # XOR with ciphertext
            plain_block = bytes(a ^ b for a, b in zip(block, encrypted_ctr[:len(block)]))
            plaintext += plain_block
            # 递增计数器
            ctr = self._inc_32(ctr)

        # 计算认证标签
        al = (len(aad) * 8).to_bytes(8, 'big')
        cl = (len(ciphertext) * 8).to_bytes(8, 'big')
        data_to_hash = aad + bytes((-len(aad)) % self.block_size) + \
                       ciphertext + bytes((-len(ciphertext)) % self.block_size) + \
                       al + cl

        s = self._ghash(h, data_to_hash)

        # 生成认证标签
        tag_input = self.sm4.encrypt_block(j0, key)
        expected_tag = bytes(a ^ b for a, b in zip(s, tag_input))

        # 验证标签
        if expected_tag[:len(tag)] != tag:
            raise ValueError("Authentication tag verification failed")

        return plaintext

if __name__ == "__main__":
    sm4 = SM4()  # 或使用优化版本SM4_TTable()

    # 创建SM4-GCM实例
    sm4_gcm = SM4_GCM(sm4)

    # 128位密钥，96位IV
    key = os.urandom(16)
    iv = os.urandom(12)
    plaintext = b"Hello, SM4-GCM encryption!"
    aad = b"Additional authenticated data"

    # 加密
    ciphertext, tag = sm4_gcm.encrypt(plaintext, key, iv, aad)
    print(f"明文: {plaintext}")
    print(f"密文: {ciphertext.hex()}")
    print(f"认证标签: {tag.hex()}")

    # 解密
    decrypted = sm4_gcm.decrypt(ciphertext, key, iv, tag, aad)
    print(f"解密后: {decrypted}")