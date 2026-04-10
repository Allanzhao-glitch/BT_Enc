"""
蓝牙加密通讯模块 - 类似TCP三次握手的密钥交换
实现EN18031认证要求的蓝牙加密协议
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(asctime)s %(filename)s|%(lineno)d: %(message)s")
logger = logging.getLogger(__name__)


class Fmt(StrEnum):
    """struct格式字节码枚举
    用于struct模块格式字符串拼接，如多字段组合时，可直接用成员.value获取格式码。
    """

    SIGNED_BYTE = "b"
    """SIGNED_BYTE        = "b"   # 有符号字节，8位，1字节，范围-128~127"""
    UNSIGNED_BYTE = "B"
    """UNSIGNED_BYTE      = "B"   # 无符号字节，8位，1字节，范围0~255"""
    BOOL = "?"
    """BOOL               = "?"   # 布尔值，1字节，True/False"""
    SIGNED_SHORT = "h"
    """SIGNED_SHORT       = "h"   # 有符号短整型，16位，2字节，范围-32768~32767"""
    UNSIGNED_SHORT = "H"
    """UNSIGNED_SHORT     = "H"   # 无符号短整型，16位，2字节，范围0~65535"""
    SIGNED_INT = "i"
    """SIGNED_INT         = "i"   # 有符号整型，32位，4字节，范围-2^31~2^31-1"""
    UNSIGNED_INT = "I"
    """UNSIGNED_INT       = "I"   # 无符号整型，32位，4字节，范围0~2^32-1"""
    SIGNED_LONG = "l"
    """SIGNED_LONG        = "l"   # 有符号长整型，32位，4字节"""
    UNSIGNED_LONG = "L"
    """UNSIGNED_LONG      = "L"   # 无符号长整型，32位，4字节"""
    SIGNED_LONG_LONG = "q"
    """SIGNED_LONG_LONG   = "q"   # 有符号长长整型，64位，8字节"""
    UNSIGNED_LONG_LONG = "Q"
    """UNSIGNED_LONG_LONG = "Q"   # 无符号长长整型，64位，8字节"""
    HALF_FLOAT = "e"
    """HALF_FLOAT         = "e"   # 半精度浮点，16位，2字节，IEEE 754二进制16位"""
    FLOAT = "f"
    """FLOAT              = "f"   # 单精度浮点，32位，4字节，IEEE 754二进制32位"""
    DOUBLE = "d"
    """DOUBLE             = "d"   # 双精度浮点，64位，8字节，IEEE 754二进制64位"""
    LITTLE_ENDIAN = "<"
    """LITTLE_ENDIAN      = "<"   # 小端字节序"""
    BIG_ENDIAN = ">"
    """BIG_ENDIAN         = ">"   # 大端字节序"""
    NATIVE = "@"
    """NATIVE             = "@"   # 原生字节序、对齐和大小（本地机器）"""
    NATIVE_STANDARD = "="
    """NATIVE_STANDARD    = "="   # 原生字节序，标准对齐和大小（本地机器，不依赖C对齐）"""
    NETWORK = "!"
    """NETWORK            = "!"   # 网络字节序（大端，与'>'等价）"""


@dataclass
class GcmEncryptedResult:
    """
    AES-GCM加解密结果对象

    Attributes:
        ciphertext_hex: 密文的十六进制字符串表示（不含tag部分）
        tag_hex: GCM认证标签的十六进制字符串表示（16字节/32个hex字符）
    """

    ciphertext: str
    """密文部分（hex字符串，不含tag，便于协议传输）"""
    tag: str
    """GCM的tag认证标签（hex字符串，16字节）"""


class PairStage(IntEnum):
    """配对阶段状态
    表示密钥配对过程中的不同阶段和相关响应类型。
    Each constant对应服务端和客户端在配对流程中的具体含义。
    所有值均为16进制，注释详细说明十进制值及作用。
    """

    PAIR_STAGE_WAIT_CONFIRM = 0x32  # 第1次握手，客户端发送公钥，服务器端等待确认
    """50: 等待确认（第1次握手，客户端发送公钥时的状态）"""

    PAIR_STAGE_STATUS_SUCC = 0x14  # 第3次握手，客户端发送确认，表示配对完成
    """20: 配对成功（第3次握手，客户端发送确认，表示配对成功进入通讯阶段）"""

    PAIR_STAGE_FAIL = 0x02  # 表示配对失败，一般由服务器主动返回
    """2: 配对失败（密钥交换或验证失败时由服务器返回的失败状态）"""

    PAIR_STAGE_DEVICE_INFO = 0x04  # 设备信息 protobuf 格式返回，指示设备已配对过
    """4: 设备信息（protobuf格式，通常表明设备已配对过，本次不进行公钥交换）"""

    PAIR_STAGE_ERROR = 0x0A  # 一般表示服务器主动报错，具体原因见data
    """10: 错误（车端返回，data字段包含详细错误信息）"""


# # 100568
# ENCRYPTED_DATA_MAGIC = 0x188D8
ENCRYPTED_DATA_MAGIC = 0x88C8
"""加密数据协议头魔术值 16位 (35016)"""


class CommunicationStage(IntEnum):
    """通讯阶段"""

    STAGE_INIT = 0x00  # 初始化阶段
    STAGE_PAIRING = 0x01  # 配对阶段
    STAGE_COMM = 0x02  # 通讯阶段


class EncryptionProtocol:
    """加密协议处理类"""

    # AES-256密钥和IV (与C代码保持一致)
    STATIC_KEY = bytes(
        [
            0x30,
            0x31,
            0x32,
            0x33,
            0x34,
            0x35,
            0x36,
            0x37,
            0x38,
            0x39,
            0x41,
            0x42,
            0x43,
            0x44,
            0x45,
            0x46,
            0x47,
            0x48,
            0x49,
            0x4A,
            0x4B,
            0x4C,
            0x4D,
            0x4E,
            0x4F,
            0x50,
            0x51,
            0x52,
            0x53,
            0x54,
            0x55,
            0x56,
        ]
    )

    STATIC_IV = bytes([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F])

    # AAD = b"mammotion"  # 附加认证数据
    AAD = b"12345678"  # 附加认证数据

    def __init__(self):
        """初始化加密协议"""
        self.shared_secret: bytes | None = None
        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.public_key: bytes | None = None
        self.peer_public_key: bytes | None = None
        self.communication_stage = CommunicationStage.STAGE_INIT

    def generate_ecdh_keypair(self) -> Tuple[bytes, ec.EllipticCurvePrivateKey]:
        """
        生成ECDH密钥对 (使用SECP256R1曲线)

        Returns:
            公钥字节(压缩格式), 私钥对象
        """
        logger.info("[OK] 生成ECDH密钥对...")

        # 生成SECP256R1曲线密钥对
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # 导出压缩格式公钥 (与C代码一致)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        logger.info(f"[OK] 公钥长度: {len(public_key)} 字节")
        logger.info(f"[OK] 公钥: {public_key.hex()}")

        return public_key, private_key

    def aes256_cbc_encrypt(self, plaintext: bytes) -> str:
        """
        AES-256 CBC模式加密 (用于密钥交换阶段)

        Args:
            plaintext: 明文数据

        Returns:
            十六进制编码的密文字符串(str)
        """

        cipher = Cipher(algorithms.AES(self.STATIC_KEY), modes.CBC(self.STATIC_IV), backend=default_backend())
        encryptor = cipher.encryptor()

        # PKCS7填充
        padding_len = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([padding_len] * padding_len)

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # 返回十六进制字符串(str类型)
        return ciphertext.hex()

    def aes256_cbc_decrypt(self, hex_ciphertext: str | bytes) -> bytes:
        """
        AES-256 CBC模式解密

        Args:
            hex_ciphertext: 十六进制编码的密文字符串(str)

        Returns:
            明文字节
        """
        # 十六进制解码 (支持str或bytes输入)
        if isinstance(hex_ciphertext, bytes):
            hex_ciphertext = hex_ciphertext.decode("ascii")
        ciphertext = bytes.fromhex(hex_ciphertext)
        print(f"解密输入ciphertext: {ciphertext}")
        cipher = Cipher(algorithms.AES(self.STATIC_KEY), modes.CBC(self.STATIC_IV), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # 去除PKCS7填充
        padding_len = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_len]

        return plaintext

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        计算ECDH共享密钥

        Args:
            peer_public_key_bytes: 对端公钥字节

        Returns:
            共享密钥
        """
        logger.info("[OK] 计算共享密钥...")
        logger.info(f"[OK] 对端公钥: {peer_public_key_bytes.hex()}")

        # 使用 SECP256R1 曲线和 from_encoded_point
        curve = ec.SECP256R1()
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, peer_public_key_bytes)

        # 计算共享密钥
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)

        logger.info(f"[OK] 共享密钥长度: {len(shared_key)} 字节")
        logger.info(f"[OK] 共享密钥: {shared_key.hex()}")

        return shared_key

    def aes256_gcm_encrypt(self, plaintext: bytes) -> bytes:
        """
        AES-256 GCM模式加密 (用于数据通讯阶段)

        Args:
            plaintext: 明文数据

        Returns:
            bytes: GCM加密数据
        """
        if not self.shared_secret:
            raise ValueError("未建立共享密钥")

        aesgcm = AESGCM(self.shared_secret)

        # GCM加密 (自动生成tag)
        ciphertext = aesgcm.encrypt(self.STATIC_IV, plaintext, self.AAD)
        logger.info(f"[OK] GCM加密: {len(ciphertext)} 字节")

        return ciphertext

    def aes256_gcm_decrypt(self, ciphertext: str, tag: str) -> bytes:
        """
        AES-256 GCM模式解密

        Args:
            ciphertext: 密文(hex字符串)
            tag: 认证标签(hex字符串)

        Returns:
            明文数据
        """
        if not self.shared_secret:
            raise ValueError("未建立共享密钥")

        # 将hex字符串转换为bytes
        ciphertext_bytes = bytes.fromhex(ciphertext)
        tag_bytes = bytes.fromhex(tag)

        aesgcm = AESGCM(self.shared_secret)

        # GCM解密 (需要拼接ciphertext + tag)
        plaintext = aesgcm.decrypt(self.STATIC_IV, ciphertext_bytes + tag_bytes, self.AAD)

        return plaintext


class KeyMatchHeader:
    """密钥交换协议头 - 自动处理ASCII编解码

    对应C结构体:
    typedef struct {
        uint16_t pair_header;      // 协议头魔数 (2字节)
        uint8_t client_pub_len;    // 加密数据长度 (1字节)
        uint8_t is_change;         // 密钥配对状态 (1字节)
        uint8_t data[];            // 公钥数据 (变长)
    } KeyMatchHeader;
    """

    FORMAT = Fmt.LITTLE_ENDIAN + Fmt.UNSIGNED_SHORT + Fmt.UNSIGNED_BYTE + Fmt.UNSIGNED_BYTE
    # FORMAT = Fmt.LITTLE_ENDIAN + Fmt.UNSIGNED_LONG_LONG + Fmt.UNSIGNED_BYTE + Fmt.UNSIGNED_BYTE
    """协议格式: 小端序 - pair_header(2字节) + client_pub_len(1字节) + is_change(1字节)"""
    HEADER_SIZE = struct.calcsize(FORMAT)
    """协议头大小: 4字节"""

    def __init__(self, client_pub_len: int, is_change: PairStage, data: str):
        """
        初始化密钥交换协议头

        Args:
            client_pub_len: 客户端公钥长度
            is_change: 配对阶段状态
            data: 数据载荷(hex字符串,如 "a1b2c3...")
        """
        self.client_pub_len = client_pub_len
        self.is_change = is_change
        self.pair_header = ENCRYPTED_DATA_MAGIC  # 添加协议头魔数
        self.data = data  # 内部存储为str

    def __repr__(self) -> str:
        """打印密钥交换协议头

        Returns:
            str: 密钥交换协议头字符串
        """
        return f"KeyMatchHeader(pair_header={self.pair_header}, client_pub_len={self.client_pub_len}, is_change={self.is_change}, data={self.data}, FORMAT={self.FORMAT}, HEADER_SIZE={self.HEADER_SIZE})"

    def pack(self) -> bytes:
        """
        打包协议数据 - 自动将data编码为ASCII

        Returns:
            打包后的完整数据包(header + ASCII编码的data)
        """
        header = struct.pack(self.FORMAT, self.pair_header, self.client_pub_len, self.is_change)
        # 将hex字符串编码为ASCII字节
        data_bytes = self.data.encode("ascii")
        return header + data_bytes

    @classmethod
    def unpack(cls, raw_data: bytes) -> KeyMatchHeader:
        """
        解包协议数据 - 自动将data从ASCII解码

        Args:
            raw_data: 原始数据包(bytes)

        Returns:
            解包后的KeyMatchHeader对象,data字段为str类型
        """
        if len(raw_data) < cls.HEADER_SIZE:
            raise ValueError("数据长度不足")

        # 解析header部分(前4字节)
        pair_header, client_pub_len, is_change = struct.unpack(cls.FORMAT, raw_data[: cls.HEADER_SIZE])
        logger.info(f"解析后 - pair_header: {pair_header} (0x{pair_header:04x})")

        # 提取data部分并从ASCII解码为字符串
        data_bytes = raw_data[cls.HEADER_SIZE :]
        # data_str = data_bytes.decode("ascii", errors="replace")
        data_str = data_bytes
        data_str = data_bytes.decode("ascii", errors="replace")
        # data_str = data_bytes

        return cls(client_pub_len, PairStage(is_change), data_str)


class EncryptedDataHeader:
    """加密数据协议头 - 自动处理ASCII编解码"""

    FORMAT = Fmt.LITTLE_ENDIAN + Fmt.UNSIGNED_INT + Fmt.UNSIGNED_INT
    """协议格式: 小端序 - data_len(4字节) + tag_len(4字节)"""
    HEADER_SIZE = struct.calcsize(FORMAT)
    """协议头大小: 8字节"""

    def __init__(self, data_len: int, tag_len: int, data: str):
        """
        初始化加密数据协议头

        Args:
            data_len: 加密数据长度(hex字符串长度)
            tag_len: 认证标签长度(hex字符串长度)
            data: 数据载荷(hex字符串,如 "a1b2c3...def123...")
        """
        self.data_len = data_len
        self.tag_len = tag_len
        self.data = data  # 内部存储为str

    def __repr__(self) -> str:
        """打印加密数据协议头

        Returns:
            str: 加密数据协议头字符串
        """
        return f"EncryptedDataHeader(data_len={self.data_len}, tag_len={self.tag_len}, data={self.data}, FORMAT={self.FORMAT}, HEADER_SIZE={self.HEADER_SIZE})"

    def pack(self) -> bytes:
        """
        打包协议数据 - 自动将data编码为ASCII

        Returns:
            打包后的完整数据包(header + ASCII编码的data)
        """
        header = struct.pack(self.FORMAT, self.data_len, self.tag_len)
        # 将hex字符串编码为ASCII字节
        data_bytes = self.data.encode("ascii")
        return header + data_bytes

    @classmethod
    def unpack(cls, raw_data: bytes) -> EncryptedDataHeader:
        """
        解包协议数据 - 自动将data从ASCII解码

        Args:
            raw_data: 原始数据包(bytes)

        Returns:
            解包后的EncryptedDataHeader对象,data字段为str类型
        """
        if len(raw_data) < cls.HEADER_SIZE:
            raise ValueError("数据长度不足")

        # 解析header部分(前8字节)
        data_len, tag_len = struct.unpack(cls.FORMAT, raw_data[: cls.HEADER_SIZE])

        # 提取data部分并从ASCII解码为字符串
        data_bytes = raw_data[cls.HEADER_SIZE :]
        data_str = data_bytes.decode("ascii", errors="replace")

        return cls(data_len, tag_len, data_str)


class BluetoothCryptoClient:
    """
    蓝牙加密客户端 - 实现类似TCP三次握手的密钥交换

    流程:
    1. 客户端 → 服务器: 发送加密的客户端公钥
    2. 服务器 → 客户端: 发送加密的服务器公钥
    3. 客户端 → 服务器: 确认配对成功
    4. 进入加密通讯阶段
    """

    def __init__(self):
        """初始化客户端"""
        self.crypto = EncryptionProtocol()
        logger.info("蓝牙加密客户端初始化")

    async def handshake_step1_send_public_key(self) -> bytes:
        """
        【第一次握手】客户端发送加密的公钥给服务器

        Returns:
            待发送的数据包
        """
        logger.info("\n" + "=" * 60)
        logger.info("【第1次握手】客户端 → 服务器: 发送加密公钥")
        logger.info("=" * 60)

        # 生成ECDH密钥对
        public_key, private_key = self.crypto.generate_ecdh_keypair()
        self.crypto.public_key = public_key
        self.crypto.private_key = private_key

        # 使用静态密钥加密公钥 (返回hex字符串)
        encrypted_pub_hex = self.crypto.aes256_cbc_encrypt(public_key)

        # 构造协议包 (KeyMatchHeader会自动将hex字符串编码为ASCII)
        packet = KeyMatchHeader(
            client_pub_len=len(encrypted_pub_hex),
            is_change=PairStage.PAIR_STAGE_WAIT_CONFIRM,
            data=encrypted_pub_hex,
        )

        data = packet.pack()
        logger.info(f"发送数据长度: {len(data)} 字节")
        logger.info(f"发送数据: {packet}")
        logger.info(f"原始数据: {data.hex()}")

        self.crypto.communication_stage = CommunicationStage.STAGE_PAIRING
        return data

    async def handshake_step2_receive_server_key(self, response: bytes) -> bool:
        """
        【第二次握手】客户端接收服务器加密的公钥

        Args:
            response: 服务器响应数据

        Returns:
            是否成功
        """
        logger.info("\n" + "=" * 60)
        logger.info("【第2次握手】服务器 → 客户端: 接收加密公钥")
        logger.info("=" * 60)

        try:
            # 解析协议包
            logger.info(f"接收数据长度: {len(response)} 字节")
            logger.info(f"原始数据(hex): {response.hex()}")

            packet = KeyMatchHeader.unpack(response)

            logger.info(f"解析后 - client_pub_len: {packet.client_pub_len}")
            logger.info(f"解析后 - is_change: {packet.is_change} (0x{packet.is_change:02x})")
            logger.info(f"解析后 - data长度: {len(packet.data)}")
            logger.info(f"解析后 - data(ASCII): {packet.data}")

            # 检查响应类型
            if packet.is_change == PairStage.PAIR_STAGE_ERROR:
                # packet.data 现在是str类型
                error_msg = packet.data
                logger.error(f"[X] 车端返回错误: {error_msg}")
                logger.error("[X] 可能原因:")
                logger.error("  1. 公钥解密失败 - 检查静态密钥是否匹配")
                logger.error("  2. ECDH密钥生成失败 - 检查公钥格式")
                logger.error("  3. 共享密钥计算失败")
                return False

            elif packet.is_change == PairStage.PAIR_STAGE_DEVICE_INFO:
                logger.warning("[!] 收到设备信息(protobuf),这可能不是密钥交换响应")
                logger.warning("[!] 设备可能已经配对过,使用静态密钥进行通讯")
                # packet.data 现在是str类型(hex字符串)
                logger.info(f"[!] Protobuf数据: {packet.data}")

                # 设备已配对,不需要交换公钥
                # 使用静态密钥作为共享密钥
                self.crypto.shared_secret = self.crypto.STATIC_KEY
                logger.info("[OK] 使用静态密钥作为共享密钥")

                return True

            elif packet.is_change != PairStage.PAIR_STAGE_STATUS_SUCC:
                logger.error(f"[X] 配对失败: {packet.is_change}")
                return False

            # 解密服务器公钥
            # 注意: C服务器发送的data字段本身就是hex字符串(ASCII编码)
            # 所以直接使用,不需要再次hex编码
            print(f"服务器响应data字段(ASCII): {packet.data}")
            server_public_key = self.crypto.aes256_cbc_decrypt(packet.data)
            logger.info(f"服务器公钥server_public_key: {server_public_key}")
            self.crypto.peer_public_key = server_public_key

            logger.info(f"服务器公钥: {server_public_key.hex()}")

            # 计算共享密钥
            self.crypto.shared_secret = self.crypto.compute_shared_secret(server_public_key)

            return True

        except Exception:
            logger.exception("[X] 处理服务器响应失败")
            return False

    async def handshake_step3_confirm(self) -> bytes:
        """
        【第三次握手】客户端确认配对成功

        Returns:
            确认数据包
        """
        logger.info("\n" + "=" * 60)
        logger.info("【第3次握手】客户端 → 服务器: 确认配对成功")
        logger.info("=" * 60)

        # 发送配对成功确认
        packet = KeyMatchHeader(client_pub_len=0, is_change=PairStage.PAIR_STAGE_STATUS_SUCC, data="")

        data = packet.pack()
        logger.info("[OK] 配对成功,进入加密通讯阶段")

        self.crypto.communication_stage = CommunicationStage.STAGE_COMM
        return data

    async def encrypt_send_data(self, plaintext: bytes) -> bytes:
        """
        加密并发送数据

        Args:
            plaintext: 明文数据

        Returns:
            加密后的数据包
        """
        logger.info("\n" + "-" * 60)
        logger.info("加密发送数据")

        if self.crypto.communication_stage != CommunicationStage.STAGE_COMM:
            raise ValueError("未完成配对,无法发送加密数据")

        # GCM加密
        encrypted_bytes = self.crypto.aes256_gcm_encrypt(plaintext)

        # AESGCM.encrypt 返回 ciphertext + tag (tag 是最后16字节)
        ciphertext = encrypted_bytes[:-16]
        tag = encrypted_bytes[-16:]

        # 构造数据包 (分别发送密文和tag的hex字符串)
        # 注意: data_len 和 tag_len 应该是 hex 字符串长度，车端用 data_len / 2 得到字节长度
        packet = EncryptedDataHeader(
            data_len=len(ciphertext.hex()),  # hex字符串长度 (41 * 2 = 82)
            tag_len=len(tag.hex()),  # tag的hex字符串长度 (16 * 2 = 32)
            data=ciphertext.hex() + tag.hex()  # 密文hex + taghex
        )

        data = packet.pack()
        logger.info(f"加密数据包: {data.hex()}")
        logger.info(f"加密数据包头(前16字节): {data[:16].hex()}")
        logger.info(f"  头4字节(data_len): {data[:4].hex()} = {int.from_bytes(data[:4], 'little')}")
        logger.info(f"  头4-8字节(tag_len): {data[4:8].hex()} = {int.from_bytes(data[4:8], 'little')}")
        logger.info(f"明文: {plaintext.hex()}")
        logger.info(f"密文(hex): {ciphertext.hex()}")
        logger.info(f"Tag(hex): {tag.hex()}")
        logger.info(f"加密数据长度: {len(data)} 字节")
        logger.info(f"加密数据包头(hex): {data[:20].hex()}")
        logger.info(f"  data_len={packet.data_len}, tag_len={packet.tag_len}")

        return data

    async def decrypt_receive_data(self, encrypted_data: bytes) -> bytes:
        """
        接收并解密数据

        Args:
            encrypted_data: 加密数据包

        Returns:
            明文数据
        """
        logger.info("\n" + "-" * 60)
        logger.info("解密接收数据")

        if self.crypto.communication_stage != CommunicationStage.STAGE_COMM:
            raise ValueError("未完成配对,无法接收加密数据")

        # 检查是否是protobuf数据(设备信息)
        if len(encrypted_data) >= 2:
            header_byte2 = encrypted_data[1]

            # 如果是KeyMatchHeader格式(0x04 = 设备信息)
            if header_byte2 == 0x04:
                logger.warning("[!] 收到的是protobuf设备信息,不是加密数据")
                logger.info(f"[!] 原始数据: {encrypted_data.hex()}")
                raise ValueError("收到protobuf设备信息,不是加密响应")

        # 解析加密数据包
        packet = EncryptedDataHeader.unpack(encrypted_data)

        # 提取密文和标签 (packet.data 是 hex 字符串)
        # data_len 是 hex 字符串长度，直接使用
        ciphertext_hex = packet.data[: packet.data_len]  # hex 字符串
        tag_hex = packet.data[packet.data_len : packet.data_len + packet.tag_len]  # hex 字符串

        # GCM解密 (需要 hex 字符串)
        plaintext = self.crypto.aes256_gcm_decrypt(ciphertext_hex, tag_hex)

        logger.info(f"[OK] 明文: {plaintext.hex()}")

        return plaintext