# 蓝牙加密通讯系统 - EN18031认证

基于ECDH密钥交换和AES-256-GCM加密的蓝牙安全通讯实现,采用类似TCP三次握手的密钥协商机制。

## 📋 目录

- [系统架构](#系统架构)
- [加密流程](#加密流程)
- [安装依赖](#安装依赖)
- [快速开始](#快速开始)
- [API文档](#api文档)
- [安全特性](#安全特性)

## 🏗️ 系统架构

### 文件说明

```
BT_Enc/
├── aes256.c                      # C语言AES加密实现(参考)
├── data.c                        # C语言数据处理实现(参考)
├── bluetooth_crypto.py           # 核心加密协议实现
├── bluetooth_secure_client.py    # 蓝牙安全客户端
├── test_crypto_handshake.py      # 握手流程测试
└── README.md                     # 本文档
```

### 核心模块

1. **EncryptionProtocol** - 加密协议类
   - ECDH密钥生成和交换
   - AES-256-CBC加密(密钥交换阶段)
   - AES-256-GCM加密(数据通讯阶段)

2. **BluetoothCryptoClient** - 客户端实现
   - 密钥交换握手
   - 加密数据发送/接收

3. **BluetoothCryptoServer** - 服务端实现
   - 处理客户端握手请求
   - 加密数据发送/接收

4. **BluetoothSecureClient** - 完整蓝牙客户端
   - 集成Bleak蓝牙库
   - 设备搜索和连接
   - 完整的加密通讯流程

## 🔐 加密流程

### 三次握手流程图

```
客户端                                    服务端
  |                                         |
  |--- ① 发送加密客户端公钥 --------------->|
  |     (AES-256-CBC加密,使用静态密钥)      |
  |                                         |
  |                     生成服务端ECDH密钥对 |
  |                     计算共享密钥(32字节) |
  |                                         |
  |<-- ② 发送加密服务端公钥 ----------------|
  |     (AES-256-CBC加密,配对成功标记)      |
  |                                         |
  | 解密服务端公钥                           |
  | 计算共享密钥(32字节)                     |
  |                                         |
  |--- ③ 发送配对成功确认 ------------------>|
  |     (配对状态: PAIR_STAGE_STATUS_SUCC) |
  |                                         |
  |========== 进入加密通讯阶段 =============|
  |                                         |
  |<-- 加密数据通讯 (AES-256-GCM) --------->|
  |                                         |
```

### 详细步骤

#### 阶段1: 密钥交换(ECDH + AES-256-CBC)

**第1次握手 - 客户端发起**
```python
# 1. 客户端生成ECDH密钥对(SECP256R1曲线)
client_private_key, client_public_key = generate_ecdh_keypair()

# 2. 使用静态AES-256密钥加密公钥(CBC模式)
encrypted_pub = aes256_cbc_encrypt(client_public_key, STATIC_KEY, STATIC_IV)

# 3. 构造协议包发送
packet = {
    'client_pub_len': len(encrypted_pub),
    'is_change': PAIR_STAGE_WAIT_CONFIRM,
    'data': encrypted_pub
}
```

**第2次握手 - 服务端响应**
```python
# 1. 解密客户端公钥
client_public_key = aes256_cbc_decrypt(encrypted_pub, STATIC_KEY, STATIC_IV)

# 2. 生成服务端ECDH密钥对
server_private_key, server_public_key = generate_ecdh_keypair()

# 3. 计算共享密钥(ECDH)
shared_secret = ecdh_compute(server_private_key, client_public_key)

# 4. 加密服务端公钥并发送
encrypted_server_pub = aes256_cbc_encrypt(server_public_key, STATIC_KEY, STATIC_IV)
```

**第3次握手 - 客户端确认**
```python
# 1. 解密服务端公钥
server_public_key = aes256_cbc_decrypt(encrypted_server_pub)

# 2. 计算共享密钥(必须与服务端一致)
shared_secret = ecdh_compute(client_private_key, server_public_key)

# 3. 发送确认
packet = {
    'is_change': PAIR_STAGE_STATUS_SUCC
}
```

#### 阶段2: 数据通讯(AES-256-GCM)

```python
# 发送加密数据
ciphertext, tag = aes256_gcm_encrypt(plaintext, shared_secret, IV, AAD)

# 数据包格式
packet = {
    'data_len': len(ciphertext),
    'tag_len': len(tag),  # 固定16字节
    'data': ciphertext + tag
}

# 接收解密数据
plaintext = aes256_gcm_decrypt(ciphertext, tag, shared_secret, IV, AAD)
```

## 📦 安装依赖

### Python依赖

```bash
# 安装加密库
pip install cryptography

# 安装蓝牙库(用于实际设备通讯)
pip install bleak

# 可选:安装开发工具
pip install pytest pytest-asyncio
```

### 系统要求

- Python 3.8+
- 支持蓝牙BLE的操作系统
  - Windows 10+
  - Linux (BlueZ 5.43+)
  - macOS 10.13+

## 🚀 快速开始

### 示例1: 测试加密握手流程

运行完整的握手测试(不需要真实蓝牙设备):

```bash
cd BT_Enc
python test_crypto_handshake.py
```

**输出示例:**
```
====================================================
【第1次握手】客户端 → 服务器: 发送加密公钥
====================================================
🔑 生成ECDH密钥对...
✅ 公钥长度: 33 字节
📤 发送数据长度: 68 字节

====================================================
【第2次握手】服务器 → 客户端: 接收加密公钥
====================================================
🔓 客户端公钥: 02a1b2c3...
🔐 计算共享密钥...
✅ 共享密钥长度: 32 字节

====================================================
【第3次握手】客户端 → 服务器: 确认配对成功
====================================================
✅ 配对成功,进入加密通讯阶段!

📡 开始加密数据通讯测试
✅ 所有测试通过!
```

### 示例2: 与真实蓝牙设备通讯

```python
from bluetooth_secure_client import BluetoothSecureClient

async def main():
    # 创建安全客户端
    async with BluetoothSecureClient("YourDeviceName") as client:
        # 1. 搜索并连接设备
        if await client.search_device():
            if await client.connect():
                
                # 2. 执行密钥交换握手
                if await client.perform_handshake():
                    
                    # 3. 发送加密消息
                    message = b"Hello Secure World!"
                    await client.send_encrypted_data(message)
                    
                    # 4. 接收加密响应
                    response = await client.receive_encrypted_data()
                    print(f"收到: {response}")

asyncio.run(main())
```

### 示例3: 自定义加密协议

```python
from bluetooth_crypto import EncryptionProtocol

# 创建加密实例
crypto = EncryptionProtocol()

# 生成密钥对
pub_key, priv_key = crypto.generate_ecdh_keypair()

# 加密数据
encrypted_data = crypto.aes256_cbc_encrypt(b"sensitive data")

# 解密数据
plaintext = crypto.aes256_cbc_decrypt(encrypted_data)
```

## 📚 API文档

### EncryptionProtocol

核心加密协议类。

#### 方法

**`generate_ecdh_keypair() -> Tuple[bytes, ec.EllipticCurvePrivateKey]`**
- 生成ECDH密钥对(SECP256R1曲线)
- 返回: (压缩公钥字节, 私钥对象)

**`compute_shared_secret(peer_public_key: bytes) -> bytes`**
- 计算ECDH共享密钥
- 参数: 对端公钥字节
- 返回: 32字节共享密钥

**`aes256_cbc_encrypt(plaintext: bytes) -> bytes`**
- AES-256-CBC加密(用于密钥交换)
- 返回: 十六进制编码的密文

**`aes256_gcm_encrypt(plaintext: bytes) -> Tuple[bytes, bytes]`**
- AES-256-GCM加密(用于数据通讯)
- 返回: (十六进制密文, 十六进制认证标签)

### BluetoothCryptoClient

客户端加密通讯类。

#### 方法

**`async handshake_step1_send_public_key() -> bytes`**
- 第1次握手: 发送加密公钥
- 返回: 待发送的数据包

**`async handshake_step2_receive_server_key(response: bytes) -> bool`**
- 第2次握手: 接收服务器公钥
- 返回: 是否成功

**`async handshake_step3_confirm() -> bytes`**
- 第3次握手: 发送确认
- 返回: 确认数据包

**`async encrypt_send_data(plaintext: bytes) -> bytes`**
- 加密并打包数据
- 返回: 加密数据包

**`async decrypt_receive_data(encrypted_data: bytes) -> bytes`**
- 解密接收的数据
- 返回: 明文数据

### BluetoothSecureClient

完整的蓝牙安全客户端。

#### 方法

**`async search_device(timeout: float = 10.0) -> bool`**
- 搜索蓝牙设备
- 参数: 超时时间(秒)
- 返回: 是否找到

**`async connect() -> bool`**
- 连接蓝牙设备
- 返回: 是否连接成功

**`async perform_handshake() -> bool`**
- 执行完整握手流程
- 返回: 是否握手成功

**`async send_encrypted_data(data: bytes) -> bool`**
- 发送加密数据
- 返回: 是否发送成功

**`async receive_encrypted_data(timeout: float = 10.0) -> Optional[bytes]`**
- 接收并解密数据
- 返回: 明文数据或None

## 🔒 安全特性

### 1. 多层加密保护

- **密钥交换阶段**: AES-256-CBC + ECDH
  - 使用预共享静态密钥保护公钥传输
  - ECDH生成唯一会话密钥
  
- **数据通讯阶段**: AES-256-GCM
  - 使用ECDH共享密钥加密
  - GCM模式提供认证和完整性保护

### 2. 密钥安全

```python
# 静态密钥(用于密钥交换)
STATIC_KEY = bytes([0x30, 0x31, ..., 0x56])  # 32字节

# 静态IV
STATIC_IV = bytes([0x20, 0x21, ..., 0x2f])   # 16字节

# 共享密钥(ECDH生成)
shared_secret = ecdh_compute(...)             # 32字节
```

### 3. 数据完整性

- **GCM认证标签**: 16字节
- **附加认证数据(AAD)**: "12345678"
- 自动验证数据完整性和真实性

### 4. 防重放攻击

- 每次连接生成新的ECDH密钥对
- 共享密钥仅单次会话有效
- 断开连接后自动清除密钥

### 5. 错误处理

```python
class PairStage(IntEnum):
    PAIR_STAGE_WAIT_CONFIRM = 0x00  # 等待确认
    PAIR_STAGE_STATUS_SUCC = 0x01   # 成功
    PAIR_STAGE_FAIL = 0x02          # 失败
```

## 📊 协议数据格式

### 密钥交换协议包

```c
typedef struct {
    uint8_t client_pub_len;  // 公钥长度
    uint8_t is_change;       // 配对状态
    uint8_t data[];          // 变长数据
} KeyMatchHeader;
```

### 加密数据协议包

```c
typedef struct {
    uint32_t data_len;       // 密文长度
    uint32_t tag_len;        // 标签长度(固定16)
    uint8_t data[];          // 密文 + 标签
} EncryptedDataHeader;
```

## 🔧 配置说明

### 蓝牙UUID配置

在 `bluetooth_secure_client.py` 中修改:

```python
class UUIDS:
    SERVICE = "0000ffff-0000-1000-8000-00805f9b34fb"  # 服务UUID
    WRITE = "0000ff01-0000-1000-8000-00805f9b34fb"    # 写入特征
    NOTIFY = "0000ff02-0000-1000-8000-00805f9b34fb"   # 通知特征
```

### 静态密钥配置

在 `bluetooth_crypto.py` 中修改:

```python
class EncryptionProtocol:
    STATIC_KEY = bytes([...])  # 32字节AES密钥
    STATIC_IV = bytes([...])   # 16字节IV
    AAD = b"12345678"          # 附加认证数据
```

## 🧪 测试

### 运行所有测试

```bash
# 基础握手测试
python test_crypto_handshake.py

# 测试输出
✅ 三次握手完成!
✅ 加密数据通讯正常!
✅ 所有测试通过!
```

### 使用pytest

```bash
pip install pytest pytest-asyncio

# 运行测试
pytest test_crypto_handshake.py -v
```

## 🐛 故障排查

### 问题1: 握手失败

**症状**: `PAIR_STAGE_FAIL` 错误

**解决方案**:
1. 检查静态密钥是否一致
2. 验证ECDH曲线配置(SECP256R1)
3. 确认数据包格式正确

### 问题2: 解密失败

**症状**: `aes256_gcm_decrypt` 抛出异常

**解决方案**:
1. 验证共享密钥计算正确
2. 检查GCM认证标签完整性
3. 确认AAD数据一致

### 问题3: 蓝牙连接失败

**症状**: 无法连接设备

**解决方案**:
1. 确认设备名称正确
2. 检查蓝牙是否开启
3. 验证UUID配置
4. 增加搜索超时时间

## 📖 参考资料

- [EN18031蓝牙加密认证标准](图片参考)
- [ECDH密钥交换](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
- [AES-GCM加密模式](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [Bleak蓝牙库文档](https://bleak.readthedocs.io/)

## 📝 许可证

本项目遵循项目整体许可证。

## 🤝 贡献

欢迎提交Issue和Pull Request!

## 📧 联系方式

如有问题,请通过项目Issues联系。

