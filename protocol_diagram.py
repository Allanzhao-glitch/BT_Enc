"""
蓝牙加密协议流程图生成器

生成类似TCP三次握手的协议流程图(文本版)
"""


def print_protocol_flow():
    """打印协议流程图"""

    diagram = """
    
╔══════════════════════════════════════════════════════════════════════════════╗
║                    蓝牙加密通讯协议 - 类似TCP三次握手                          ║
║                           (EN18031认证标准)                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────┐                                              ┌─────────────┐
│   客户端    │                                              │   服务器    │
│  (Client)   │                                              │  (Server)   │
└──────┬──────┘                                              └──────┬──────┘
       │                                                            │
       │ ① 生成客户端ECDH密钥对                                     │
       │    client_private_key, client_public_key                  │
       │                                                            │
       │ ② 使用AES-256-CBC加密客户端公钥                           │
       │    encrypted_client_pub = AES_CBC(client_public_key)      │
       │                                                            │
       │ ③ 发送加密公钥(KeyMatchHeader)                            │
       │ ───────────────────────────────────────────────────────>  │
       │   {client_pub_len, PAIR_STAGE_WAIT_CONFIRM, data}        │
       │                                                            │
       │                                        ④ 解密客户端公钥   │
       │                   client_public_key = AES_CBC_decrypt()   │
       │                                                            │
       │                                    ⑤ 生成服务器ECDH密钥对 │
       │                   server_private_key, server_public_key   │
       │                                                            │
       │                                        ⑥ 计算共享密钥     │
       │                      shared_secret = ECDH(server_private, │
       │                                           client_public)  │
       │                                                            │
       │                              ⑦ 加密服务器公钥             │
       │             encrypted_server_pub = AES_CBC(server_public) │
       │                                                            │
       │ ⑧ 接收加密的服务器公钥                                     │
       │ <───────────────────────────────────────────────────────  │
       │   {server_pub_len, PAIR_STAGE_STATUS_SUCC, data}         │
       │                                                            │
       │ ⑨ 解密服务器公钥                                          │
       │    server_public_key = AES_CBC_decrypt()                  │
       │                                                            │
       │ ⑩ 计算共享密钥                                            │
       │    shared_secret = ECDH(client_private, server_public)    │
       │                                                            │
       │ ⑪ 发送配对成功确认                                        │
       │ ───────────────────────────────────────────────────────>  │
       │   {0, PAIR_STAGE_STATUS_SUCC, ""}                        │
       │                                                            │
       │                                      ⑫ 确认配对成功       │
       │                                         进入通讯阶段       │
       │                                                            │
╔══════════════════════════════════════════════════════════════════════════════╗
║                           加密数据通讯阶段                                    ║
║                        (AES-256-GCM模式)                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
       │                                                            │
       │ ⑬ 加密数据                                                │
       │    ciphertext, tag = AES_GCM(plaintext, shared_secret)    │
       │                                                            │
       │ ⑭ 发送加密数据(EncryptedDataHeader)                       │
       │ ───────────────────────────────────────────────────────>  │
       │   {data_len, tag_len, ciphertext + tag}                  │
       │                                                            │
       │                                          ⑮ 解密数据       │
       │              plaintext = AES_GCM_decrypt(ciphertext, tag, │
       │                                          shared_secret)   │
       │                                                            │
       │ ⑯ 接收加密响应                                            │
       │ <───────────────────────────────────────────────────────  │
       │   {data_len, tag_len, ciphertext + tag}                  │
       │                                                            │
       │ ⑰ 解密响应数据                                            │
       │    plaintext = AES_GCM_decrypt()                          │
       │                                                            │
       ▼                                                            ▼

═══════════════════════════════════════════════════════════════════════════════

【密钥说明】

1. 静态密钥(用于密钥交换阶段)
   - AES-256密钥: 32字节 (0x30-0x56)
   - IV: 16字节 (0x20-0x2f)
   
2. 共享密钥(通过ECDH生成)
   - 算法: ECDH (SECP256R1曲线)
   - 长度: 32字节
   - 用途: 数据通讯阶段的AES-GCM加密

【数据格式】

1. KeyMatchHeader (密钥交换)
   ┌──────────────┬───────────┬─────────────────┐
   │ client_pub_len │ is_change │    data         │
   │   (1 byte)     │ (1 byte)  │  (变长)         │
   └──────────────┴───────────┴─────────────────┘

2. EncryptedDataHeader (数据通讯)
   ┌──────────┬──────────┬─────────────────────┐
   │ data_len │ tag_len  │  ciphertext + tag   │
   │ (4 bytes)│ (4 bytes)│      (变长)         │
   └──────────┴──────────┴─────────────────────┘

【配对状态】
   - 0x00: PAIR_STAGE_WAIT_CONFIRM (等待确认)
   - 0x01: PAIR_STAGE_STATUS_SUCC (配对成功)
   - 0x02: PAIR_STAGE_FAIL (配对失败)

【通讯阶段】
   - 0x00: STAGE_INIT (初始化)
   - 0x01: STAGE_PAIRING (配对中)
   - 0x02: STAGE_COMM (通讯阶段)

═══════════════════════════════════════════════════════════════════════════════
"""

    print(diagram)


def print_encryption_details():
    """打印加密细节"""

    details = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            加密算法详细说明                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

【阶段1: 密钥交换 - AES-256-CBC】

输入参数:
  - 明文: ECDH公钥 (33字节,压缩格式)
  - 密钥: STATIC_KEY (32字节)
  - IV:   STATIC_IV (16字节)
  - 模式: CBC
  - 填充: PKCS7

加密流程:
  1. PKCS7填充明文至16字节倍数
     plaintext_padded = plaintext + padding
     
  2. CBC模式加密
     ciphertext = AES_CBC_Encrypt(plaintext_padded, key, iv)
     
  3. 转换为十六进制字符串
     hex_output = ciphertext.hex()

输出:
  - 密文: 十六进制字符串 (ASCII编码)
  - 长度: 约66字节 (33*2)

─────────────────────────────────────────────────────────────────────────────

【阶段2: 数据通讯 - AES-256-GCM】

输入参数:
  - 明文: 任意数据
  - 密钥: shared_secret (32字节,通过ECDH生成)
  - IV:   STATIC_IV (16字节)
  - AAD:  "12345678" (8字节附加认证数据)
  - 模式: GCM

加密流程:
  1. GCM加密并生成认证标签
     ciphertext, tag = AES_GCM_Encrypt(plaintext, key, iv, aad)
     
  2. 转换为十六进制
     hex_ciphertext = ciphertext.hex()
     hex_tag = tag.hex()
     
  3. 构造协议包
     packet = {
       'data_len': len(hex_ciphertext),
       'tag_len': len(hex_tag),         # 固定32 (16字节*2)
       'data': hex_ciphertext + hex_tag
     }

输出:
  - 密文: 十六进制字符串
  - 标签: 32字节 (16字节tag的hex编码)
  - 完整性: 通过GCM认证保证

解密流程:
  1. 解析协议包获取密文和标签
  2. 转换回二进制
  3. GCM解密并验证标签
     plaintext = AES_GCM_Decrypt(ciphertext, tag, key, iv, aad)
  4. 如果标签验证失败,抛出异常

─────────────────────────────────────────────────────────────────────────────

【ECDH密钥交换】

算法: 椭圆曲线Diffie-Hellman
曲线: SECP256R1 (P-256)

密钥生成:
  1. 生成私钥 (32字节随机数)
     private_key = random(32_bytes)
     
  2. 计算公钥 (椭圆曲线点)
     public_key = private_key * G  (G为基点)
     
  3. 压缩公钥格式 (33字节)
     - 第1字节: 0x02或0x03 (y坐标奇偶性)
     - 后32字节: x坐标

共享密钥计算:
  客户端:
    shared_secret = client_private * server_public
    
  服务器:
    shared_secret = server_private * client_public
    
  结果: 两边计算出相同的32字节共享密钥

安全性:
  - 私钥永不传输
  - 公钥可公开传输
  - 即使截获公钥也无法推导共享密钥
  - 每次连接使用新的密钥对

═══════════════════════════════════════════════════════════════════════════════

【数据示例】

1. 客户端公钥 (压缩格式,33字节):
   02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

2. CBC加密后 (十六进制,66字节):
   3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f...

3. ECDH共享密钥 (32字节):
   f0e1d2c3b4a59687f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087

4. GCM加密数据:
   {
     data_len: 128,
     tag_len: 32,
     data: "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d..." + "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d..."
            └────────── 密文 ──────────┘   └────────── 标签 ──────────┘
   }

═══════════════════════════════════════════════════════════════════════════════
"""

    print(details)


if __name__ == "__main__":
    import io
    import sys

    # 设置UTF-8编码输出
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    print_protocol_flow()
    print("\n" * 2)
    print_encryption_details()
