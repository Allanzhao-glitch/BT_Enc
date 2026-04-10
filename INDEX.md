# 📚 蓝牙加密通讯系统 - 文件索引

## 🎯 快速导航

| 想要... | 查看文件 |
|--------|---------|
| 🚀 **快速开始使用** | [快速入门.md](快速入门.md) |
| 📖 **详细使用说明** | [README.md](README.md) |
| 📊 **项目概览总结** | [项目总结.md](项目总结.md) |
| 💻 **查看代码示例** | [example_usage.py](example_usage.py) |
| 🔍 **理解协议流程** | [protocol_diagram.py](protocol_diagram.py) |
| 🧪 **运行测试** | [test_crypto_handshake.py](test_crypto_handshake.py) |

---

## 📁 文件清单

### 📘 文档文件

#### [README.md](README.md)
**完整的使用文档和API说明**
- 系统架构介绍
- 加密流程详解
- API文档
- 配置说明
- 故障排查
- 安全特性说明

**适合**: 需要完整了解系统的开发者

---

#### [快速入门.md](快速入门.md)
**5分钟快速上手指南**
- 安装步骤
- 基本使用示例
- 常见问题解答
- 实战场景代码

**适合**: 新手用户快速入门

---

#### [项目总结.md](项目总结.md)
**项目完成情况总结**
- 已完成功能清单
- 测试结果
- 技术栈说明
- 代码量统计
- 设计亮点

**适合**: 了解项目整体情况

---

#### [INDEX.md](INDEX.md) (本文件)
**文件导航索引**
- 文件清单
- 快速导航
- 文件关系图

---

### 💻 核心代码文件

#### [bluetooth_crypto.py](bluetooth_crypto.py)
**核心加密协议实现** (857行)

**包含类**:
- `EncryptionProtocol` - 加密协议处理
- `BluetoothCryptoClient` - 客户端加密通讯
- `BluetoothCryptoServer` - 服务端加密通讯
- `KeyMatchHeader` - 密钥交换协议头
- `EncryptedDataHeader` - 加密数据协议头

**功能**:
- ✓ ECDH密钥生成和交换
- ✓ AES-256-CBC加密(密钥交换阶段)
- ✓ AES-256-GCM加密(数据通讯阶段)
- ✓ 三次握手协议实现
- ✓ 数据加密/解密

**适合**: 核心开发者,需要理解加密细节

---

#### [bluetooth_secure_client.py](bluetooth_secure_client.py)
**完整蓝牙安全客户端** (283行)

**包含类**:
- `BluetoothSecureClient` - 集成加密的蓝牙客户端
- `UUIDS` - 蓝牙UUID配置

**功能**:
- ✓ 设备搜索和连接
- ✓ 自动执行加密握手
- ✓ 加密数据收发
- ✓ 通知(Notify)处理
- ✓ 异步上下文管理

**适合**: 应用开发者,直接使用的高层API

---

#### [protocol_diagram.py](protocol_diagram.py)
**协议流程图生成器** (269行)

**功能**:
- ✓ 生成ASCII协议流程图
- ✓ 显示详细的加密步骤
- ✓ 数据格式说明
- ✓ 加密算法详解

**运行**: `python protocol_diagram.py`

**适合**: 需要理解协议流程的开发者

---

### 🧪 测试文件

#### [test_crypto_handshake.py](test_crypto_handshake.py)
**完整的握手和通讯测试** (174行)

**测试用例**:
- ✓ 三次握手流程测试
- ✓ 加密数据通讯测试
- ✓ 错误处理测试
- ✓ 状态验证测试

**运行**: `python test_crypto_handshake.py`

**输出**: 完整的测试报告和日志

**适合**: QA测试,功能验证

---

#### [example_usage.py](example_usage.py)
**实用示例代码集合** (200+行)

**包含示例**:
1. 基本连接和握手
2. 发送加密消息
3. 双向通讯
4. 发送多条消息
5. 发送二进制数据
6. 错误处理

**运行**: `python example_usage.py`

**适合**: 学习如何使用API

---

### 📋 配置文件

#### [requirements.txt](requirements.txt)
**Python依赖包清单**

```txt
cryptography>=41.0.0
bleak>=0.21.0
asyncio>=3.4.3
pytest>=7.4.0
pytest-asyncio>=0.21.0
```

**安装**: `pip install -r requirements.txt`

---

### 🔗 参考实现

#### [aes256.c](aes256.c)
**C语言AES加密实现** (372行)

**功能**:
- AES-256-CBC加密/解密
- AES-256-GCM加密/解密
- ECDH密钥生成
- 共享密钥计算

**用途**: Python实现的参考代码

---

#### [data.c](data.c)
**C语言数据处理实现** (493行)

**功能**:
- 密钥交换逻辑
- 数据加密/解密
- 协议处理
- 状态管理

**用途**: Python实现的参考代码

---

#### [BT_Enc_test.py](BT_Enc_test.py)
**原始蓝牙测试代码** (42行)

**功能**:
- 基本的蓝牙设备搜索
- UUID配置

**用途**: 初始测试代码

---

## 🔄 文件关系图

```
蓝牙加密通讯系统
│
├─── 📚 文档层
│    ├── INDEX.md (本文件)
│    ├── 快速入门.md ──→ 入门用户
│    ├── README.md ──→ 详细文档
│    └── 项目总结.md ──→ 项目概览
│
├─── 💻 核心代码层
│    ├── bluetooth_crypto.py ──→ 加密核心
│    │   ├── EncryptionProtocol
│    │   ├── BluetoothCryptoClient
│    │   └── BluetoothCryptoServer
│    │
│    └── bluetooth_secure_client.py ──→ 蓝牙集成
│        └── BluetoothSecureClient
│             └── 使用 bluetooth_crypto
│
├─── 🧪 测试层
│    ├── test_crypto_handshake.py ──→ 自动化测试
│    └── example_usage.py ──→ 使用示例
│
├─── 🛠️ 工具层
│    ├── protocol_diagram.py ──→ 流程图
│    └── requirements.txt ──→ 依赖管理
│
└─── 🔗 参考实现
     ├── aes256.c ──→ C语言加密
     ├── data.c ──→ C语言数据处理
     └── BT_Enc_test.py ──→ 原始测试
```

## 📖 推荐阅读顺序

### 新手用户
1. **快速入门.md** - 快速上手
2. **example_usage.py** - 查看代码示例
3. **test_crypto_handshake.py** - 运行测试验证
4. **README.md** - 深入了解

### 开发者
1. **项目总结.md** - 了解项目架构
2. **protocol_diagram.py** - 理解协议流程
3. **bluetooth_crypto.py** - 学习核心实现
4. **README.md** - API文档参考

### 集成者
1. **快速入门.md** - 基本使用
2. **bluetooth_secure_client.py** - 高层API
3. **example_usage.py** - 实战示例
4. **README.md** - 配置说明

## 🔍 按需查找

### 想了解加密原理?
→ `bluetooth_crypto.py` + `protocol_diagram.py`

### 想快速使用?
→ `快速入门.md` + `example_usage.py`

### 想修改配置?
→ `README.md` (配置说明章节)

### 想测试功能?
→ `test_crypto_handshake.py`

### 想了解协议?
→ `protocol_diagram.py` + `README.md`

### 遇到问题?
→ `README.md` (故障排查章节) + `快速入门.md` (常见问题)

## 📊 代码统计

| 文件类型 | 文件数 | 代码行数 |
|---------|-------|---------|
| Python核心 | 2 | 1,140 |
| Python测试 | 2 | 370 |
| Python工具 | 1 | 269 |
| C语言参考 | 2 | 865 |
| 文档 | 4 | - |
| 配置 | 1 | - |
| **总计** | **12** | **~2,500** |

## 🎯 使用建议

### 第一次使用
```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 运行测试
python test_crypto_handshake.py

# 3. 查看流程
python protocol_diagram.py
```

### 开发应用
```bash
# 1. 阅读快速入门
cat 快速入门.md

# 2. 参考示例
python example_usage.py

# 3. 集成到项目
# 导入: from bluetooth_secure_client import BluetoothSecureClient
```

### 深入研究
```bash
# 1. 阅读核心代码
cat bluetooth_crypto.py

# 2. 理解C参考实现
cat aes256.c data.c

# 3. 阅读完整文档
cat README.md
```

## 💡 提示

- 📖 所有`.md`文件都可以用文本编辑器打开
- 🏃 所有`.py`文件都可以直接运行
- 🔧 修改配置前建议备份
- 📝 遇到问题先查看文档
- 🧪 修改代码后建议运行测试

---

**最后更新**: 2025-11-03  
**版本**: 1.0.0  
**文件总数**: 12个

🎉 **祝使用愉快!**

