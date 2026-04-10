# BluFi 传输机制完善总结

## 概述

本文档总结了对 `bluetooth_secure_client.py` 中 BluFi 协议传输和接收机制的完善工作。所有改进均参考了 `pyBlufi` 的标准实现，确保与 ESP-IDF BluFi 协议完全兼容。

---

## 主要改进

### 1. ✅ 完善 BluFi 分片发送机制

#### 改进内容
- **添加总长度字段**: 分片包的载荷前 2 字节包含总数据长度（小端序）
- **正确的分片标志**: 使用 Frame Control 的 Bit 4 标识分片
- **序列号管理**: 每个分片使用独立的序列号（0-255 循环）

#### 实现细节
```python
# 分片包格式: [Type][FrameCtrl][Seq][Length][TotalLen(2字节)][Data][Checksum(可选)]
if has_more_frags or frag_index > 0:
    total_len = data_len  # 第一个分片包含完整的总长度
    frag_payload = struct.pack("<H", total_len) + frag_data
```

#### 参考代码
- `pyBlufi/blufi/client.py`: `postContainData()` 方法（第 407-461 行）

---

### 2. ✅ 完善 BluFi 分片接收机制

#### 改进内容
- **解析总长度字段**: 从分片包中提取前 2 字节的总长度信息
- **自动重组**: 累积分片数据直到接收完整包
- **序列号验证**: 检查分片序列号的连续性

#### 实现细节
```python
# 解析分片包
if is_frag and len(payload) >= 2:
    total_len = struct.unpack("<H", payload[:2])[0]  # 提取总长度
    actual_payload = payload[2:]  # 实际数据从第 3 字节开始
```

#### 参考代码
- `pyBlufi/blufi/client.py`: `parseNotification()` 方法（第 307-366 行）

---

### 3. ✅ 添加 CRC 校验和支持

#### 改进内容
- **CRC-16/XMODEM 算法**: 实现了与 pyBlufi 完全相同的 CRC 计算
- **发送端校验**: 自动计算并附加 2 字节校验和
- **接收端验证**: 验证接收数据的完整性

#### 实现细节
```python
class BlufiCRC:
    """BluFi CRC 校验和计算 (CRC-16/XMODEM)"""
    
    @staticmethod
    def calc_crc(crc: int, data: bytes) -> int:
        crc = (~crc) & 0xffff
        for byte in data:
            crc = BlufiCRC.CRC_TB[(crc >> 8) ^ (byte & 0xff)] ^ (crc << 8)
            crc &= 0xffff
        return (~crc) & 0xffff
```

#### 校验和格式
```
校验和计算: CRC(seq + data_len + payload)
包格式: [Type][FrameCtrl][Seq][Length][Payload][Checksum(2字节,小端序)]
```

#### 参考代码
- `pyBlufi/blufi/security/crc.py`: `BlufiCRC` 类
- `pyBlufi/blufi/client.py`: `getPostBytes()` 方法（第 368-398 行）

---

### 4. ✅ 优化 MTU 自动获取和包大小限制

#### 改进内容
- **自动 MTU 检测**: 连接时自动获取协商的 MTU 大小
- **平台兼容性**: Linux 平台使用默认值（bluez 不提供 MTU API）
- **手动限制**: 支持手动设置包长度限制

#### 实现细节
```python
# 自动获取 MTU
if platform.system() != 'Linux':
    self.mtu_size = self.client.mtu_size
else:
    self.mtu_size = 247  # 默认值

# 计算最大分片大小
def get_max_fragment_size(self) -> int:
    pkg_limit = self.package_length_limit if self.package_length_limit > 0 else (self.mtu_size - 4)
    max_frag_size = pkg_limit - 4 - 2  # 减去包头和总长度字段
    return max_frag_size
```

#### 包大小计算
```
可用数据 = MTU - 4(BluFi头) - 2(总长度) - 2(校验和,可选)
例如: 247 - 4 - 2 - 2 = 239 字节/片
```

#### API 方法
```python
# 手动设置包长度限制
client.set_package_length_limit(256)  # 适用于 Linux 或特殊场景
```

#### 参考代码
- `pyBlufi/blufi/client.py`: `setPostPackageLengthLimit()` 方法（第 90-99 行）
- `pyBlufi/blufi/client.py`: `_connect_async_name()` 方法（第 154-183 行）

---

### 5. ✅ 添加 ACK 确认机制

#### 改进内容
- **ACK 请求**: 支持在 Frame Control 中设置 Bit 3 请求 ACK
- **ACK 解析**: 识别并解析 ACK 包（Type=0x00, SubType=0x00）
- **异步等待**: 使用事件机制等待 ACK 确认
- **超时处理**: 支持可配置的 ACK 超时时间

#### 实现细节
```python
# 发送时请求 ACK
async def send_encrypted_data(self, data: bytes, require_ack: bool = False):
    frame_ctrl = 0x08 if require_ack else 0x00  # Bit 3: Require ACK
    
    # 等待 ACK
    if require_ack:
        ack_received = await self.wait_for_ack(current_seq, timeout=5.0)
        if not ack_received:
            return False  # ACK 超时，发送失败

# 接收 ACK
def _notification_handler(self, sender, data):
    if pkg_type == 0x00 and sub_type == 0x00:  # ACK 包
        ack_seq = self.parse_ack_packet(payload)
        self.notify_ack_received(ack_seq)
```

#### ACK 包格式
```
Type: 0x00 (CTRL.PACKAGE_VALUE | CTRL.SUBTYPE_ACK)
Payload: [seq(1字节)]
```

#### 参考代码
- `pyBlufi/blufi/client.py`: `parseAck()` 方法（第 272-278 行）
- `pyBlufi/blufi/client.py`: `postContainData()` 方法（第 454-455 行）

---

## BluFi 协议详解

### 包格式

#### 完整包格式
```
[Type(1)] [FrameCtrl(1)] [Seq(1)] [Length(1)] [Payload(N)] [Checksum(2,可选)]
```

#### 分片包格式
```
[Type(1)] [FrameCtrl(1)] [Seq(1)] [Length(1)] [TotalLen(2)] [Data(N)] [Checksum(2,可选)]
```

### Frame Control 字段

| Bit | 名称 | 说明 |
|-----|------|------|
| 0 | Encrypted | 加密标志 (1=加密, 0=未加密) |
| 1 | Checksum | 校验标志 (1=有校验, 0=无校验) |
| 2 | Direction | 数据方向 (1=发送, 0=接收) |
| 3 | RequireAck | 需要应答 (1=需要, 0=不需要) |
| 4 | Frag | 分片标志 (1=分片, 0=完整) |
| 5-7 | Reserved | 保留位 |

### Type 字段

```
Type = (SubType << 2) | PackageType
```

- **PackageType** (低 2 位):
  - `0x00`: CTRL (控制包)
  - `0x01`: DATA (数据包)

- **SubType** (高 6 位):
  - CTRL: `0x00`=ACK, `0x01`=SetSecMode, `0x02`=SetOpMode, ...
  - DATA: `0x00`=Negotiate, `0x04`=CustomData, ...

---

## 使用示例

### 基本使用

```python
from bluetooth_secure_client import BluetoothSecureClient

# 创建客户端
client = BluetoothSecureClient("BLUFI_DEVICE")

# 搜索并连接设备
await client.search_device()
await client.connect()

# 执行握手
await client.perform_handshake()

# 发送加密数据（自动分片）
data = b"Hello, World!" * 100  # 大数据
await client.send_encrypted_data(data)

# 接收加密数据
response = await client.receive_encrypted_data()
```

### 高级配置

```python
# 手动设置包长度限制（适用于 Linux 或特殊场景）
client.set_package_length_limit(256)

# 发送数据并要求 ACK 确认
await client.send_encrypted_data(data, require_ack=True)

# 配置 ACK 超时时间
client.ack_timeout = 10.0  # 10 秒
```

---

## 性能优化

### 分片策略

1. **自动分片**: 根据 MTU 自动计算最佳分片大小
2. **延迟控制**: 分片之间延迟 50ms，避免接收端缓冲区溢出
3. **可靠传输**: 优先使用 write-with-response，失败时降级到 write-without-response

### MTU 配置建议

| 平台 | 默认 MTU | 推荐配置 |
|------|----------|----------|
| Windows | 247 | 自动检测 |
| Android | 247 | 自动检测 |
| Linux | 20 | 手动设置 256 |
| ESP32 | 256 | 可配置到 512 |

---

## 与 pyBlufi 的兼容性

### 完全兼容的特性

✅ 分片机制（总长度字段）  
✅ CRC-16 校验和  
✅ MTU 自动检测  
✅ 序列号管理  
✅ Frame Control 标志  

### 部分兼容的特性

⚠️ **ACK 机制**: pyBlufi 中 ACK 处理尚未完全实现（有 TODO 标记），本实现提供了完整的 ACK 支持  
⚠️ **加密支持**: 本实现使用自定义加密（bluetooth_crypto），而 pyBlufi 使用 DH 密钥交换 + AES-128-CFB

---

## 测试建议

### 分片测试

```python
# 测试小数据（不分片）
small_data = b"Hello"
await client.send_encrypted_data(small_data)

# 测试大数据（自动分片）
large_data = b"X" * 1000
await client.send_encrypted_data(large_data)

# 测试超大数据
huge_data = b"Y" * 10000
await client.send_encrypted_data(huge_data)
```

### 校验和测试

```python
# 启用校验和
client.create_blufi_packet(data, seq, enable_checksum=True)

# 验证接收数据的校验和
# 自动在 parse_blufi_packet() 中验证
```

### ACK 测试

```python
# 发送并等待 ACK
success = await client.send_encrypted_data(data, require_ack=True)
if not success:
    print("ACK 超时，发送失败")
```

---

## 故障排查

### 常见问题

1. **分片丢失**
   - 检查 MTU 设置是否正确
   - 增加分片之间的延迟时间
   - 启用 ACK 确认机制

2. **校验和错误**
   - 确认发送端和接收端使用相同的校验算法
   - 检查数据是否在传输过程中被修改

3. **ACK 超时**
   - 增加 ACK 超时时间
   - 检查接收端是否正确发送 ACK
   - 确认通知功能已启用

4. **Linux 平台 MTU 问题**
   - 手动设置包长度限制: `client.set_package_length_limit(256)`

---

## 参考资料

1. **pyBlufi 项目**: https://github.com/someburner/pyBlufi
2. **ESP-IDF BluFi 文档**: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/blufi.html
3. **BluFi 协议规范**: ESP32 BluFi Protocol Specification
4. **CRC-16/XMODEM**: https://en.wikipedia.org/wiki/Cyclic_redundancy_check

---

## 版本历史

- **v1.0** (2025-11-17): 初始版本，完善 BluFi 传输和接收机制
  - 添加分片总长度字段
  - 实现 CRC-16 校验和
  - 优化 MTU 自动获取
  - 添加 ACK 确认机制

---

## 作者

基于 pyBlufi 项目的实现，参考 ESP-IDF BluFi 协议规范完成。

