import socket
import time
import struct
import random
import pandas as pd  # 用于RTT统计分析

# 全局配置
loss_possibility = 0.05  # 模拟丢包概率（0.05表示5%的丢包率）
corruption_rate = 0.05  # 模拟数据损坏概率（0.05表示5%的损坏率）
header_format = '!BHHHH'  # 数据包头部格式：!表示网络字节序，B(1字节)为包类型，H(2字节)为序号、确认号等
header_size = struct.calcsize(header_format)  # 计算头部字节大小


def compute_checksum(packet):
    """计算数据包的校验和（简单的字节求和）
    用于验证数据包在传输过程中是否发生损坏
    """
    return sum(packet) % 65536


def create_packet(packet_type, seq_num=0, ack_num=0, payload=b''):
    """创建数据包（包含校验和）
    参数:
        packet_type: 包类型（0=SYN, 1=SYN_ACK, 2=DATA, 3=ACK, 4=ESTABLISH）
        seq_num: 序列号
        ack_num: 确认号
        payload: 负载数据（字节类型）
    返回:
        完整的数据包（头部+负载+校验和）
    """
    payload_len = len(payload)
    # 先创建不带校验和的头部（校验和字段暂时填0）
    header_no_checksum = struct.pack(header_format, packet_type, seq_num, ack_num, payload_len, 0)
    full_packet = header_no_checksum + payload  # 拼接头部和负载
    # 计算整个数据包的校验和
    checksum = compute_checksum(full_packet)
    # 创建包含正确校验和的完整头部
    header = struct.pack(header_format, packet_type, seq_num, ack_num, payload_len, checksum)
    return header + payload


def parse_packet(packet):
    """解析数据包并验证校验和
    参数:
        packet: 接收到的完整数据包
    返回:
        解析后的包类型、序列号、确认号、负载长度、校验和及负载数据
    异常:
        校验和不匹配时抛出ValueError
    """
    if len(packet) < header_size:
        raise ValueError("数据包过短，无法包含完整头部")

    header_bytes = packet[:header_size]
    payload_bytes = packet[header_size:]

    # 解包头部信息
    packet_type, seq_num, ack_num, payload_len, checksum = struct.unpack(header_format, header_bytes)

    # 重新计算校验和进行验证
    header_no_checksum = struct.pack(header_format, packet_type, seq_num, ack_num, payload_len, 0)
    full_packet = header_no_checksum + payload_bytes
    computed_checksum = compute_checksum(full_packet)

    if computed_checksum != checksum:
        raise ValueError("校验和验证失败")

    return packet_type, seq_num, ack_num, payload_len, checksum, payload_bytes


def simulate_corruption(data):
    """模拟数据包损坏（随机修改一个字节）
    用于测试协议的错误处理能力
    """
    if len(data) == 0:
        return data

    pos = random.randint(0, len(data) - 1)
    data_array = bytearray(data)
    data_array[pos] ^= 0xFF  # 翻转一个随机字节，模拟传输错误
    return bytes(data_array)


def main():
    host = '0.0.0.0'  # 监听所有可用网络接口
    port = 12342
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建UDP套接字
    server_socket.bind((host, port))  # 绑定地址和端口
    print(f"服务器正在监听 {host}:{port}")

    # 统计信息
    total_packets = 0  # 接收的总包数
    corrupted_count = 0  # 损坏的包数
    lost_count = 0  # 模拟丢失的包数
    rtt_list = []  # 存储每个数据包的RTT值

    # 连接状态
    next_idx = 1  # 期望接收的下一个数据包序号
    data_received = {}  # 已接收的数据包（按序号存储）
    total_received = 0  # 累计接收的字节数
    handshake_successful1 = False  # 第一次握手完成标志（SYN包）
    handshake_successful2 = False  # 第二次握手完成标志（ESTABLISH包）
    total_num = 0  # 预计接收的数据包总数

    print("等待握手...\n")
    # 三次握手过程
    while not handshake_successful1 or not handshake_successful2:
        try:
            data, client_address = server_socket.recvfrom(1024)

            # 模拟数据损坏
            if random.random() < corruption_rate:
                data = simulate_corruption(data)
                corrupted_count += 1

            try:
                packet_type, total_num, _, _, _, _ = parse_packet(data)
            except ValueError as e:
                print(f"数据包错误: {e}")
                continue

            if packet_type == 0:  # SYN包（客户端发起连接）
                print(f"接收到来自 {client_address} 的SYN包。正在发送SYN_ACK包。")
                syn_ack_packet = create_packet(1)  # 创建SYN_ACK响应包
                server_socket.sendto(syn_ack_packet, client_address)
                handshake_successful1 = True
            elif packet_type == 4:  # ESTABLISH包（客户端确认连接）
                print(f"接收到来自 {client_address} 的连接建立包。握手完成。")
                handshake_successful2 = True
            else:
                print(f"握手过程中接收到来自 {client_address} 的意外数据包类型 {packet_type}。")
        except Exception as e:
            print(f"握手错误: {e}")

    # 数据接收阶段（使用滑动窗口协议）
    print("开始接收数据...\n")
    while next_idx < total_num:
        try:
            data, client_address = server_socket.recvfrom(1024)
            total_packets += 1

            # 模拟丢包（用于测试协议的重传机制）
            if random.random() < loss_possibility:
                print(f"来自 {client_address} 的数据包已丢失")
                lost_count += 1
                continue

            # 模拟数据损坏（用于测试协议的错误检测机制）
            if random.random() < corruption_rate:
                data = simulate_corruption(data)
                corrupted_count += 1

            try:
                recv_time = time.perf_counter()  # 使用高精度计时器记录接收时间
                packet_type, seq_num, _, payload_len, _, payload = parse_packet(data)
            except ValueError as e:
                print(f"数据包错误: {e}")
                continue

            if packet_type == 2:  # DATA包（客户端发送的数据）
                print(f"接收到来自 {client_address} 的DATA包（序号：{seq_num}，负载长度：{payload_len}）")

                if seq_num == next_idx:  # 按序到达的数据包
                    data_received[seq_num] = payload
                    total_received += payload_len

                    # 滑动窗口：尝试向前移动窗口基序号
                    while next_idx in data_received:
                        next_idx += 1

                    # 模拟网络延迟（使RTT计算更真实）
                    network_delay = random.uniform(0.01, 0.1)  # 10-100ms随机延迟
                    time.sleep(network_delay)

                    # 发送ACK（确认已接收至next_idx-1的所有包）
                    ack_packet = create_packet(3, 0, next_idx - 1)
                    server_socket.sendto(ack_packet, client_address)

                    # 计算RTT（往返时间）
                    rtt = (time.perf_counter() - recv_time) * 1000  # 转换为毫秒
                    rtt_list.append(rtt)

                    now = time.strftime("%H-%M-%S", time.localtime())
                    print(f"{now}: 已向 {client_address} 发送累积确认，确认序号至 {next_idx - 1}，RTT: {rtt:.2f}ms")
                else:  # 乱序包（序号不等于期望的next_idx）
                    # 模拟网络延迟
                    time.sleep(random.uniform(0.01, 0.1))

                    # 发送对已接收的最高连续包的确认（累积确认）
                    ack_packet = create_packet(3, 0, next_idx - 1)
                    server_socket.sendto(ack_packet, client_address)
                    print(
                        f"接收到乱序/重复包（序号：{seq_num}）。当前期望接收序号：{next_idx}。重新发送序号 {next_idx - 1} 的确认。")
            else:
                print(f"接收到来自 {client_address} 的意外数据包类型 {packet_type}。")

        except Exception as e:
            print(f"服务器错误: {e}")
            break

    # 拼接完整数据（按序号顺序）
    res_data = ''
    for i in range(1, next_idx):
        if i in data_received:
            res_data += data_received[i].decode()
        else:
            res_data += f"[缺失包 {i}]"  # 标记可能存在的缺失包

    # 输出统计信息
    print(f"\n数据接收完成。累计接收 {total_received} 字节")
    print(f"总接收包数: {total_packets}")
    print(f"丢包数: {lost_count} ({lost_count / total_packets * 100:.2f}%)")
    print(f"损坏包数: {corrupted_count} ({corrupted_count / total_packets * 100:.2f}%)")

    if rtt_list:
        rtt_series = pd.Series(rtt_list)
        print(f"平均RTT: {rtt_series.mean():.2f}ms")
        print(f"最大RTT: {rtt_series.max():.2f}ms")
        print(f"最小RTT: {rtt_series.min():.2f}ms")
        print(f"RTT标准差: {rtt_series.std():.2f}ms")
    else:
        print("未收集到RTT数据。")

    # 输出完整数据内容
    print("\n完整数据内容:")
    print(res_data)
    print(f"(数据长度: {len(res_data)} 字符)")


if __name__ == '__main__':
    main()