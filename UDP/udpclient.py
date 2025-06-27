import socket
import time
import struct
import sys
import random
import pandas as pd


# 全局配置
TIMEOUT_MS = 300                  # 超时时间（毫秒）
loss_possibility = 0.05           # 接收时丢包概率（模拟网络不可靠性）
corruption_rate = 0.05            # 接收时数据损坏概率（模拟网络噪声）
header_format = '!BHHHH'          # 数据包头部格式：!表示网络字节序，B(1字节)为包类型，H(2字节)为序号等
header_size = struct.calcsize(header_format)  # 计算头部字节大小


def compute_checksum(packet):
    """计算数据包的校验和（简单的字节求和）
    用于检测数据包在传输过程中是否发生损坏
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
    用于测试协议的错误检测和恢复能力
    """
    if len(data) == 0:
        return data

    pos = random.randint(0, len(data) - 1)
    data_array = bytearray(data)
    data_array[pos] ^= 0xFF  # 翻转一个随机字节，模拟传输错误
    return bytes(data_array)


def split_random(data, Lmin=40, Lmax=80):
    """随机分割数据为多个数据段（用于模拟实际网络中的MTU限制）
    参数:
        data: 待分割的字符串数据
        Lmin: 最小段长度
        Lmax: 最大段长度
    返回:
        分割后的元组列表 [(数据段, 起始字节位置), ...]
    """
    chunks = [('null'.encode(), 0)]  # 初始段（占位）
    total_size = len(data)
    current = 0

    while current < total_size:
        remaining = total_size - current
        if remaining <= Lmin:
            chunk_size = remaining  # 剩余数据不足Lmin时，全部作为一个段
        else:
            chunk_size = random.randint(Lmin, min(Lmax, remaining))  # 随机选择段长度
        chunks.append((data[current:current + chunk_size].encode(), current))  # 确保是字节类型
        current += chunk_size

    return chunks


def main():
    # 检查命令行参数
    if len(sys.argv) != 3:
        print("使用方法: python udpclient.py <服务器IP> <服务器端口>")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建UDP套接字
    client_socket.settimeout(TIMEOUT_MS / 1000.0)  # 设置超时时间（秒）

    print(f"客户端已启动，正在连接 {server_ip}:{server_port}")

    # 统计信息
    rtts = []                   # 存储每个数据包的RTT值
    retransmission_cnt = 0      # 重传次数
    initial_transmission_cnt = 0  # 初始传输次数
    corrupted_count = 0         # 损坏的包数
    lost_count = 0              # 模拟丢失的包数

    # 生成测试数据（0到799的数字字符串）
    total_message = ' '.join(str(i) for i in range(800))
    segments_to_send = split_random(total_message)  # 随机分割数据为多个段
    len_segments = len(segments_to_send)  # 数据段总数

    # 握手阶段（三次握手协议实现）
    print("正在发起握手...\n")
    syn_packet = create_packet(0)  # 创建SYN包（连接请求）
    handshake_successful = False
    retries = 0
    max_handshake_retries = 5  # 最大握手重试次数

    while not handshake_successful and retries < max_handshake_retries:
        try:
            start_time = time.perf_counter()  # 使用高精度计时器记录发送时间
            client_socket.sendto(syn_packet, (server_ip, server_port))
            print(f"已发送SYN包，尝试次数：{retries + 1}")

            # 接收响应
            response, _ = client_socket.recvfrom(1024)
            end_time = time.perf_counter()

            # 模拟网络延迟（用于测试RTT计算）
            network_delay = random.uniform(0.01, 0.1)  # 模拟10-100ms随机延迟
            time.sleep(network_delay)
            end_time += network_delay  # 调整结束时间以包含模拟延迟

            # 模拟丢包（用于测试协议的鲁棒性）
            if random.random() < loss_possibility:
                print("模拟丢包，丢弃接收的包")
                lost_count += 1
                continue

            # 模拟数据损坏
            if random.random() < corruption_rate:
                response = simulate_corruption(response)
                corrupted_count += 1

            try:
                pkt_type, _, _, _, _, _ = parse_packet(response)
            except ValueError as e:
                print(f"数据包错误: {e}")
                continue

            if pkt_type == 1:  # SYN_ACK（服务器响应）
                print("收到SYN_ACK包，握手成功。")
                # 发送ESTABLISH包确认连接，并告知服务器总段数
                establish_message = create_packet(4, len_segments)
                client_socket.sendto(establish_message, (server_ip, server_port))
                handshake_successful = True
            else:
                print("握手过程中接收到意外类型的数据包。")
        except socket.timeout:
            print("超时，正在重试...")
            retries += 1
        except Exception as e:
            print(f"握手错误: {e}")
            break

    if not handshake_successful:
        print("多次重试后握手仍未成功，程序退出。")
        return

    print("数据传输开始！\n")

    # Go-Back-N协议实现（滑动窗口机制）
    base = 1                 # 窗口基序号（最早未确认的包）
    next_seq_num = 1         # 下一个可用的序列号
    window_size = 5          # 滑动窗口大小
    sent_packets = {}        # 已发送但未确认的包 {序号: (数据包, 发送时间, 起始字节)}

    while base < len_segments:  # 当还有数据需要发送时
        # 发送窗口内的包（只要窗口未满且还有数据）
        while next_seq_num < len_segments and next_seq_num < base + window_size:
            segment, start_byte = segments_to_send[next_seq_num]
            packet = create_packet(2, next_seq_num, 0, segment)  # 创建DATA包
            client_socket.sendto(packet, (server_ip, server_port))

            # 使用高精度计时器记录发送时间
            send_time = time.perf_counter()
            sent_packets[next_seq_num] = (packet, send_time, start_byte)  # 记录已发送的包

            end_byte = start_byte + len(segment) - 1
            print(f"客户端已发送第 {next_seq_num} 号包（{start_byte}-{end_byte} 字节）")

            initial_transmission_cnt += 1
            next_seq_num += 1

        # 等待ACK或处理超时
        try:
            ack_response, _ = client_socket.recvfrom(1024)

            # 模拟ACK包丢包
            if random.random() < loss_possibility:
                print("模拟丢包，丢弃接收的ACK包")
                lost_count += 1
                continue

            # 模拟ACK包数据损坏
            if random.random() < corruption_rate:
                ack_response = simulate_corruption(ack_response)
                corrupted_count += 1

            try:
                pkt_type, _, ack_num, _, _, _ = parse_packet(ack_response)
            except ValueError as e:
                print(f"ACK包错误: {e}")
                continue

            if pkt_type == 3:  # ACK包（服务器确认）
                if ack_num >= base:
                    # 处理所有被确认的包（累积确认机制）
                    for i in range(base, ack_num + 1):
                        if i in sent_packets:
                            _, send_time_float, _ = sent_packets[i]
                            # 计算更精确的RTT（往返时间）
                            rtt = (time.perf_counter() - send_time_float) * 1000
                            rtts.append(rtt)
                            del sent_packets[i]  # 从待确认队列中移除已确认的包
                            print(f"第 {i} 号包已被服务器接收，RTT为 {rtt:.2f} 毫秒")
                    base = ack_num + 1  # 滑动窗口基序号
                else:
                    print(f"收到重复或无效的ACK {ack_num}（当前窗口基序号为 {base}）")
            else:
                print(f"数据传输过程中接收到意外类型的数据包 {pkt_type}")

        except socket.timeout:
            print(f"{base} 号包超时，正在从 {base} 号包开始重传...")
            retransmission_cnt += (next_seq_num - base)  # 记录重传次数

            # 回退N步：重传窗口内所有未确认的包
            for seq_to_retransmit in range(base, next_seq_num):
                if seq_to_retransmit in sent_packets:
                    packet_data, _, start_byte = sent_packets[seq_to_retransmit]
                    client_socket.sendto(packet_data, (server_ip, server_port))
                    # 更新发送时间（用于重新计算RTT）
                    sent_packets[seq_to_retransmit] = (packet_data, time.perf_counter(), start_byte)

                    end_byte = start_byte + len(packet_data) - 1
                    print(f"重传第 {seq_to_retransmit} 号包（{start_byte}-{end_byte} 字节）")
                else:
                    print(f"未找到 {seq_to_retransmit} 号包，无法重传")
        except Exception as e:
            print(f"数据传输过程中发生错误: {e}")
            break

    print("数据传输完成。\n")
    print("统计结果：\n")

    # 计算传输统计
    total_transmissions = initial_transmission_cnt + retransmission_cnt
    if total_transmissions > 0:
        packet_loss_rate = (retransmission_cnt / total_transmissions) * 100
    else:
        packet_loss_rate = 0

    print(f"丢包率: {packet_loss_rate:.2f}%")
    print(f"初始传输次数: {initial_transmission_cnt}")
    print(f"重传次数: {retransmission_cnt}")
    print(f"损坏包数: {corrupted_count}")
    print(f"丢失包数: {lost_count}")

    if rtts:
        rtt_series = pd.Series(rtts)
        min_rtt = rtt_series.min()
        max_rtt = rtt_series.max()
        avg_rtt = rtt_series.mean()
        std_rtt = rtt_series.std()
        print(f"整个过程中最大RTT: {max_rtt:.2f} 毫秒")
        print(f"整个过程中最小RTT: {min_rtt:.2f} 毫秒")
        print(f"整个过程中平均RTT: {avg_rtt:.2f} 毫秒")
        print(f"整个过程中RTT标准差: {std_rtt:.2f} 毫秒")
    else:
        print("未收集到RTT数据。")

    client_socket.close()
    print("客户端已关闭。")


if __name__ == '__main__':
    main()