import socket  # 导入套接字模块，用于网络通信
import time  # 导入时间模块，用于获取当前时间
import struct  # 导入结构体模块，用于打包/解包二进制数据
import random  # 导入随机数模块，用于模拟丢包

# 丢包概率（0.05表示5%的概率丢包）
loss_possibility = 0.05

"""
数据包头部格式说明（使用网络字节序!）:
- 类型 (1字节): 0=SYN(同步请求), 1=SYN_ACK(同步确认), 2=DATA(数据), 3=ACK(确认), 4=ESTABLISH(连接建立)
- 序号 (2字节): 用于DATA数据包的序号（无符号短整型）
- 确认号 (2字节): 用于ACK数据包的确认号（无符号短整型）
- 负载长度 (2字节): 数据负载的字节长度（无符号短整型）
- 校验和 (2字节): 头部+负载的简单校验和（无符号短整型）
"""
header_format = '!BHHHH'  # 定义头部结构体格式（网络字节序）
header_size = struct.calcsize(header_format)  # 计算头部字节长度


def create_packet(packet_type, seq_num=0, ack_num=0, payload=b''):
    """
    创建数据包（头部+负载）
    :param packet_type: 数据包类型（0-4）
    :param seq_num: 序号（默认0）
    :param ack_num: 确认号（默认0）
    :param payload: 负载数据（字节类型，默认空）
    :return: 完整数据包（头部+负载的字节流）
    """
    payload_len = len(payload)  # 计算负载长度
    # 计算校验和（负载字节求和后取模65536）
    checksum = sum(payload) % 65536
    # 打包头部（使用预定义的结构体格式）
    header = struct.pack(header_format, packet_type, seq_num, ack_num, payload_len, checksum)
    return header + payload  # 返回头部+负载的完整数据包


def parse_packet(packet):
    """
    解析数据包（分离头部和负载）
    :param packet: 完整数据包（字节流）
    :return: (类型, 序号, 确认号, 负载长度, 校验和, 负载数据) 元组
    """
    if len(packet) < header_size:
        raise ValueError("数据包过短，无法包含完整头部")
    header_bytes = packet[:header_size]  # 提取头部字节（前header_size字节）
    payload_bytes = packet[header_size:]  # 提取负载字节（剩余部分）

    # 解包头部（按预定义格式解析）
    packet_type, seq_num, ack_num, payload_len, checksum = struct.unpack(header_format, header_bytes)
    return packet_type, seq_num, ack_num, payload_len, checksum, payload_bytes


def main():
    host = '0.0.0.0'  # 监听所有网络接口
    port = 12342  # 监听端口号
    # 创建UDP套接字（AF_INET表示IPv4，SOCK_DGRAM表示UDP）
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))  # 绑定地址和端口
    print(f"服务器正在监听 {host}:{port}")

    next_idx = 1  # 下一个期望按序接收的序号（初始为1）
    data_received = {}  # 存储已接收数据段的字典（键：序号，值：负载数据）
    total_received = 0  # 累计接收的字节数

    print("等待握手...\n")
    handshake_successful1 = False  # SYN确认标志
    handshake_successful2 = False  # 连接建立确认标志
    total_num = 0  # 总数据段数（由客户端通过SYN包告知）

    # 握手过程循环（直到两个握手标志都为True）
    while not handshake_successful1 or not handshake_successful2:
        try:
            data, client_address = server_socket.recvfrom(1024)  # 接收客户端数据（最大1024字节）
            # 解析数据包（仅提取类型和总数据段数，其他字段暂不使用）
            packet_type, total_num, _, _, _, _ = parse_packet(data)

            if packet_type == 0:  # 类型0：SYN（同步请求）
                print(f"接收到来自 {client_address} 的SYN包。正在发送SYN_ACK包。")
                syn_ack_packet = create_packet(1)  # 创建SYN_ACK包（类型1）
                server_socket.sendto(syn_ack_packet, client_address)  # 发送SYN_ACK响应
                handshake_successful1 = True  # 标记SYN确认成功
            elif packet_type == 4:  # 类型4：ESTABLISH（连接建立）
                print(f"接收到来自 {client_address} 的连接建立包。握手完成。")
                handshake_successful2 = True  # 标记连接建立成功
            else:
                print(f"握手过程中接收到来自 {client_address} 的意外数据包类型 {packet_type}。")
        except Exception as e:
            print(f"握手错误: {e}")

    # 数据接收阶段
    print("开始接收数据...\n")
    # 循环直到接收完所有数据段（next_idx达到总数据段数）
    while next_idx < total_num:
        try:
            data, client_address = server_socket.recvfrom(1024)  # 接收客户端数据
            # 解析数据包（获取类型、序号、负载长度、校验和、负载数据）
            packet_type, seq_num, _, payload_len, checksum, payload = parse_packet(data)

            if packet_type == 2:  # 类型2：DATA（数据）
                # 模拟丢包（随机数小于丢包概率时视为丢包）
                if random.random() < loss_possibility:
                    print(f"来自 {client_address} 的序号为 {seq_num} 的数据包已丢失")
                    continue  # 跳过后续处理

                # 输出接收到的DATA包信息
                print(f"接收到来自 {client_address} 的DATA包（序号：{seq_num}，负载长度：{payload_len}）")

                if seq_num == next_idx:  # 序号匹配期望接收的序号
                    data_received[seq_num] = payload  # 存储当前数据段
                    total_received += payload_len  # 累计接收字节数

                    # 滑动窗口：检查是否有连续的已接收数据段（处理按序到达的情况）
                    while next_idx in data_received:
                        next_idx += 1  # 期望序号后移

                    # 发送累积ACK（确认最后一个按序接收的序号）
                    ack_packet = create_packet(3, 0, next_idx - 1)  # 创建ACK包（类型3，确认号为next_idx-1）
                    server_socket.sendto(ack_packet, client_address)  # 发送ACK响应
                    now = time.strftime("%H-%M-%S", time.localtime())  # 获取当前时间（时分秒格式）
                    print(f"{now}: 已向 {client_address} 发送累积确认，确认序号至 {next_idx - 1}")
                else:  # 序号不匹配（乱序或重复）
                    # 对于Go-Back-N协议，丢弃乱序包并重新发送最后一个按序确认的ACK
                    ack_packet = create_packet(3, 0, next_idx - 1)  # 创建ACK包（确认最后一个按序序号）
                    server_socket.sendto(ack_packet, client_address)  # 发送ACK响应
                    print(
                        f"接收到乱序/重复包（序号：{seq_num}）。当前期望接收序号：{next_idx}。重新发送序号 {next_idx - 1} 的确认。")

            else:
                print(f"接收到来自 {client_address} 的意外数据包类型 {packet_type}。")

        except Exception as e:
            print(f"服务器错误: {e}")
            break  # 出现错误时退出循环

    # 拼接所有已接收的负载数据（按序号顺序）
    res_data = ''
    for i in range(1, next_idx):
        res_data += data_received[i].decode()  # 字节数据解码为字符串
    # 输出接收完成信息
    print(f"数据接收完成。累计接收 {total_received} 字节，数据内容：{res_data}")


if __name__ == '__main__':
    main()  # 执行主函数