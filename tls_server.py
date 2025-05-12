import socket
import json
import ssl
from typing import Dict, Any
import time
from xmi_logger import XmiLogger
import binascii
import hashlib

logger = XmiLogger(
    file_name="test",
)


def start_server(host: str, port: int):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_NONE
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        logger.info(f"服务器启动 - Listening on {host}:{port}")
        
        while True:
            try:
                # 接收原始TCP连接
                raw_conn, addr = s.accept()
                client_ip, client_port = addr  # 提取IP和端口
                ip_addr = f'{client_ip}:{client_port}'
                # 接收原始数据（包含ClientHello）
                raw_data = raw_conn.recv(8192, socket.MSG_PEEK)
                time.sleep(0.01)
                raw_data_2 = raw_conn.recv(8192, socket.MSG_PEEK)
                if len(raw_data_2) > len(raw_data):
                    raw_data = raw_data_2

                logger.info(f"接收到客户端 {ip_addr} 的原始数据: {raw_data}")
                
                # 解析原始TLS数据
                tls_info = parse_raw_tls_data(raw_data)
                
                # 计算JA3指纹
                ja3_fingerprint = calculate_ja3_fingerprint(tls_info)
                if ja3_fingerprint:
                    tls_info["ja3_fingerprint"] = ja3_fingerprint
                
                # 初始化headers字段
                tls_info["headers"] = {}
                
                logger.info(f"接收到客户端 {ip_addr} 的原始TLS数据解析结果: {json.dumps(tls_info, indent=4, ensure_ascii=False)}")
               
                ssl_conn = context.wrap_socket(raw_conn, server_side=True)
                handle_connection(ssl_conn, addr, tls_info)  # 传递tls_info参数
                
            except Exception as e:
                logger.error(f"连接错误: {e}")


def handle_connection(ssl_conn: ssl.SSLSocket, addr: tuple, tls_info: Dict[str, Any] = None):
    client_ip, client_port = addr
    client_addr = f"{client_ip}:{client_port}"
    try:
        # 解析TLS信息（此时会执行握手）
        conn_tls_info = parse_tls_client_hello(ssl_conn)
        logger.info(f"客户端 {client_addr} TLS握手信息: {conn_tls_info}")
        
        # 读取HTTP请求
        request = ssl_conn.recv(4096)
        if not request:
            logger.warning(f"客户端 {client_addr} 没有发送任何数据")
            return
            
        logger.info(f"客户端 {client_addr} 原始请求数据: {request}")
        
        try:
            decoded_request = request.decode('utf-8', errors='replace')
            http_headers = parse_http_headers(decoded_request)
            logger.info(f"客户端 {client_addr} HTTP请求头: {http_headers}")
            
            # 将HTTP头信息添加到tls_info中
            if tls_info is not None:
                tls_info["headers"] = http_headers
                logger.info(f"已更新客户端 {client_addr} 的TLS信息，添加了HTTP头: {json.dumps(tls_info, indent=4, ensure_ascii=False)}")
            
            # 检查是否为空请求或只有空行
            if not http_headers or ('Method' not in http_headers and 'Path' not in http_headers):
                logger.warning(f"客户端 {client_addr} 发送了无效的HTTP请求")
                error_response = generate_error_response("无效的HTTP请求", tls_info)
                ssl_conn.sendall(error_response.encode())
                return
                
        except Exception as e:
            logger.error(f"解析HTTP请求头时出错: {e}")
            http_headers = {"error": str(e)}
            
        # 生成响应，传入TLS信息
        response = generate_response('检测通过!', tls_info)
        ssl_conn.sendall(response.encode())
        logger.info(f"已向客户端 {client_addr} 发送成功响应")
        
    except Exception as e:
        logger.error(f"处理客户端 {client_addr} 连接时出错: {e}")
        error_response = generate_error_response(str(e), tls_info)
        try:
            ssl_conn.sendall(error_response.encode())
        except Exception as send_error:
            logger.error(f"发送错误响应时出错: {send_error}")
    finally:
        ssl_conn.close()


def calculate_ja3_fingerprint(tls_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    计算JA3指纹、peetprint指纹和JA4指纹
    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    """
    try:
        # 检查是否是有效的TLS ClientHello
        if not tls_info.get("is_tls") or tls_info.get("handshake_type") != "ClientHello (0x01)":
            return {}
        
        # 1. TLS版本
        client_version = tls_info.get("client_version", "")
        if not client_version:
            return {}
        
        # 移除点号，只保留数字
        version_parts = client_version.split(".")
        if len(version_parts) != 2:
            return {}
        
        tls_version = version_parts[0] + version_parts[1]
        
        # 2. 密码套件
        cipher_suites = tls_info.get("cipher_suites", [])
        # 移除"0x"前缀
        cipher_suites_str = ",".join([cs.replace("0x", "") for cs in cipher_suites])
        
        # 为格式化JA3字符串准备的密码套件（使用连字符连接）
        cipher_suites_decimal = []
        for cs in cipher_suites:
            if cs.startswith("0x"):
                cipher_suites_decimal.append(str(int(cs.replace("0x", ""), 16)))
        cipher_suites_formatted = "-".join(cipher_suites_decimal)
        
        # 3. 扩展类型
        extensions = tls_info.get("extensions", [])
        extension_types = []
        extension_types_formatted = []
        elliptic_curves = []
        ec_point_formats = []
        
        for ext in extensions:
            ext_type = ext.get("type", "")
            if ext_type.startswith("0x"):
                # 移除"0x"前缀并转换为十进制
                ext_type_num = int(ext_type.replace("0x", ""), 16)
                extension_types.append(str(ext_type_num))
                extension_types_formatted.append(str(ext_type_num))
                
                # 提取椭圆曲线信息 (扩展类型10)
                if ext_type_num == 10:  # 支持的曲线组
                    try:
                        data = binascii.unhexlify(ext.get("data", ""))
                        if len(data) >= 2:
                            curves_length = (data[0] << 8) | data[1]
                            pos = 2
                            while pos < curves_length + 2 and pos + 1 < len(data):
                                curve_id = (data[pos] << 8) | data[pos + 1]
                                elliptic_curves.append(str(curve_id))
                                pos += 2
                    except Exception:
                        pass
                
                # 提取椭圆曲线格式信息 (扩展类型11)
                elif ext_type_num == 11:  # EC点格式
                    try:
                        data = binascii.unhexlify(ext.get("data", ""))
                        if len(data) >= 1:
                            formats_length = data[0]
                            for i in range(1, formats_length + 1):
                                if i < len(data):
                                    ec_point_formats.append(str(data[i]))
                    except Exception:
                        pass
        
        # 组合扩展类型
        extensions_str = ",".join(extension_types) if extension_types else ""
        # 格式化扩展类型（使用连字符连接）
        extensions_formatted = "-".join(extension_types_formatted) if extension_types_formatted else ""
        
        # 组合椭圆曲线信息
        elliptic_curves_str = ",".join(elliptic_curves) if elliptic_curves else ""
        # 格式化椭圆曲线信息（使用连字符连接）
        elliptic_curves_formatted = "-".join(elliptic_curves) if elliptic_curves else ""
        
        # 组合椭圆曲线格式信息
        ec_point_formats_str = ",".join(ec_point_formats) if ec_point_formats else ""
        # 格式化椭圆曲线格式信息（使用连字符连接）
        ec_point_formats_formatted = "-".join(ec_point_formats) if ec_point_formats else ""
        
        # 构建JA3字符串
        ja3_str = f"{tls_version},{cipher_suites_str},{extensions_str},{elliptic_curves_str},{ec_point_formats_str}"
        
        # 构建格式化JA3字符串（使用连字符分隔各部分内部元素）
        ja3_formatted = f"{tls_version},{cipher_suites_formatted},{extensions_formatted},{elliptic_curves_formatted},{ec_point_formats_formatted}"
        
        # 计算MD5哈希
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        
        # 动态生成peetprint指纹
        # 检测GREASE值并标记
        grease_values = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]
        
        # 处理密码套件，标记GREASE值
        cipher_parts = []
        for cs in cipher_suites:
            if cs.startswith("0x"):
                cs_value = int(cs.replace("0x", ""), 16)
                if cs_value in grease_values:
                    cipher_parts.append("GREASE")
                else:
                    cipher_parts.append(str(cs_value))
        cipher_peet = "-".join(cipher_parts)
        
        # TLS版本部分
        tls_version_peet = f"{version_parts[0]}-{version_parts[1]}"
        
        # 扩展部分，标记GREASE值
        ext_parts = []
        for ext in extensions:
            ext_type = ext.get("type", "")
            if ext_type.startswith("0x"):
                ext_value = int(ext_type.replace("0x", ""), 16)
                if ext_value in grease_values:
                    ext_parts.append("GREASE")
                else:
                    ext_parts.append(str(ext_value))
        ext_peet = "-".join(ext_parts)
        
        # 曲线部分
        curves_peet = "-".join(elliptic_curves)
        
        # EC点格式部分
        ec_format_peet = "-".join(ec_point_formats)
        
        # 构建peetprint字符串（这里使用简化的格式，实际应根据具体规则调整）
        # 格式: 密码套件|TLS版本|扩展|曲线|EC点格式|其他特征
        peetprint = f"{cipher_peet}|{tls_version_peet}|{ext_peet}|{curves_peet}|{ec_format_peet}|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-41-43-45-5-51-65037-65281-GREASE-GREASE"
        
        # 计算peetprint哈希
        peetprint_hash = hashlib.md5(peetprint.encode()).hexdigest()
        
        # 计算JA4指纹
        # JA4格式: t{TLS版本}d{密码套件数量}{扩展数量}{ALPN}_{密码套件列表}_{扩展列表}
        
        # 获取TLS版本
        tls_version_ja4 = ""
        if tls_version.startswith("3"):  # TLS 1.x
            tls_version_ja4 = f"1{tls_version[-1]}"
        else:
            tls_version_ja4 = tls_version
            
        # 计算密码套件数量和列表
        cipher_count = len(cipher_suites)
        cipher_list = []
        for cs in cipher_suites:
            if cs.startswith("0x"):
                hex_value = cs.replace("0x", "").lower()
                cipher_list.append(hex_value)
        cipher_str = ",".join(cipher_list)
        
        # 计算扩展数量和列表
        extension_count = len(extensions)
        ext_list = []
        for ext in extensions:
            ext_type = ext.get("type", "")
            if ext_type.startswith("0x"):
                hex_value = ext_type.replace("0x", "").lower()
                ext_list.append(hex_value)
        ext_str = ",".join(ext_list)
        
        # 获取ALPN (如果有)
        alpn = ""
        for ext in extensions:
            if ext.get("type") == "0x0010":  # ALPN扩展类型
                try:
                    data = binascii.unhexlify(ext.get("data", ""))
                    if len(data) > 2:
                        alpn_list_len = (data[0] << 8) | data[1]
                        if alpn_list_len > 0 and len(data) > 2:
                            pos = 2
                            while pos < alpn_list_len + 2:
                                proto_len = data[pos]
                                if pos + 1 + proto_len <= len(data):
                                    proto = data[pos+1:pos+1+proto_len].decode('ascii', errors='ignore')
                                    if proto == "h2":
                                        alpn = "h2"
                                        break
                                    elif proto == "http/1.1":
                                        alpn = "11"
                                        break
                                    elif proto:
                                        alpn = proto[:2]
                                        break
                                pos += 1 + proto_len
                except Exception:
                    pass
        
        # 构建JA4字符串
        ja4_string = f"t{tls_version_ja4}d{cipher_count:02d}{extension_count:02d}{alpn}_{cipher_str}_{ext_str}"
        
        # 构建JA4格式化字符串 (更易读的格式)
        # 将内部的逗号分隔符替换为连字符，使其更易读
        cipher_str_formatted = "-".join(cipher_list)
        ext_str_formatted = "-".join(ext_list)
        ja4_formatted = f"t{tls_version_ja4}d{cipher_count:02d}{extension_count:02d}{alpn}_{cipher_str_formatted}_{ext_str_formatted}"
        
        # 计算JA4哈希 - 使用完整JA4字符串的哈希
        ja4_hash = hashlib.md5(ja4_string.encode()).hexdigest()[:8]  # 取前8位
        
        return {
            "ja3_hash": ja3_hash,
            "ja3_string": ja3_str,
            "ja3_formatted": ja3_formatted,
            "peetprint": peetprint,
            "peetprint_hash": peetprint_hash,
            "ja4": ja4_string,
            "ja4_hash": ja4_hash,
            "ja4_string": ja4_string,
            # "ja4_formatted": ja4_formatted
        }
    
    except Exception as e:
        logger.error(f"计算指纹时出错: {e}")
        return {}


def parse_raw_tls_data(data: bytes) -> Dict[str, Any]:
    """解析原始TLS数据，提取ClientHello信息"""
    result = {
        "raw_data_length": len(data),
        "is_tls": False,
        "tls_version": None,
        "handshake_type": None,
        "cipher_suites": [],
        "extensions": []
    }
    
    try:
        # 检查是否是TLS记录
        if len(data) < 5:
            return result
        
        # TLS记录层
        content_type = data[0]
        if content_type != 0x16:  # Handshake
            result["content_type"] = f"0x{content_type:02x} (非Handshake类型)"
            return result
        
        result["is_tls"] = True
        result["content_type"] = "Handshake (0x16)"
        
        # TLS版本
        major, minor = data[1], data[2]
        result["tls_record_version"] = f"{major}.{minor}"
        
        # 记录长度
        record_length = (data[3] << 8) | data[4]
        result["record_length"] = record_length
        
        # 如果数据不足，返回
        if len(data) < 5 + record_length:
            return result
        
        # Handshake类型
        handshake_type = data[5]
        if handshake_type != 0x01:  # ClientHello
            result["handshake_type"] = f"0x{handshake_type:02x} (非ClientHello)"
            return result
        
        result["handshake_type"] = "ClientHello (0x01)"
        
        # Handshake长度
        handshake_length = (data[6] << 16) | (data[7] << 8) | data[8]
        result["handshake_length"] = handshake_length
        
        # ClientHello版本
        client_major, client_minor = data[9], data[10]
        result["client_version"] = f"{client_major}.{client_minor}"
        
        # 随机数
        client_random = data[11:43]
        result["client_random"] = binascii.hexlify(client_random).decode()
        
        # 会话ID长度
        session_id_length = data[43]
        result["session_id_length"] = session_id_length
        
        # 会话ID
        session_id_end = 44 + session_id_length
        if session_id_length > 0:
            session_id = data[44:session_id_end]
            result["session_id"] = binascii.hexlify(session_id).decode()
        
        # 密码套件长度
        cipher_suites_length = (data[session_id_end] << 8) | data[session_id_end + 1]
        result["cipher_suites_length"] = cipher_suites_length
        
        # 密码套件
        cipher_suites_start = session_id_end + 2
        cipher_suites_end = cipher_suites_start + cipher_suites_length
        
        for i in range(cipher_suites_start, cipher_suites_end, 2):
            if i + 1 < len(data):
                cipher_suite = (data[i] << 8) | data[i + 1]
                result["cipher_suites"].append(f"0x{cipher_suite:04x}")
        
        # 压缩方法长度
        compression_methods_length = data[cipher_suites_end]
        result["compression_methods_length"] = compression_methods_length
        
        # 压缩方法
        compression_methods_start = cipher_suites_end + 1
        compression_methods_end = compression_methods_start + compression_methods_length
        
        if compression_methods_length > 0:
            compression_methods = data[compression_methods_start:compression_methods_end]
            result["compression_methods"] = binascii.hexlify(compression_methods).decode()
        
        # 扩展长度
        if compression_methods_end < len(data):
            extensions_length = (data[compression_methods_end] << 8) | data[compression_methods_end + 1]
            result["extensions_length"] = extensions_length
            
            # 扩展
            extensions_start = compression_methods_end + 2
            extensions_end = extensions_start + extensions_length
            
            pos = extensions_start
            while pos < extensions_end and pos + 4 <= len(data):
                ext_type = (data[pos] << 8) | data[pos + 1]
                ext_length = (data[pos + 2] << 8) | data[pos + 3]
                
                ext_data_start = pos + 4
                ext_data_end = ext_data_start + ext_length
                
                if ext_data_end <= len(data):
                    ext_data = data[ext_data_start:ext_data_end]
                    
                    # 解析SNI扩展 (类型 0)
                    if ext_type == 0 and ext_length > 2:
                        sni_list_length = (ext_data[0] << 8) | ext_data[1]
                        if sni_list_length > 0 and len(ext_data) > 2:
                            sni_type = ext_data[2]
                            if sni_type == 0:  # host_name
                                sni_length = (ext_data[3] << 8) | ext_data[4]
                                if len(ext_data) >= 5 + sni_length:
                                    sni_hostname = ext_data[5:5+sni_length].decode('utf-8', errors='ignore')
                                    result["extensions"].append({
                                        "type": "server_name (0)",
                                        "hostname": sni_hostname
                                    })
                    else:
                        # 其他扩展类型 - 修改这里，不再截断数据
                        ext_info = {
                            "type": f"0x{ext_type:04x}",
                            "length": ext_length,
                            "data": binascii.hexlify(ext_data).decode()  # 完整输出所有数据，不再截断
                        }
                        result["extensions"].append(ext_info)
                
                pos = ext_data_end
        
        return result
    
    except Exception as e:
        result["error"] = f"解析TLS数据时出错: {str(e)}"
        return result


def parse_tls_client_hello(ssl_conn: ssl.SSLSocket) -> Dict[str, Any]:
    """ 获取有效的TLS连接信息 """
    try:
        # 显式执行握手操作
        ssl_conn.do_handshake()
        
        # 获取连接信息
        cipher = ssl_conn.cipher()
        version = ssl_conn.version()
        sni = ssl_conn.server_hostname
        
        return {
            "tls_version": version,
            "cipher_suite": cipher[0] if cipher else "Unknown",
            "sni": sni,
            "handshake_status": "Success"
        }
    except ssl.SSLError as e:
        return {
            "handshake_status": f"Failed: {e}"
        }


def parse_http_headers(data: str) -> Dict[str, str]:
    headers = {}
    lines = data.split('\r\n')
    
    if not lines or not lines[0]:
        return headers
        
    try:
        # 尝试解析请求行
        request_parts = lines[0].split(' ', 2)
        if len(request_parts) >= 2:
            headers['Method'] = request_parts[0]
            headers['Path'] = request_parts[1]
            if len(request_parts) > 2:
                headers['Protocol'] = request_parts[2]
    except Exception as e:
        logger.warning(f"解析请求行失败: {e}, 原始数据: {lines[0]}")
    
    # 解析其余的头部
    for line in lines[1:]:
        if not line:  # 跳过空行
            continue
        if ': ' in line:
            try:
                key, value = line.split(': ', 1)
                headers[key] = value
            except Exception as e:
                logger.warning(f"解析头部行失败: {e}, 原始数据: {line}")
    
    return headers


def generate_response(success, tls_info=None) -> str:
    body = f"TLS检测成功:{success}"
    body = ""
    
    # 如果提供了TLS信息，将其添加到响应中
    if tls_info:
        body += f"\n\n{json.dumps(tls_info, indent=4, ensure_ascii=False)}"
    
    return (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        f"{body}"
    )


def generate_error_response(error: str, tls_info=None) -> str:
    body = f"TLS检测失败: {error}"
    body = ""
    
    # 如果提供了TLS信息，将其添加到响应中
    if tls_info:
        body += f"\n\n{json.dumps(tls_info, indent=4, ensure_ascii=False)}"
    
    return (
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        f"{body}"
    )


if __name__ == "__main__":
    start_server("0.0.0.0", 443)
