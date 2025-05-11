import requests


def test_ssl_verify():
    """测试 SSL 验证选项"""
    # 不验证 SSL 证书
    url = "https://localhost:443"  # 使用本地服务器
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Connection': 'keep-alive'
        }
        headers = {}
        response = requests.get(url, headers=headers, verify=False)
        print(f"不验证 SSL 的请求状态码: {response.status_code}")
        print(f"响应内容: {response.text}")
    except requests.exceptions.SSLError as e:
        print(f"SSL 错误: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"连接错误: {e}")
    except Exception as e:
        print(f"发生其他异常: {e}")


if __name__ == "__main__":
    # 禁用不安全连接警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("\n6. 测试 SSL 验证选项")
    test_ssl_verify()
    