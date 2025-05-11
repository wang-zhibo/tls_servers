

```

server {
    listen 443 ssl;
    server_name your_domain.com;  # 替换为您的域名

    # SSL/TLS 证书配置
    ssl_certificate /path/to/your/certificate.crt;  # 替换为您的证书路径
    ssl_certificate_key /path/to/your/private.key;  # 替换为您的私钥路径

    # 优化 SSL 设置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    # 反向代理到您的 Python 应用
    location / {
        proxy_pass http://127.0.0.1:11443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP 重定向到 HTTPS
server {
    listen 80;
    server_name your_domain.com;  # 替换为您的域名
    return 301 https://$host$request_uri;
}

```
