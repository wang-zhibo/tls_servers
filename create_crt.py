from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
# 生成私钥
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
# 生成自签名证书
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(private_key, hashes.SHA256())
)
# 保存私钥和证书
with open("server.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))