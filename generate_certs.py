import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# 1. Generate Root CA Private Key & Certificate
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GTRE CA")])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=365)
    )
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    .sign(ca_key, hashes.SHA256())
)


# 2. Helper to generate node certs signed by Root CA
def create_node_cert(common_name, cert_filename, key_filename):
  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

  cert = (
      x509.CertificateBuilder()
      .subject_name(subject)
      .issuer_name(ca_name)
      .public_key(key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
      .not_valid_after(
          datetime.datetime.now(datetime.timezone.utc)
          + datetime.timedelta(days=365)
      )
      .sign(ca_key, hashes.SHA256())
  )

  with open(key_filename, "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

  with open(cert_filename, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))


# Write CA Certificate
with open("ca.crt", "wb") as f:
  f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

# Generate Receiver and Sender Certificate Pairs
create_node_cert("ReceiverNode", "receiver.crt", "receiver.key")
create_node_cert("SenderNode", "sender.crt", "sender.key")

print(
    "✅ Certificate Generation Complete! All 5 mTLS files created"
    " successfully."
)