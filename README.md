octo-keygen-cpp
================

[![Keygen Linux Build Pipeline](https://github.com/ofiriluz/octo-keygen-cpp/actions/workflows/linux.yml/badge.svg)](https://github.com/ofiriluz/octo-keygen-cpp/actions/workflows/linux.yml)

Key generation library, supports generating of public private key pairs and certificates

Currently it supports generating those keys from:
- OpenSSL

Each generation implements the base interface defined in Keygen for the following classes
- IKeypair
- IKeypairCertificate
- IKeypairCertificateChain
- IKeygen

The keygen class is used to generate the key pairs and certificates in memory

Alongside that, ssl certificates and chains also implement methods such as:
- Chain validation
- Certificate comparison
- Extensions management

All of which use openssl

Usage
=====

In order to use the existing implmenets, and generate keypair and certificates, we can use it as follows with ssl:

```cpp
octo::keygen::KeygenPtr ssl_key_gen = std::make_shared<octo::keygen::ssl::SSLKeygen>();
octo::keygen::KeygenOptions ssl_opts;
octo::keygen::KeypairPtr ssl_key_pair = ssl_key_gen->generate_keypair(ssl_opts);
logger.info() << "\n" << ssl_key_pair->private_key();
logger.info() << "\n" << ssl_key_pair->public_key();

octo::keygen::KeygenOptions ssl_sign_opts;
octo::keygen::KeypairCertificatePtr ssl_cert = ssl_key_gen->sign_key_pair(ssl_key_pair, ssl_sign_opts);
logger.info() << "\n" << ssl_cert->certificate();
logger.info() << "\n" << ssl_cert->pretty_print_certificate_info();
```

We can further use openssl certificates to perform the following:

```cpp
std::unique_ptr<octo::keygen::ssl::SSLKeypairCertificate> cert = octo::keygen::ssl::SSLKeypairCertificate::load_certificate("some_data");
cert->add_certificate_extension(NID_netscape_ssl_server_name, "some_value");

std::unique_ptr<octo::keygen::ssl::SSLKeypairCertificate> other_cert = octo::keygen::ssl::SSLKeypairCertificate::load_certificate("some_other_data");

if (octo::keygen::ssl::SSLKeypairCertificate::compare_certificates(cert.get(), other_cert.get()))
{
    logger.info() << "Equal Certificates";
}
```
