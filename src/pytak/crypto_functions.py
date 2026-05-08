#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# crypto_functions.py from https://github.com/snstac/pytak
#
# Copyright Sensors & Signals LLC https://www.snstac.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""PyTAK Crypto (as in cryptography) Functions."""

import os
from pathlib import Path
import tempfile
import warnings
import ssl
import logging
from typing import Optional, Union,Tuple


INSTALL_MSG = (
    "Python cryptography module not installed. Install with: "
    " python3 -m pip install cryptography"
)

# Check if cryptography is installed
USE_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12, PrivateFormat, NoEncryption
    from cryptography import x509

    USE_CRYPTOGRAPHY = True
except ImportError as exc:
    warnings.warn(str(exc))

logger = logging.getLogger("pytak.crypto")

def save_pem(pem: bytes, dest: Union[str, None] = None) -> str:
    """Save PEM data to dest."""
    if dest and Path(dest).write_bytes(pem) > 0:
        return dest
    pem_fd, pem_path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(pem_fd, "wb+") as pfd:
        pfd.write(pem)
    return pem_path


def convert_cert(cert_path: str, cert_pass: str|None = None, output: str|None = None) -> dict[str, str]:
    """Extract a P12 bundle to separate PEM files

    :return: dict with paths to extracted PEM files
        - pk_pem_path: private key in PEM format
        - cert_pem_path: public certificate belonging to the private key
        - ca_pem_path: CA certificate (first certificate in the chain after the client certificate)
        - root_ca_pem_path: rootCA certificate (the last certificate in the chain)
        - cert_chain_path: full certificate chain from the client's up to rootCA (you want to identify with this)
    """
    if not USE_CRYPTOGRAPHY:
        raise ValueError(INSTALL_MSG)

    cert_paths = {
        "pk_pem_path": None,
        "cert_pem_path": None,
        "ca_pem_path": None,
        "root_ca_pem_path": None,
        "cert_chain_path": None,
    }

    private_key, cert, additional_certificates = pkcs12.load_key_and_certificates(
        Path(cert_path).read_bytes(),
        cert_pass.encode() if cert_pass else None
    )

    pk_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_paths["pk_pem_path"] = save_pem(pk_pem, output+".key.pem" if output else None)

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_paths["cert_pem_path"] = save_pem(cert_pem, output+".cert_only.pem" if output else None)

    cert_paths["cert_chain_path"] = save_pem(cert_pem, output+".cert.pem" if output else None)
    with open(cert_paths["cert_chain_path"], "ab") as cert_file:
        for ca in additional_certificates:
            cert_file.write(ca.public_bytes(serialization.Encoding.PEM))

    ca_cert: x509.Certificate = additional_certificates[0]
    ca_pem = ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_paths["ca_pem_path"] = save_pem(ca_pem, output+".ca.pem" if output else None)

    ca_root_cert: x509.Certificate = additional_certificates[-1]
    ca_root_pem = ca_root_cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_paths["root_ca_pem_path"] = save_pem(ca_root_pem, output+".root_ca.pem" if output else None)

    assert all(cert_paths)
    return cert_paths


def convert_p12_to_pem(output_path: str, passphrase: Optional[str]) -> Tuple[str, str]:
    """Extract p12 bundle to `output_path`.key.pem and cert-chain `output_path`.cert.pem"""
    pems = convert_cert(output_path, passphrase, output_path)
    return pems["pk_pem_path"], pems["cert_chain_path"]


def convert_p12_to_ssl_context(output_path: str|Path, passphrase: Optional[str], check_hostname: bool = False, check_server: bool = True, use_root_ca: bool = False) -> ssl.SSLContext:
    """Create an SSL Context from a PKCS#12 certificate container.

    :param output_path: the input .p12 bundle
    :param passphrase: password for unpacking .p12 bundle
    :param check_hostname: whether force checking CN part of the server certificate for correct hostname/IP
    :param check_server: if False, the communication will use client certificate but not require server certificate
    :param use_root_ca: use rootCA from .p12 for server certificate verification
    """
    pems = convert_cert(str(output_path), passphrase)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=pems["cert_chain_path"], keyfile=pems["pk_pem_path"])
    if not check_server:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ctx.check_hostname = check_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED  # we always require certificate from the server
    ctx.verify_flags = ssl.VERIFY_DEFAULT  # do not check against CRL databases
    if use_root_ca:
        ctx.load_verify_locations(cafile=pems["root_ca_pem_path"])
    else:
        ctx.load_default_certs()
    return ctx

create_ssl_context = convert_p12_to_ssl_context  # deprecated; backward-compatibility only
