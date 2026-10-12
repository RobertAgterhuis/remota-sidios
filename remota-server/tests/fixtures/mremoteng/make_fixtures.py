#!/usr/bin/env python3
"""Writes the mRemoteNG confCons.xml fixtures for the importer tests.

An independent implementation of the formats in SidiOS specs/011-remote-connections/research.md
R16 (Python `cryptography`, not the Rust code under test), so the tests check the importer against a
second reading of mRemoteNG's AeadCryptographyProvider and LegacyRijndaelCryptographyProvider.
Every password here is a made-up fixture value, never a real secret.

Run from this directory: python3 make_fixtures.py
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT = "mR3m"


def gcm(plain: str, password: str, iterations: int) -> str:
    salt, nonce = os.urandom(16), os.urandom(16)
    # BouncyCastle's Pkcs5PasswordToBytes keeps the low byte of each UTF-16 unit.
    secret = bytes(ord(ch) & 0xFF for ch in password)
    key = hashlib.pbkdf2_hmac("sha1", secret, salt, iterations, 32)
    sealed = AESGCM(key).encrypt(nonce, plain.encode(), salt)  # ciphertext || tag
    return base64.b64encode(salt + nonce + sealed).decode()


def cbc(plain: str, password: str) -> str:
    key = hashlib.md5(password.encode()).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(iv + encryptor.update(data) + encryptor.finalize()).decode()


def nodes(encrypt) -> str:
    return f"""
  <Node Name="Prod" Type="Container" Username="ops" Domain="CORP" Password="{encrypt('not-a-secret-folder')}" InheritUsername="False" InheritPassword="False" InheritDomain="False">
    <Node Name="web-1" Type="Connection" Protocol="SSH2" Hostname="10.0.0.11" Port="2222" Username="" Password="" InheritUsername="True" InheritPassword="True" InheritDomain="True" />
    <Node Name="win-1" Type="Connection" Protocol="RDP" Hostname="win1.corp.example" Port="3389" Username="administrator" Domain="CORP" Password="{encrypt('not-a-secret-rdp')}" InheritUsername="False" InheritPassword="False" InheritDomain="False" />
    <Node Name="vnc-1" Type="Connection" Protocol="VNC" Hostname="10.0.0.12" Port="5900" />
    <Node Name="Nested" Type="Container" InheritUsername="True" InheritPassword="True" InheritDomain="True">
      <Node Name="old-ssh" Type="Connection" Protocol="SSH1" Hostname="10.0.1.5" Port="22" Username="legacy" Password="{encrypt('not-a-secret-ssh1')}" InheritUsername="False" InheritPassword="False" InheritDomain="True" />
      <Node Name="same-as-rdp" Type="Connection" Protocol="RDP" Hostname="win2.corp.example" Port="3389" Username="administrator" Domain="CORP" Password="{encrypt('not-a-secret-rdp')}" InheritUsername="False" InheritPassword="False" InheritDomain="False" />
    </Node>
  </Node>
  <Node Name="router" Type="Connection" Protocol="Telnet" Hostname="10.0.0.1" Port="23" />
"""


def root(attributes: str, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" {attributes}>'
        f"{body}</mrng:Connections>\n"
    )


def aead_attributes(protected: str, iterations: int, engine="AES", mode="GCM", full=False) -> str:
    return (
        f'Export="false" EncryptionEngine="{engine}" BlockCipherMode="{mode}" '
        f'KdfIterations="{iterations}" FullFileEncryption="{str(full).lower()}" '
        f'Protected="{protected}" ConfVersion="2.8"'
    )


def write(name: str, text: str) -> None:
    with open(name, "w", encoding="utf-8") as file:
        file.write(text)


def main() -> None:
    def default(plain):
        return gcm(plain, DEFAULT, 1000)

    write(
        "confCons.gcm-default.xml",
        root(aead_attributes(default("ThisIsNotProtected"), 1000), nodes(default)),
    )

    def custom(plain):
        return gcm(plain, "fixture-master-ü", 10000)

    write(
        "confCons.gcm-custom.xml",
        root(aead_attributes(custom("ThisIsProtected"), 10000), nodes(custom)),
    )
    write(
        "confCons.gcm-fullfile.xml",
        root(
            aead_attributes(default("ThisIsNotProtected"), 1000, full=True),
            default(nodes(default)),
        ),
    )

    def legacy(plain):
        return cbc(plain, DEFAULT)

    write(
        "confCons.cbc-legacy.xml",
        root(f'Protected="{legacy("ThisIsNotProtected")}" ConfVersion="2.5"', nodes(legacy)),
    )
    # Twofish cannot be produced here; the importer must skip its passwords without reading them.
    write(
        "confCons.twofish.xml",
        root(
            aead_attributes("AAAA", 1000, engine="Twofish"),
            nodes(lambda plain: base64.b64encode(os.urandom(64)).decode()),
        ),
    )
    write(
        "confCons.iterations.xml",
        root(aead_attributes(gcm("ThisIsNotProtected", DEFAULT, 1000), 2_000_000), nodes(default)),
    )


if __name__ == "__main__":
    main()
