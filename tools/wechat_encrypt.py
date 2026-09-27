#!/usr/bin/env python3
# 微信 EnMicroMsg.db 逐页加密器（SQLCipher 1 兼容格式：page 1024 / kdf_iter 4000 / 无 HMAC）
#
# 用法:
#   encrypt : python wechat_encrypt.py encrypt <明文库> <输出加密库> <密钥>
#             用全新随机 salt + 每页随机 IV 加密（正常生产用）
#   rebuild : python wechat_encrypt.py rebuild <明文库> <输出加密库> <密钥> <参考加密库>
#             用参考加密库的 salt 与逐页 IV 重加密；若明文正是该参考库的解密结果，输出应与其逐字节一致（验证用）
#
# 页布局（与 wechat_decrypt.py 完全对称）:
#   每页 1024 字节 = [密文] + [IV 16]
#     页0: salt(16，即文件头) + AES-256-CBC(明文[16:1008]) + IV
#     页N: AES-256-CBC(明文[0:1008]) + IV
#   key = PBKDF2-HMAC-SHA1(密码, salt, 4000, 32)
import sys, os, hashlib, secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PAGE = 1024
RESERVE = 16
ITER = 4000
KEYLEN = 32
IVLEN = 16
SQLITE_HEADER = b"SQLite format 3\x00"


def derive(pw, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA1(), length=KEYLEN, salt=salt,
                      iterations=ITER, backend=default_backend()).derive(pw.encode("utf-8"))


def enc_page(key, iv, data):
    e = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    return e.update(data) + e.finalize()


def encrypt(src, dst, password, ivsource=None):
    buf = open(src, "rb").read()
    if len(buf) % PAGE:
        raise SystemExit("源文件不是 1024 字节整数倍，拒绝加密")
    if buf[:16] != SQLITE_HEADER:
        raise SystemExit("源文件不是明文 SQLite 库")
    if buf[18] != 2 or buf[19] != 2:
        raise SystemExit("源文件头部 WAL 标志不是 2,2（微信库必须保持 wal）")
    if buf[20] != RESERVE:
        raise SystemExit("源文件 reserve 字节不是 16（微信为无 HMAC 布局）")
    npage = len(buf) // PAGE
    if ivsource:
        ref = open(ivsource, "rb").read()
        if len(ref) != len(buf):
            raise SystemExit("参考加密库大小不一致")
        salt = ref[:IVLEN]
        ivs = [ref[p * PAGE + PAGE - RESERVE: p * PAGE + PAGE] for p in range(npage)]
    else:
        salt = secrets.token_bytes(IVLEN)
        ivs = [secrets.token_bytes(IVLEN) for _ in range(npage)]
    key = derive(password, salt)
    out = bytearray()
    for p in range(npage):
        page = buf[p * PAGE:(p + 1) * PAGE]
        iv = ivs[p]
        if p == 0:
            out += salt + enc_page(key, iv, page[16:PAGE - RESERVE]) + iv
        else:
            out += enc_page(key, iv, page[:PAGE - RESERVE]) + iv
    with open(dst, "wb") as f:
        f.write(bytes(out))
    return npage, salt


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(__doc__)
        raise SystemExit(2)
    mode, src, dst, pw = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    ivsrc = sys.argv[5] if len(sys.argv) > 5 else None
    if mode not in ("encrypt", "rebuild"):
        raise SystemExit("mode 只能是 encrypt 或 rebuild")
    n, salt = encrypt(src, dst, pw, ivsrc if mode == "rebuild" else None)
    h = hashlib.sha256(open(dst, "rb").read()).hexdigest()
    print("pages=%d  size=%d  salt=%s" % (n, os.path.getsize(dst), salt.hex()))
    print("sha256=%s" % h)
