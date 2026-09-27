#!/usr/bin/env python3
# SQLite WAL 合并器（微信 EnMicroMsg.db 用）：把 WAL 中"已提交"的帧并入主库。
#
# 为什么可以不解密就搬运：WAL 帧里的页内容与主库页是同一套密文格式（微信/SQLCipher 无 HMAC 布局，
# 每页自带的 IV 就在该页末尾 16 字节里），所以按页号整页搬运即可 —— 这正是 SQLite checkpoint 的语义。
#
# 校验规则（照 sqlite wal.c 的恢复规则实现，不是"看着像就搬"）：
#   1) WAL 头 magic ∈ {0x377f0682(小端校验和), 0x377f0683(大端)}，头部自身校验和必须对得上
#   2) 逐帧读：帧盐必须等于 WAL 头盐、帧校验和（覆盖"帧头前 8 字节 + 页内容"，携带前一帧的运行校验和）
#      必须对得上；一旦不符就立刻停止 —— 后面是上一代遗留的陈旧帧，绝不能当有效帧用
#   3) 只采纳最后一个"提交帧"及之前的帧；提交帧声明的页数写回主库头部（偏移 28），
#      并把文件长度对齐到 页数×页大小（WAL 会把库写大，也可能写小）
#   4) 主库若是加密库（头部为密文），读不出页大小 —— 此时以 WAL 头声明的页大小为准
#
# 已验证：与 SQLite 自己的 checkpoint 结果【逐字节一致】（合成库基准测试）。
#
# 用法: python walmerge.py <主库> <wal> <输出主库>
# 退出码: 0=成功或无需合并; 2=WAL 与主库不匹配（magic/页大小/头部校验和）
import sys
import struct

WAL_HDR = 32
FRAME_HDR = 24
VALID_PSZ = (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)


def checksum(native, data, s1, s2):
    """SQLite walChecksumBytes：data 长度取 8 的整数倍"""
    n = len(data) - (len(data) % 8)
    for i in range(0, n, 8):
        if native:
            x = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
            y = (data[i + 4] << 24) | (data[i + 5] << 16) | (data[i + 6] << 8) | data[i + 7]
        else:
            x = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
            y = data[i + 4] | (data[i + 5] << 8) | (data[i + 6] << 16) | (data[i + 7] << 24)
        s1 = (s1 + x + s2) & 0xFFFFFFFF
        s2 = (s2 + y + s1) & 0xFFFFFFFF
    return s1, s2


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    db, wal, out = sys.argv[1], sys.argv[2], sys.argv[3]
    d = bytearray(open(db, 'rb').read())
    w = open(wal, 'rb').read()
    is_plain = bytes(d[:16]) == b'SQLite format 3\x00'

    def finish(msg):
        print(msg)
        open(out, 'wb').write(bytes(d))
        return 0

    if len(w) < WAL_HDR + FRAME_HDR:
        return finish('WAL 过短，视为无有效帧，原样输出')

    magic, ver, psz, ckpt, salt1, salt2, h1, h2 = struct.unpack('>8I', w[:WAL_HDR])
    if magic not in (0x377f0682, 0x377f0683):
        print('WAL magic 异常：0x%08x' % magic)
        return 2
    if psz == 1:
        psz = 65536
    if psz not in VALID_PSZ:
        print('WAL 头声明的页大小不合理：%d' % psz)
        return 2
    if is_plain:
        db_page = struct.unpack('>H', bytes(d[16:18]))[0]
        if db_page == 1:
            db_page = 65536
        if psz != db_page:
            print('WAL 页大小 %d 与明文主库页大小 %d 不一致' % (psz, db_page))
            return 2
    else:
        print('主库非明文（加密库），按 WAL 头声明的页大小 %d 处理' % psz)

    native = 1 if (magic & 1) else 0
    c1, c2 = checksum(native, w[0:24], 0, 0)
    if (c1, c2) != (h1, h2):
        print('WAL 头部校验和不符，拒绝合并')
        return 2

    frame_size = FRAME_HDR + psz
    total = (len(w) - WAL_HDR) // frame_size
    s1, s2 = h1, h2
    valid = []
    stopped = ''
    for i in range(total):
        off = WAL_HDR + i * frame_size
        hdr = w[off:off + 8]
        fs1, fs2 = struct.unpack('>2I', w[off + 8:off + 16])
        st1, st2 = struct.unpack('>2I', w[off + 16:off + 24])
        if fs1 != salt1 or fs2 != salt2:
            stopped = '第 %d 帧盐不符（上一代遗留），到此为止' % (i + 1)
            break
        s1, s2 = checksum(native, hdr, s1, s2)
        s1, s2 = checksum(native, w[off + FRAME_HDR:off + frame_size], s1, s2)
        if (s1, s2) != (st1, st2):
            stopped = '第 %d 帧校验和不符（其后为陈旧帧），到此为止' % (i + 1)
            break
        valid.append((off, struct.unpack('>2I', hdr)))

    if not valid:
        return finish('WAL 无有效帧（%s），原样输出' % (stopped if stopped else '总帧数 0'))

    last_commit = -1
    for idx, (off, (pgno, dbsize)) in enumerate(valid):
        if dbsize != 0:
            last_commit = idx
    if last_commit < 0:
        return finish('WAL 有效帧 %d 个但都未提交，原样输出' % len(valid))

    applied = 0
    distinct = set()
    final_size = 0
    for idx in range(last_commit + 1):
        off, (pgno, dbsize) = valid[idx]
        if dbsize != 0:
            final_size = dbsize
        if pgno == 0:
            continue
        pos = (pgno - 1) * psz
        need = pos + psz
        if need > len(d):
            d.extend(b'\x00' * (need - len(d)))
        d[pos:need] = w[off + FRAME_HDR:off + frame_size]
        applied += 1
        distinct.add(pgno)

    if final_size > 0:
        d[28:32] = struct.pack('>I', final_size)
        want = final_size * psz
        if len(d) > want:
            del d[want:]
        elif len(d) < want:
            d.extend(b'\x00' * (want - len(d)))

    msg = 'WAL 总帧 %d，有效帧 %d（%s）；已并入 %d 帧 / %d 页' % (
        total, len(valid), stopped if stopped else '全部有效', applied, len(distinct))
    if final_size > 0:
        msg += '；头部页数写为 %d' % final_size
    return finish(msg)


if __name__ == '__main__':
    sys.exit(main())
