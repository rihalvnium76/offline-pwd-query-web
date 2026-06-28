#!/usr/bin/env python3
"""
离线查询数据文件管理工具
用法:
  生成用户配置: python cli.py -u user1 user2 ...
  转换数据文件: python cli.py -c [input.toml] [output_dir] [-y]
"""

import argparse
import os
import sys
import secrets
import hashlib
import struct
import json
import shutil
from pathlib import Path

# 尝试导入 tomllib (Python 3.11+)
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        sys.stderr.write("错误: 需要 tomllib (Python 3.11+) 或 tomli 库\n")
        sys.exit(1)

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


# ---------- 常量 ----------
PBKDF2_ITERATIONS = 600000
KEY_LEN = 32
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16


# ---------- 工具函数 ----------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """使用随机 IV 加密，返回 (iv, ciphertext_with_tag)"""
    iv = get_random_bytes(IV_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv, ciphertext + tag


def decrypt_aes_gcm(key: bytes, iv: bytes, ciphertext_with_tag: bytes) -> bytes:
    """解密，ciphertext_with_tag 包含末尾 16 字节 tag"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext_with_tag[:-TAG_LEN], ciphertext_with_tag[-TAG_LEN:])


def derive_key(token: bytes, salt: bytes) -> bytes:
    return PBKDF2(token, salt, dkLen=KEY_LEN, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)


def pack_user_entries(entries: list[tuple[int, bytes]]) -> bytes:
    """将 [(groupId, groupKey), ...] 序列化为二进制"""
    out = bytearray()
    for gid, gkey in entries:
        out.extend(struct.pack('<H', gid))
        out.extend(gkey)  # 32 bytes
    return bytes(out)


def pack_group_entries(entries: list[tuple[int, bytes]]) -> bytes:
    """将 [(fileId, fileKey), ...] 序列化为二进制"""
    out = bytearray()
    for fid, fkey in entries:
        out.extend(struct.pack('<H', fid))
        out.extend(fkey)
    return bytes(out)


# ---------- 生成用户配置 ----------
def generate_user_config(usernames: list[str]) -> str:
    """生成 TOML 格式的用户配置"""
    lines = []
    for name in usernames:
        token = secrets.token_urlsafe()
        lines.append(f'[user."{name}"]')
        lines.append(f'token = "{token}"')
        lines.append('')
    return '\n'.join(lines)


# ---------- 转换数据文件 ----------
def convert_data(input_file: str, output_dir: str, force: bool = False):
    input_path = Path(input_file)
    if not input_path.exists():
        sys.stderr.write(f"错误: 输入文件 {input_file} 不存在\n")
        sys.exit(1)

    output_path = Path(output_dir)
    if output_path.exists():
        if force:
            shutil.rmtree(output_path)
        else:
            resp = input(f"输出目录 {output_dir} 已存在，是否删除并重建？(y/N): ")
            if resp.lower() != 'y':
                print("已取消")
                sys.exit(0)
            shutil.rmtree(output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    # 读取 TOML
    with open(input_path, 'rb') as f:
        data = tomllib.load(f)

    # 解析用户、组、文件
    users = data.get('user', {})
    groups = data.get('group', {})
    files = data.get('file', [])

    # 验证用户 token 唯一
    tokens = set()
    for uname, uinfo in users.items():
        token = uinfo.get('token')
        if not token:
            sys.stderr.write(f"错误: 用户 {uname} 缺少 token\n")
            sys.exit(1)
        if token in tokens:
            sys.stderr.write(f"错误: 用户 {uname} 的 token 重复\n")
            sys.exit(1)
        tokens.add(token)

    # 验证 group.users 引用存在
    for gname, ginfo in groups.items():
        for uname in ginfo.get('users', []):
            if uname not in users:
                sys.stderr.write(f"错误: 组 {gname} 引用了不存在的用户 {uname}\n")
                sys.exit(1)

    # 验证 file.groups 引用存在
    for idx, finfo in enumerate(files):
        for gname in finfo.get('groups', []):
            if gname not in groups:
                sys.stderr.write(f"错误: 文件 #{idx} 引用了不存在的组 {gname}\n")
                sys.exit(1)

    # 分配 file 加密块
    file_blocks = []           # 每个元素: (iv, enc, file_key)
    file_entries = []          # 用于 group 引用: (fileId, fileKey)
    for idx, finfo in enumerate(files):
        # 构建 file JSON
        file_json = {
            "name": finfo.get("name", ""),
            "path": finfo.get("path", ""),
            "pwd": finfo.get("pwd", ""),
            "desc": finfo.get("desc", ""),
            "author": finfo.get("author", "")
        }
        plaintext = json.dumps(file_json, ensure_ascii=False).encode('utf-8')
        file_key = get_random_bytes(KEY_LEN)
        iv, enc = encrypt_aes_gcm(file_key, plaintext)
        file_blocks.append((iv, enc))
        file_entries.append((idx, file_key))  # idx 即 fileId

    # 分配 group 加密块
    group_blocks = []          # 每个元素: (iv, enc, group_key, group_name)
    group_id_map = {}          # group_name -> groupId (在最终 data 中的索引)

    # 构建 group 的 file 引用列表 (fileId, fileKey)
    group_file_refs = {}
    for gname, ginfo in groups.items():
        refs = []
        for fidx, finfo in enumerate(files):
            if gname in finfo.get('groups', []):
                file_key = file_entries[fidx][1]
                refs.append((fidx, file_key))
        group_file_refs[gname] = refs

    # 为每个 group 生成加密块
    for gname, refs in group_file_refs.items():
        plaintext = pack_group_entries(refs)
        group_key = get_random_bytes(KEY_LEN)
        iv, enc = encrypt_aes_gcm(group_key, plaintext)
        group_blocks.append((iv, enc, group_key, gname))

    # 确定最终 data 数组顺序: 先所有 file 块，然后所有 group 块
    all_blocks = []   # 每个元素 (iv, enc)
    for iv, enc in file_blocks:
        all_blocks.append((iv, enc))
    group_start_index = len(file_blocks)
    for idx, (iv, enc, gkey, gname) in enumerate(group_blocks):
        all_blocks.append((iv, enc))
        group_id = group_start_index + idx
        group_id_map[gname] = group_id

    # 构建 group_name -> (groupId, groupKey) 映射
    group_info_map = {}
    for gname, gid in group_id_map.items():
        # 找到对应的 group_blocks 中的 gkey
        for iv, enc, gkey, name in group_blocks:
            if name == gname:
                group_info_map[gname] = (gid, gkey)
                break

    # 为每个用户生成加密文件
    user_dir = output_path / 'user'
    user_dir.mkdir(exist_ok=True)

    for uname, uinfo in users.items():
        token = uinfo['token']
        token_bytes = token.encode('utf-8')
        token_hash = sha256_hex(token_bytes)

        # 收集该用户所属的组
        user_group_entries = []
        for gname, ginfo in groups.items():
            if uname in ginfo.get('users', []):
                if gname not in group_info_map:
                    sys.stderr.write(f"错误: 组 {gname} 未找到 groupId\n")
                    sys.exit(1)
                gid, gkey = group_info_map[gname]
                user_group_entries.append((gid, gkey))

        plaintext = pack_user_entries(user_group_entries)
        salt = get_random_bytes(SALT_LEN)
        key = derive_key(token_bytes, salt)
        iv, enc = encrypt_aes_gcm(key, plaintext)

        # 文件内容: salt + iv + enc
        user_file_content = salt + iv + enc
        user_file_path = user_dir / token_hash
        with open(user_file_path, 'wb') as f:
            f.write(user_file_content)

    # 写入 data/data 文件
    data_file_path = output_path / 'data'
    with open(data_file_path, 'wb') as f:
        for iv, enc in all_blocks:
            encrypted_data = iv + enc  # iv + ciphertext+tag
            size = len(encrypted_data)
            if size > 0xFFFF:
                sys.stderr.write(f"错误: 加密数据块大小 {size} 超过 65535\n")
                sys.exit(1)
            f.write(struct.pack('<H', size))
            f.write(encrypted_data)

    print(f"转换完成。数据文件已写入 {output_path}")
    print(f"共写入 {len(all_blocks)} 个加密块 (file: {len(file_blocks)}, group: {len(group_blocks)})")
    print(f"用户文件生成在 {user_dir} 目录")


# ---------- 主函数 ----------
def main():
    parser = argparse.ArgumentParser(description="离线查询数据文件管理工具")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--users', nargs='+', help='生成用户 Token 配置，后跟用户名列表')
    group.add_argument('-c', '--convert', nargs='*', help='转换 TOML 数据文件，后可跟 [input_file] [output_dir]')
    parser.add_argument('-y', '--yes', action='store_true', help='静默删除并重建输出目录（仅与 -c 配合）')

    args = parser.parse_args()

    if args.users:
        # 生成用户配置
        toml_output = generate_user_config(args.users)
        print(toml_output)
    elif args.convert is not None:
        # 解析参数
        if len(args.convert) > 2:
            parser.error('-c 最多接受两个参数：输入文件和输出目录')
        input_file = args.convert[0] if len(args.convert) >= 1 else 'data.toml'
        output_dir = args.convert[1] if len(args.convert) >= 2 else 'data'
        convert_data(input_file, output_dir, args.yes)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()