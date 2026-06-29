#!/usr/bin/env python3
"""
资源文件管理工具 - 用于准备离线查询网页所需的数据文件。

用法:
    python cli.py -u [LIB_DIR]
    python cli.py -c [INPUT_FILE] [DATA_DIR] [-y]
"""

import argparse
import base64
import hashlib
import secrets
import shutil
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Tuple
import tomllib  # Python 3.11+

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except ImportError:
    print("错误: 需要安装 pycryptodome 库: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

try:
    import msgpack
except ImportError:
    print("错误: 需要安装 msgpack 库: pip install msgpack", file=sys.stderr)
    sys.exit(1)


# ===== 常量 =====
PBKDF2_ITERATIONS = 600000
AES_KEY_LEN = 32  # 256 bits
AES_NONCE_LEN = 12
AES_TAG_LEN = 16
TOKEN_URLSAFE_BYTES = 32


# ===== 辅助函数 =====

def ensure_dir(path: Path) -> None:
    """确保目录存在，若不存在则递归创建。"""
    path.mkdir(parents=True, exist_ok=True)


def to_base64url(data: bytes) -> str:
    """将 bytes 转为 URL-safe Base64（无填充）。"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def from_base64url(s: str) -> bytes:
    """从 URL-safe Base64 字符串还原 bytes（自动补齐填充）。"""
    s = s.strip()
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.urlsafe_b64decode(s)


def sha256(data: bytes) -> bytes:
    """计算 SHA-256 摘要。"""
    return hashlib.sha256(data).digest()


def derive_key(password: str, salt: bytes) -> bytes:
    """使用 PBKDF2-HMAC-SHA256 派生 AES-256 密钥。"""
    return PBKDF2(password, salt, dkLen=AES_KEY_LEN, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    使用 AES-256-GCM 加密明文。
    返回: (nonce, ciphertext, tag)
    """
    nonce = get_random_bytes(AES_NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag


def build_user_encrypted_payload(user_data: Dict[str, Any], token: str) -> bytes:
    """
    构造用户数据文件内容（MsgPack 数组）:
        [salt, nonce, ciphertext + tag]
    其中 salt 用于 PBKDF2，nonce 用于 AES-GCM。
    使用 token 作为密码派生密钥。
    """
    salt = get_random_bytes(16)  # PBKDF2 salt 16 字节
    key = derive_key(token, salt)
    plaintext = msgpack.packb(user_data)
    nonce, ciphertext, tag = aes_gcm_encrypt(key, plaintext)
    ciphertext_tag = ciphertext + tag
    payload = msgpack.packb([salt, nonce, ciphertext_tag])
    return payload


def encrypt_group_or_file(data: Dict[str, Any] or List) -> Tuple[bytes, bytes, bytes]:
    """
    加密 group 或 file 数据，返回 (key, nonce, ciphertext+tag)
    注意：不在此处进行 msgpack 打包，由调用者负责组装。
    """
    key = get_random_bytes(AES_KEY_LEN)
    plaintext = msgpack.packb(data)
    nonce, ciphertext, tag = aes_gcm_encrypt(key, plaintext)
    ciphertext_tag = ciphertext + tag
    return key, nonce, ciphertext_tag


def load_token_file(token_path: Path) -> Dict[str, str]:
    """加载 token.toml 文件，返回 {user_name: token}。"""
    if not token_path.exists():
        return {}
    with open(token_path, 'rb') as f:
        data = tomllib.load(f)
    return {k: v for k, v in data.items() if isinstance(v, str)}


def save_token_file(token_path: Path, token_map: Dict[str, str]) -> None:
    """保存 token.toml 文件。"""
    sorted_items = sorted(token_map.items())
    with open(token_path, 'w', encoding='utf-8') as f:
        for user, token in sorted_items:
            f.write(f'"{user}" = "{token}"\n')


def generate_token() -> str:
    """生成一个新的 URL-safe Token（32 字节）。"""
    return secrets.token_urlsafe(TOKEN_URLSAFE_BYTES)


# ===== 数据转换核心 =====

def convert_data(toml_path: Path, data_dir: Path, yes: bool) -> None:
    """
    读取 TOML 文件，执行转换，生成 data/ 目录下的文件。
    """
    if not toml_path.exists():
        print(f"错误: 输入文件 {toml_path} 不存在", file=sys.stderr)
        sys.exit(1)

    with open(toml_path, 'rb') as f:
        toml_data = tomllib.load(f)

    token_file_str = toml_data.get('token_file', None)
    if token_file_str:
        token_path = Path(token_file_str)
    else:
        token_path = toml_path.parent / 'token.toml'

    user_table = toml_data.get('user', {})
    group_table = toml_data.get('group', {})
    file_list = toml_data.get('file', [])

    # 验证约束
    all_users = set(user_table.keys())
    for gname, gdata in group_table.items():
        users = gdata.get('users', [])
        for uname in users:
            if uname not in all_users:
                print(f"错误: group '{gname}' 中的 user '{uname}' 未在 user 表中定义", file=sys.stderr)
                sys.exit(1)

    all_groups = set(group_table.keys())
    for f_idx, fdata in enumerate(file_list):
        groups = fdata.get('groups', [])
        for gname in groups:
            if gname not in all_groups:
                print(f"错误: file #{f_idx} 中的 group '{gname}' 未在 group 表中定义", file=sys.stderr)
                sys.exit(1)

    data_dir = Path(data_dir)
    if data_dir.exists():
        if yes:
            shutil.rmtree(data_dir)
        else:
            resp = input(f"目录 {data_dir} 已存在，删除并重建？[y/N] ").strip().lower()
            if resp != 'y':
                print("操作取消")
                sys.exit(0)
            shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    user_dir = data_dir / 'user'
    user_dir.mkdir(parents=True, exist_ok=True)

    token_map = load_token_file(token_path)
    updated = False
    for uname in user_table.keys():
        if uname not in token_map or not token_map[uname]:
            token_map[uname] = generate_token()
            updated = True
    if updated:
        save_token_file(token_path, token_map)
        print(f"已更新 token 清单: {token_path}")

    # 构建 data 数组，每个元素为 [nonce, ciphertext+tag] (均为 bytes)
    data_entries: List[List[bytes]] = []  # 最终将 msgpack 序列化此列表

    # 记录 id 映射
    group_id_map: Dict[str, int] = {}
    file_id_map: Dict[int, int] = {}  # 原始文件索引 -> data id
    file_keys: Dict[int, bytes] = {}  # 原始文件索引 -> fileKey

    # 处理所有 file
    for f_idx, fdata in enumerate(file_list):
        file_obj = {
            'name': fdata.get('name', ''),
            'path': fdata.get('path', ''),
            'pwd': fdata.get('pwd', ''),
            'desc': fdata.get('desc', ''),
            'author': fdata.get('author', ''),
        }
        key, nonce, ciphertext_tag = encrypt_group_or_file(file_obj)
        file_id = len(data_entries)
        data_entries.append([nonce, ciphertext_tag])
        file_keys[f_idx] = key
        file_id_map[f_idx] = file_id

    # 处理所有 group
    group_keys: Dict[str, bytes] = {}
    for gname, gdata in group_table.items():
        group_files = []
        for f_idx, fdata in enumerate(file_list):
            if gname in fdata.get('groups', []):
                file_id = file_id_map[f_idx]
                file_key = file_keys[f_idx]
                group_files.append([file_id, file_key])
        # group 对象是数组
        group_obj = group_files
        key, nonce, ciphertext_tag = encrypt_group_or_file(group_obj)
        group_id = len(data_entries)
        data_entries.append([nonce, ciphertext_tag])
        group_keys[gname] = key
        group_id_map[gname] = group_id

    # 处理所有 user
    for uname, udata in user_table.items():
        token = token_map.get(uname)
        if not token:
            token = generate_token()
            token_map[uname] = token
            save_token_file(token_path, token_map)
        user_groups = []
        for gname, gid in group_id_map.items():
            gdata = group_table.get(gname, {})
            if uname in gdata.get('users', []):
                group_key = group_keys[gname]
                user_groups.append([gid, group_key])
        user_obj = {
            'name': uname,
            'groups': user_groups,
        }
        payload = build_user_encrypted_payload(user_obj, token)
        token_bytes = token.encode('utf-8')
        token_hash = to_base64url(sha256(token_bytes))
        user_file_path = user_dir / token_hash
        with open(user_file_path, 'wb') as f:
            f.write(payload)

    # 写入 data/data (整个数组 msgpack 序列化)
    data_file_path = data_dir / 'data'
    with open(data_file_path, 'wb') as f:
        msgpack.pack(data_entries, f)

    print(f"转换完成。")
    print(f"  用户数: {len(user_table)}")
    print(f"  组数: {len(group_table)}")
    print(f"  文件数: {len(file_list)}")
    print(f"  数据文件写入: {data_file_path}")
    print(f"  用户数据目录: {user_dir}")
    print(f"  Token 清单: {token_path}")


# ===== 下载依赖 =====

def download_dependencies(lib_dir: Path) -> None:
    """下载第三方库到 lib_dir 目录。"""
    ensure_dir(lib_dir)

    dependencies = [
        {
            'url': 'https://unpkg.com/@msgpack/msgpack/dist.umd/msgpack.min.js',
            'local': lib_dir / 'msgpack.min.js',
        },
    ]

    for dep in dependencies:
        url = dep['url']
        local_path = dep['local']
        print(f"下载 {url} -> {local_path}")
        try:
            urllib.request.urlretrieve(url, local_path)
        except Exception as e:
            print(f"错误: 下载 {url} 失败: {e}", file=sys.stderr)
            sys.exit(1)
    print("依赖下载完成。")


# ===== 命令行入口 =====

def main():
    parser = argparse.ArgumentParser(description="资源文件管理工具")
    # 两个选项不再互斥，可以同时使用
    parser.add_argument('-u', '--update', nargs='?', const='./lib/', default=None,
                        metavar='LIB_DIR', help='下载更新依赖到 LIB_DIR (默认 ./lib/)')
    parser.add_argument('-c', '--convert', nargs='*', metavar=('INPUT_FILE', 'DATA_DIR'),
                        help='转换数据文件: INPUT_FILE (默认 ./data.toml) 和 DATA_DIR (默认 ./data/)')
    parser.add_argument('-y', '--yes', action='store_true', help='静默删除并重建 DATA_DIR (仅用于 -c)')

    args = parser.parse_args()

    # 如果没有任何操作，显示帮助
    if args.update is None and args.convert is None:
        parser.print_help()
        sys.exit(0)

    # 1. 执行 -u（下载依赖）
    if args.update is not None:
        lib_dir = Path(args.update) if args.update else Path('./lib/')
        download_dependencies(lib_dir)

    # 2. 执行 -c（转换数据）
    if args.convert is not None:
        args_list = args.convert
        if len(args_list) == 0:
            input_file = Path('./data.toml')
            data_dir = Path('./data/')
        elif len(args_list) == 1:
            input_file = Path(args_list[0])
            data_dir = Path('./data/')
        elif len(args_list) == 2:
            input_file = Path(args_list[0])
            data_dir = Path(args_list[1])
        else:
            print("错误: -c 接受最多两个参数", file=sys.stderr)
            sys.exit(1)
        convert_data(input_file, data_dir, args.yes)


if __name__ == '__main__':
    main()