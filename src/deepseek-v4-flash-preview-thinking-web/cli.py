#!/usr/bin/env python3
"""
资源文件管理工具 (cli.py)
"""

import argparse
import os
import sys
import secrets
import base64
import hashlib
import tomllib
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import urllib.request

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256   # 新增导入
except ImportError:
    print("错误: 需要安装 pycryptodome 库。请运行: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

try:
    import msgpack
except ImportError:
    print("错误: 需要安装 msgpack 库。请运行: pip install msgpack", file=sys.stderr)
    sys.exit(1)

# ---------- 常量 ----------
PBKDF2_ITERATIONS = 600000
AES_KEY_LEN = 32
AES_IV_LEN = 12

# 依赖列表
DEPENDENCIES = [
    {
        'url': 'https://unpkg.com/@msgpack/msgpack/dist.umd/msgpack.min.js',
        'local': 'msgpack.min.js'
    }
]

# ---------- 工具函数 ----------
def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def generate_token() -> str:
    return secrets.token_urlsafe()

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    nonce = get_random_bytes(AES_IV_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def derive_key_from_token(token: str, salt: bytes) -> bytes:
    # 使用 Crypto.Hash.SHA256 作为 HMAC 哈希模块
    return PBKDF2(token.encode('utf-8'), salt, dkLen=AES_KEY_LEN,
                  count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

# ---------- 下载依赖 ----------
def download_lib(lib_dir: Path) -> None:
    ensure_dir(lib_dir)
    for dep in DEPENDENCIES:
        url = dep['url']
        local_path = lib_dir / dep['local']
        print(f"下载: {url} -> {local_path}")
        try:
            urllib.request.urlretrieve(url, local_path)
            print(f"  成功")
        except Exception as e:
            print(f"  下载失败: {e}", file=sys.stderr)
            sys.exit(1)

# ---------- 数据转换 ----------
def load_toml(file_path: Path) -> Dict[str, Any]:
    with open(file_path, 'rb') as f:
        return tomllib.load(f)

def load_token_file(token_path: Path) -> Dict[str, str]:
    if not token_path.exists():
        return {}
    with open(token_path, 'rb') as f:
        data = tomllib.load(f)
    return {k: str(v) for k, v in data.items()}

def save_token_file(token_path: Path, token_map: Dict[str, str]) -> None:
    with open(token_path, 'w', encoding='utf-8') as f:
        for name, token in token_map.items():
            f.write(f'"{name}" = "{token}"\n')

def validate_path(path: str) -> bool:
    if not path.startswith('/'):
        return False
    if path.endswith('/'):
        return False          # 文件路径不允许以 / 结尾
    if path != path.strip():
        return False
    if '//' in path:
        return False
    if '\\' in path:
        return False
    return True

def convert_data(input_file: Path, data_dir: Path, yes: bool) -> None:
    # 处理 data_dir
    if data_dir.exists():
        if yes:
            import shutil
            shutil.rmtree(data_dir)
            print(f"已删除目录: {data_dir}")
        else:
            resp = input(f"目录 {data_dir} 已存在，是否删除并重建? (y/N): ")
            if resp.lower() != 'y':
                print("操作取消")
                sys.exit(0)
            import shutil
            shutil.rmtree(data_dir)
    ensure_dir(data_dir)
    ensure_dir(data_dir / 'user')

    # 加载原始数据
    print(f"加载原始数据: {input_file}")
    raw = load_toml(input_file)

    # 加载 token 清单
    token_file = input_file.parent / 'token.toml'
    token_map = load_token_file(token_file)

    users = raw.get('user', {})
    groups = raw.get('group', {})
    files = raw.get('file', {})

    # 验证约束
    for gname, gval in groups.items():
        if 'users' not in gval:
            gval['users'] = []
        for uname in gval['users']:
            if uname not in users:
                raise ValueError(f"组 {gname} 引用了不存在的用户 {uname}")

    for fpath, fval in files.items():
        if 'groups' not in fval:
            fval['groups'] = []
        for gname in fval['groups']:
            if gname not in groups:
                raise ValueError(f"文件 {fpath} 引用了不存在的组 {gname}")

    for fpath in files.keys():
        if not validate_path(fpath):
            raise ValueError(f"文件路径不符合规范: {fpath}")

    # 分配 id：先 group 后 file（file 按路径排序）
    group_items = list(groups.items())
    file_items = sorted(files.items(), key=lambda x: x[0])

    data_records = []          # (type, name, obj, id)
    id_counter = 0
    for gname, gval in group_items:
        data_records.append(('group', gname, gval, id_counter))
        id_counter += 1
    for fpath, fval in file_items:
        data_records.append(('file', fpath, fval, id_counter))
        id_counter += 1

    # 存放加密后的数据 [nonce, ciphertext+tag]
    encrypted_data = [None] * len(data_records)

    # 密钥映射
    file_key_map = {}   # 路径 -> 密钥
    group_key_map = {}  # 组名 -> 密钥

    # 第一次循环：为每条记录生成 key 和 iv，并加密 file（group 稍后处理）
    for record_type, name, obj, id_ in data_records:
        key = get_random_bytes(AES_KEY_LEN)
        if record_type == 'file':
            file_key_map[name] = key
            plaintext = msgpack.packb({
                'path': name,
                'loc': obj.get('loc', ''),
                'pwd': obj.get('pwd', ''),
                'desc': obj.get('desc', ''),
                'author': obj.get('author', '')
            })
            nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext)
            encrypted_data[id_] = [nonce, ciphertext + tag]
        else:  # group
            group_key_map[name] = key
            # 暂存 key，稍后加密
            obj['_key'] = key

    # 构建组 -> 文件列表的映射（反向索引）
    group_files = {gname: [] for gname in groups.keys()}
    for fpath, fval in files.items():
        for gname in fval.get('groups', []):
            if gname in group_files:
                group_files[gname].append(fpath)

    # 第二次循环：加密 group
    for record_type, name, obj, id_ in data_records:
        if record_type == 'group':
            key = group_key_map[name]
            files_list = []
            for fpath in group_files.get(name, []):
                fid = None
                # 根据路径查找文件 id
                for rt, rn, robj, rid in data_records:
                    if rt == 'file' and rn == fpath:
                        fid = rid
                        break
                if fid is None:
                    raise ValueError(f"组 {name} 引用了不存在的文件 {fpath}")
                file_key = file_key_map.get(fpath)
                if file_key is None:
                    raise ValueError(f"无法找到文件 {fpath} 的密钥")
                files_list.append([fid, file_key])
            group_plain = msgpack.packb(files_list)
            nonce, ciphertext, tag = encrypt_aes_gcm(key, group_plain)
            encrypted_data[id_] = [nonce, ciphertext + tag]

    # 加密用户数据并写入文件
    for uname, uval in users.items():
        user_groups = []
        for gname, gval in groups.items():
            if uname in gval.get('users', []):
                # 查找组 id
                gid = None
                for rt, rn, robj, rid in data_records:
                    if rt == 'group' and rn == gname:
                        gid = rid
                        break
                if gid is None:
                    raise ValueError(f"用户 {uname} 引用的组 {gname} 未找到")
                gkey = group_key_map.get(gname)
                if gkey is None:
                    raise ValueError(f"组 {gname} 的密钥未找到")
                user_groups.append([gid, gkey])

        user_obj = {
            'name': uname,
            'groups': user_groups
        }
        user_plain = msgpack.packb(user_obj)

        salt = get_random_bytes(16)
        token = token_map.get(uname)
        if token is None:
            token = generate_token()
            token_map[uname] = token
        key = derive_key_from_token(token, salt)
        nonce, ciphertext, tag = encrypt_aes_gcm(key, user_plain)
        user_encrypted = [salt, nonce, ciphertext + tag]

        token_hash = urlsafe_b64encode(sha256_bytes(token.encode('utf-8')))
        user_file_path = data_dir / 'user' / token_hash
        with open(user_file_path, 'wb') as f:
            f.write(msgpack.packb(user_encrypted))
        print(f"  用户 {uname} -> {user_file_path}")

    # 写入共享数据文件 data/data
    data_path = data_dir / 'data'
    with open(data_path, 'wb') as f:
        f.write(msgpack.packb(encrypted_data))
    print(f"共享数据文件已写入: {data_path}")

    # 保存 token.toml
    save_token_file(token_file, token_map)
    print(f"Token 清单已更新: {token_file}")

    print(f"\n转换完成:")
    print(f"  用户数: {len(users)}")
    print(f"  组数: {len(groups)}")
    print(f"  文件数: {len(files)}")
    print(f"  数据记录总数: {len(data_records)}")

# ---------- 主函数 ----------
def main():
    parser = argparse.ArgumentParser(
        description='资源文件管理工具 - 下载依赖并转换数据文件',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--update-lib', nargs='?', const='./lib/', default=None,
                        help='下载第三方库到指定目录 (默认 ./lib/)')
    parser.add_argument('-c', '--convert', nargs='*', metavar=('INPUT_FILE', 'DATA_DIR'),
                        help='转换数据文件: INPUT_FILE (默认 ./data.toml) 和 DATA_DIR (默认 ./data/)')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='静默删除并重建 DATA_DIR，无需确认')
    args = parser.parse_args()

    if args.update_lib is None and args.convert is None:
        parser.print_help()
        sys.exit(1)

    if args.update_lib is not None:
        lib_dir = Path(args.update_lib)
        download_lib(lib_dir)

    if args.convert is not None:
        if len(args.convert) == 0:
            input_file = Path('./data.toml')
            data_dir = Path('./data/')
        elif len(args.convert) == 1:
            input_file = Path(args.convert[0])
            data_dir = Path('./data/')
        elif len(args.convert) == 2:
            input_file = Path(args.convert[0])
            data_dir = Path(args.convert[1])
        else:
            print("错误: -c 最多接受两个参数", file=sys.stderr)
            sys.exit(1)

        if not input_file.exists():
            print(f"错误: 输入文件不存在: {input_file}", file=sys.stderr)
            sys.exit(1)

        convert_data(input_file, data_dir, args.yes)

if __name__ == '__main__':
    main()