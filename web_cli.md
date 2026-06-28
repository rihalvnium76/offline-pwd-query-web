# 离线查询网页 {#offline-web}

这是一个纯前端、可离线部署的数据查询页面，页面所使用的数据文件通过加密实现严格的访问控制。

用户输入管理员分配的 Token 来登录，页面会用该 Token 从数据文件中解密并展示该 Token 允许访问的数据。

为减小页面体积，代码尽可能使用原生 JavaScript，避免引入第三方库；数据文件采用紧凑格式，并通过 ID 引用共享数据以避免重复。

## 项目结构

- `index.html` 离线查询网页主体
- `data/` 数据文件目录
    - `user/{tokenHash}` 用户数据文件
    - `data` 共享数据文件

### 用户数据文件 `data/user/{tokenHash}`（`encryptedUser`）

文件为二进制格式，其结构如下：

- `encryptedUser -> salt:u8[16] iv:u8[12] enc:u8[]`
    - `salt`: PBKDF2 盐值
    - `iv`: AES-GCM Nonce
    - `enc`: AES-GCM 密文 + Tag（适配 Web Crypto API）
    - 解密后得到 `user`

`user` 结构（二进制格式）：`(groupId:u16 groupKey:u8[32])[]`

### 共享数据文件 `data/data`（`dataSet`）

文件为二进制格式，其结构如下：

- `dataSet -> (size:u32 encryptedData:u8[size])[]`
- `encryptedData -> iv:u8[12] enc:u8[]`
    - `iv`: AES-GCM Nonce
    - `enc`: AES-GCM 密文 + Tag
    - 解密后得到 `group` 或 `file`

`group` 结构（二进制格式）：`(fileId:u16 fileKey:u8[32])[]`

`file`：UTF-8 编码的 JSON

```json
{
    "name": "<fileName|originalPath>",
    "path": "<filePath>",
    "pwd": "<filePassword>",
    "desc": "[description]",
    "author": "[authorName]"
}
```

### 端序定义

使用小端序

### 加密算法相关参数

- Token：由 Python `secrets.token_urlsafe()` 生成
- PBKDF2：哈希算法 HMAC-SHA-256，盐值长度 16 字节，迭代次数 600000 次，输出长度 32 字节
- AES-GCM（AES-256-GCM）：密钥长度 32 字节，Nonce（IV）长度 12 字节，Tag 长度 16 字节

## 文件缓存

禁用网页与数据文件的缓存

## 文件读取

使用 `fetch()` 异步加载固定路径的数据文件，严禁设计为让用户上传数据文件

## 功能流程参考

页面初始化：

1. 读取 `data/data` 文件的内容，计算其 SHA-256 哈希值并以 Hex 字符串形式存入 `dataHash`，然后将该文件内容解析为 `[iv, enc][]` 数组存入 `data`
    - 读取失败则禁止进行登录，并终止初始化流程（同时向用户显示错误）
2. 读取 localStorage 中缓存的 Token。若存在 Token，则自动输入该 Token 到输入框并触发登录逻辑。若自动登录失败，则清除缓存的 Token

用户登录：

1. 用户输入 Token 登录
2. `tokenBytes = token.encode("utf-8"); tokenHash = sha256Hex(tokenBytes)`
3. 读取 `data/user/{tokenHash}` 并解析出 `salt`、`iv`、`enc`
    - 若文件不存在则说明 Token 无效，终止流程
4. 用 `salt` 和 `tokenBytes` 通过 PBKDF2 派生出密钥 `key`，再结合 `iv`，对 `enc` 进行 AES-256-GCM 解密，反序列化后得到 `user`
5. `files = []; visited = new Set()`
6. 遍历 `user`，其记录解构为 `[groupId, groupKey]`：
    1. `encryptedGroup = data[groupId]`
    2. 用 `groupKey` 对 `encryptedGroup` 进行 AES-256-GCM 解密，反序列化后得到 `group`
    3. 遍历 `group`，其记录解构为 `[fileId, fileKey]`：
        1. 若 `fileId` 存在于 `visited`，则跳过该记录，否则添加 `fileId` 到 `visited`
        2. `encryptedFile = data[fileId]`
        3. 用 `fileKey` 对 `encryptedFile` 进行 AES-256-GCM 解密，反序列化后得到 `file`
        4. 添加 `file` 到 `files`
7. 将 `files` 按 `File.path`、`File.name` 进行升序排序，后续 `files` 会显示到页面的文件表格中
8. 将当前登录的 Token 明文存入 localStorage

## 网页 UI

### 页面元素

- Token 输入框（`type="password"`）
- “登录”按钮
    - 登录按钮始终显示，已登录再点击登录是重新/切换登录
    - 每次重新登录或切换用户前，必须清空当前用户的状态数据、缓存，并重置 UI 状态（包括清空及隐藏文件表格等）
    - 登录成功后缓存当前用户的 Token 到 localStorage，下次进入页面自动登录
- “退出”按钮
    - 用户登录后按钮可见且可点击；未登录时按钮隐藏且处于禁用状态
    - 退出登录时，需要清空用户的状态数据、缓存，和重置 UI 状态
- 提示信息区：展示用户提示信息，其中错误提示为红色，其他提示为默认颜色
- 文件表格搜索框：可搜索文件表格中的所有内容，搜索结果直接显示在文件表格中
- 文件表格
    - 表格列：
        - 名称（`File.name`）
        - 路径（`File.path`）
        - 密码（`File.pwd`）
        - 描述（`File.desc`）
        - 作者（`File.author`）
    - 密码列的密码文本：
        - 密码文本的背景色（非整个单元格的背景色）为 #EBEEF2，且其背景带圆角样式
        - 密码文本点击可以复制到剪贴板，且复制成功时提示信息区显示“已复制密码到剪贴板”
        - 密码文本可以被选择复制（适配移动端某些 Clipboard API 失效的场景）
    - 描述列：
        - 表格中描述的单元格最多允许显示一行文本，超出部分截断显示为“...”
        - 点击描述文本可弹出模态框，完整展示并可复制内容
    - 表格分页显示，每页最多 100 条记录，支持跳页
    - 表格数据源自数据文件解析出的 `files`
    - 表格仅在解析出 `user` 后显示，没文件数据也要显示列头；Token 无效或无法解析出 `user`，则隐藏表格
- 数据文件校验码区
    - `dataHash` 有值时显示该值（灰色文字）；无值时隐藏校验码区域
    - 显示在网页底部

### 页面元素状态

| 阶段 | 提示信息区 | “登录”按钮状态 |
| --- | --- | --- |
| 载入 `data/data`：载入中 | 显示“正在加载数据文件……” | 禁用 |
| 载入 `data/data`：成功 | 清空（占位留空） | 启用 |
| 载入 `data/data`：失败 | 显示红色文字“数据文件加载失败，请刷新页面重试或联系管理员” | 禁用 |
| 登录 - 解密中 | 显示“正在解密用户数据……”（若实现分批解密，可附加进度，如“已处理数/总数”，每 5 秒更新一次） | 禁用 |
| 登录 - Token 无效或解密失败 | 显示红色文字“Token 无效或数据解密失败” | 启用 |
| 登录 - 成功（有文件数据） | 清空（占位留空） | 启用 |
| 登录 - 成功（无文件数据或组数据） | 显示“暂无可访问的数据” | 启用 |

### 设备适配

UI 需要适配桌面端和移动端


# 数据文件管理工具

这是一个 Python CLI 脚本，用于生成 [离线查询网页](#offline-web) 所需的数据文件。

脚本主要功能有：

- 批量生成用户配置并输出到控制台
- 转换数据文件：转换人类易编写的 TOML 格式的原始数据文件为一系列自定义二进制格式的加密数据文件

除以下场景必须使用的依赖库外，脚本尽可能使用标准库实现，除非标准库实现过于复杂：

- pycryptodome 库：用于 AES 加密

命令行参数解析用 argparse 库，TOML 解析使用 tomllib 库。

## 批量生成用户配置并输出到控制台

命令行入参：`-u <USER_NAME> [<USER_NAME> ...]`

- `USER_NAME` 表示要生成配置的用户名

向控制台输出每个用户的配置。配置格式如下：

```toml
[user."<USER_NAME>"]
token = "<token>"

```

其中每个用户的 `<token>` 的值由 `secrets.token_urlsafe()` 独立生成。

## 转换数据文件

命令行入参：`-c [INPUT_FILE [OUTPUT_DIR]]` `[-y]`

- `INPUT_FILE` 是 TOML 格式的原始数据文件的路径，默认为当前路径下的 `data.toml`
- `OUTPUT_DIR` 是输出的加密数据文件目录，若目录不存在则递归创建。默认为当前路径下的 `data/`

- `-y` 表示静默删除并重建输出目录，无需确认

未指定 `-y` 时，若输出目录已存在，则询问是否删除并重建

### 原始数据文件

#### 文件结构

```toml
[user."<userName>"]
token = "<token>"

[group."<groupName>"]
# 允许空列表
users = ["<userName>"]

[[file]]
name = "<fileName|originalPath>"
path = "<filePath>"
pwd = "<filePassword>"
desc = "[description]"
# authorName 与 userName 无关联
author = "[authorName]"
# 允许空列表
groups = ["<groupName>"]
```

分配字段：

- `user` 的每条记录在后续转换过程中，会被分配到全局唯一的 `salt`、`iv`
- `group`、`file` 的每条记录在后续转换过程中，会被分配到全局唯一的 `iv`、`key`，同时该记录在输出 `data` 二进制数组中的位置下标（即该记录的 `id`）将被用作引用标识。例如，`user` 中的 `groupId` 和 `group` 中的 `fileId` 均指向对应记录在 `data` 数组中的下标值

#### 输入约束

唯一性约束：

- `user` 的记录之间的 `token` 不可重复

有效性约束：

- `group.<groupName>.users` 中的 `userName` 必须 `user[userName]` 存在
- `files[].groups` 中的 `groupName` 必须 `group[groupName]` 存在
