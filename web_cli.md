# 离线查询网页（`index.html`） {#offline-web}

这是一个纯前端、可离线部署、支持多级目录分组显示（类似网盘 UI）的数据查询页面，页面所使用的数据文件通过加密实现严格的访问控制。

用户输入管理员分配的 Token 来登录，页面会用该 Token 从数据文件中解密并展示该 Token 允许访问的数据。

为减小页面体积，代码尽可能使用原生 JavaScript，避免引入第三方库（除了 MessagePack 库）；数据文件采用紧凑格式，并通过 ID 引用共享数据以避免重复。

## 加密/哈希算法相关参数

- Token 生成：Python `secrets.token_urlsafe()`
- PBKDF2：哈希算法 HMAC-SHA-256，盐值长度 16 字节，迭代次数 600000 次，输出长度 32 字节
- AES-GCM：AES-256，密钥长度 32 字节，Nonce（IV）长度 12 字节，Tag 长度 16 字节

## 项目结构

- `index.html` 离线查询网页主体
- `data/` 数据文件目录
    - `user/{tokenHash}` 用户数据文件
    - `data` 共享数据文件
- `lib/` 第三方库目录
    - `msgpack.min.js` MessagePack 库（UMD 格式）

### 用户数据文件 `data/user/{tokenHash}`

文件为 MessagePack 格式，其结构如下：

```json
// 解密得到 user
[
    "<bin, PBKDF2 Salt>",
    "<bin, AES-GCM Nonce>",
    // Tag 拼在密文后以适配 Web Crypto API
    "<bin, AES-GCM 密文 + Tag>"
]
```

`user` 结构（MessagePack 格式）：

```json
{
    "name": "<str, userName>",
    "groups": [
        // 在 data 中指向加密的 group
        ["<uint, groupId>", "<bin, groupKey>"]
    ]
}
```

### 共享数据文件 `data/data`

文件为 MessagePack 格式，其结构如下：

```json
[
    // 外层数组的索引即为该记录的唯一 id（dataId）
    // 解密得到 group 或 file
    [
        "<bin, AES-GCM Nonce>",
        // Tag 拼在密文后以适配 Web Crypto API
        "<bin, AES-GCM 密文 + Tag>"
    ]
]
```

`group` 结构（MessagePack 格式）：

```json
// files
[
    // 在 data 中指向加密的 file
    ["<uint, fileId>", "<bin, fileKey>"]
]
```

`file` 结构（MessagePack 格式）：

```json
{
    "path": "<str, virtualFilePath>",
    "loc": "[str, externalRealFilePath]",
    "pwd": "[str, filePassword]",
    "desc": "[str, description]",
    "author": "[str, authorName]"
}
```

## 文件缓存

禁用网页与数据文件的缓存

## 文件读取

使用 `fetch()` 异步加载固定路径的数据文件，严禁设计为让用户上传数据文件

## 虚拟路径规范

- 路径仅支持 `/` 分隔符
- 路径必须以分隔符（根目录）开始
- 文件禁止以分隔符结束，目录必须以分隔符结束
- 同一目录下，文件与目录之间不能重名（如同一目录下，不能有两个文件或目录叫 a，也不能有一个文件和一个目录都叫 a）
- 文件/目录名不能以空白字符（ANSI 和 Unicode 空白字符，同 Python `str.strip()` 的范围）开始或结束
- 路径大小写敏感

## 功能流程参考

### 页面初始化

1. 加载 `lib/msgpack.min.js`。失败则显示红色错误，禁用登录，终止初始化流程
2. 读取 `data/data` 内容。成功则计算其 SHA-256 并转为 URL-safe Base64，存入 `dataHash`；反序列化存入 `data`。失败则显示红色错误，禁用登录，终止初始化流程
3. 检查 `localStorage` 中的 Token，若有则自动填入并尝试登录。失败则清除缓存

### 登录

1. 用户输入 Token 登录
2. `tokenBytes = token.encode("utf-8"); tokenHash = urlsafeBase64(sha256(tokenBytes))`
3. 读取 `data/user/{tokenHash}` 并反序列化到 `encryptedUser`
    - 若文件不存在则说明 Token 无效，终止流程
4. 用 `tokenBytes`、`encryptedUser` 通过 PBKDF2 派生出密钥 `key`，再对 `encryptedUser` 进行 AES-256-GCM 解密，反序列化后得到 `user`
5. `files = []; visited = new Set()`
6. 遍历 `user.groups`，其记录解构为 `[groupId, groupKey]`：
    1. `encryptedGroup = data[groupId]`
    2. 用 `groupKey` 对 `encryptedGroup` 进行 AES-256-GCM 解密，反序列化后得到 `group`
    3. 遍历 `group`，其记录解构为 `[fileId, fileKey]`：
        1. 若 `fileId` 存在于 `visited`，则跳过该记录，否则添加 `fileId` 到 `visited`
        2. `encryptedFile = data[fileId]`
        3. 用 `fileKey` 对 `encryptedFile` 进行 AES-256-GCM 解密，反序列化后得到 `file`
        4. 添加 `file` 到 `files`
7. 若 `files` 非空，则解析其中的路径（`file.path`）得到路径节点树与映射（例如构建一个 Map，键为规范化的路径，值为文件节点或目录节点；而目录节点含有子目录节点和文件节点列表），用于后续的面包屑导航和文件表格的渲染，以及搜索功能
8. 现在是登陆成功状态。将当前登录的 Token 明文存入 `localStorage`。设置当前目录路径为根目录，并显示其内容

> 解密最好实现为分批并行解密

## UI

### UI 元素

- Token 输入区
    - 单独一行，从左到右：Token 输入框，登录/注销按钮，用户信息区
        - 移动端空间不足时，可以 Token 输入框 在区域第 1 行，登录/注销按钮、用户信息区 在第 2 行
    - Token 输入框（密码类型）：
        - 输入框左边无提示文本
        - 输入框为空时，自身显示灰色文本“请输入 Token”
    - 登录/注销按钮：
        - 登录成功后为“注销”按钮，否则为“登录”按钮
        - 登录成功后将 Token 明文存入 `localStorage`，用于自动登录
        - 退出登录（注销）时，清空当前用户的状态数据、缓存（如 `localStorage`），并重置 UI 状态（包括清空及隐藏文件表格等）
    - 用户信息区：
        - 解析出 `user` 后，显示当前登录 Token 对应的用户名（`user.name`）；否则为空
        - 注意移动端可能会出现登录/注销按钮右边还有空间，但用户信息区依旧被挤到下一行的显示问题
- 提示信息区：独立一行。错误信息红色，普通信息默认色
- 文件目录搜索区：
    - 单独一行，从左到右为：搜索目标下拉框，搜索范围下拉框，搜索类型下拉框，搜索框，“搜索”按钮
        - 移动端页面空间不足时，可以 搜索目标下拉框、搜索范围下拉框、搜索类型下拉框 在区域第 1 行，搜索框、搜索按钮 在第 2 行
    - 搜索目标下拉框：
        - 选项：全部列，精确路径，路径，（文件表格的各列）
        - 默认选项：全部列
        - 搜索方式默认为模糊搜索
        - 特殊：“精确路径”为等值匹配，但忽略路径首尾的路径分隔符差异（例如输入 `a`、`/a` 或 `/a/` 仅匹配 `/a` 和 `/a/`，不匹配 `/ab` 或 `/a/b`）
    - 搜索范围下拉框：
        - 选项：全局，当前目录，当前及子目录
        - 默认选项：全局
        - 搜索目标为“精确路径”时，搜索范围仅允许为“全局”
        - “当前及子目录”选项：当前目录及其下面所有层级的子目录
    - 搜索类型下拉框：
        - 选项：全部，仅文件，仅目录
        - 默认选项：全部
    - 只有点击“搜索”按钮或者输入框中按下 Enter 才开始搜索，进入搜索状态；进行搜索时，若搜索内容为空字符串，则退出搜索状态
    - 搜索对象包括文件和目录
    - 搜索结果直接显示在文件表格中
    - 搜索结果为空时，表格无内容，而不是列出全部文件
    - 搜索结果条数统计显示在提示信息区
    - 搜索区在文件表格显示时显示，否则隐藏
    - 特殊：精确路径模式搜索 `/` 时，结果直接只显示一条可跳转的根目录记录
- 面包屑导航区：
    - 单独一行，允许多行显示，从左到右为：“上一级”按钮，“根目录”按钮，当前目录路径
    - “上一级”按钮是返回上一级目录，在根目录无效果
    - “根目录”按钮点击跳转到根目录
    - 当前目录路径显示格式参考虚拟路径规范，但路径分隔符两侧（除了首尾）有空格，举例：`/`，`/ 目录1 / 目录2 /`
    - 当前目录路径中各级目录（除了根目录和当前目录）可点击并跳转到对应目录
    - 当前目录路径中的当前目录（除了根目录）点击后复制当前目录路径到剪贴板（复制成功提示“已复制路径到剪贴板”）
    - 在搜索状态或文件表格不显示时，导航区隐藏，否则显示
- 文件表格
    - 列：
        - 名称
        - 位置（`file.loc`）
        - 密码（`file.pwd`）
        - 描述（`file.desc`）
        - 作者（`file.author`）
    - 名称列：
        - 非搜索状态下，显示 `file.path` 解析出的文件/目录名
        - 表格显示搜索结果时，该列显示文件/目录的全路径
        - 目录名/路径始终以路径分隔符为结尾，与文件区分
        - 点击文件名复制文件虚拟路径到剪贴板（复制成功提示“已复制路径到剪贴板”）
        - 点击目录名进入该目录
    - 位置列：文本点击复制（复制成功提示“已复制位置到剪贴板”）
    - 密码列：文本背景色（非整个单元格的背景色）`#EBEEF2`，圆角半径 6px，点击复制（复制成功提示“已复制密码到剪贴板”），支持移动端手动选择复制（适配移动端某些 Clipboard API 失效的场景）
    - 描述列：描述**手动截断到第一行行尾**，点击弹出模态框，标题为文件名，完整描述可复制
        - 截断到第一行行尾的代码参考：`const lines = (fullDesc == null ? '' : fullDesc).split('\n', 2); const firstLine = lines[0] ? lines[0].trim() : ''; const displayDesc = firstLine + (lines.length > 1 ? '…' : '')`
    - 目录始终显示在文件前面，然后表格记录以 名称列（名称/路径） 升序排列
    - 表格支持水平滚动，自动最大最适列宽（**保证所有单元格内容刚好完整显示，不被提前截断，尤其注意避免使用自动截断类或限制单元格最大宽度的 CSS 样式**）
    - 表格非搜索状态下仅显示当前目录的文件/目录记录
    - 表格（包括搜索结果）分页显示，每页最多 100 条记录，支持跳页
        - 分页组件从左到右为：“上一页”按钮，当前页数输入框（无 Spinner），总页数，跳转按钮，“下一页”按钮，分页大小输入框（无 Spinner）
        - 页数显示为 `第 [X] / Y 页`，`[]` 表示输入框
        - 页数输入框中按 Enter 或者点击“跳转”按钮后才跳页
        - 分页大小输入框：
            - 样式：`每页 [Z] 条`，`[]` 表示输入框
            - `Z` 默认为 100
            - `Z` 若为非正数，则显示全部记录
            - 输入框中按 Enter 后才生效
    - 表格数据源自数据文件解析出的路径节点树与映射
    - 表格（含表头）在解析出 `user` 后显示，后续即使无文件数据也保持显示表格；Token 无效或无法解析出 `user`，则隐藏表格
- 数据文件校验码区：网页底部显示 `dataHash`（灰色），无值则隐藏整个区域

- 不在页面内容中显示应用名/页面标题

### 页面元素状态

| 阶段 | 提示信息区 | 登录/注销按钮状态 |
| --- | --- | --- |
| 第三方库/依赖加载中 | “正在加载依赖……” | 禁用 |
| 第三方库/依赖加载失败 | 红色“依赖加载失败，请刷新页面重试或联系管理员” | 禁用 |
| `data/data` 加载中 | “正在加载数据文件……” | 禁用 |
| `data/data` 加载成功 | 清空 | 启用 |
| `data/data` 加载失败 | 红色“数据文件加载失败，请刷新页面重试或联系管理员” | 禁用 |
| 登录解密中 | “正在解密用户数据……”（分批解密时，追加“已解密数/总数”进度显示，每 5 秒更新） | 禁用 |
| 登录失败（Token 无效或解密失败） | 红色“Token 无效或数据解密失败” | 启用 |
| 登录成功（有文件数据） | 清空 | 启用 |
| 登录成功（无文件数据） | “暂无可访问的数据” | 启用 |

### 设备适配

需要适配桌面端和移动端

### 布局与元素风格

总体使用紧凑风格

## 其他

MessagePack 库的全局导入对象名为 `MessagePack`，不是 `msgpack`


# 资源文件管理工具（`cli.py`）

这是一个 Python CLI 脚本，用于准备 [离线查询网页](#offline-web) 所需的第三方库和数据文件。

脚本主要功能有：

- 下载更新依赖：自动下载更新页面所需的第三方库
- 转换数据文件：转换便于人工编写的 TOML 格式的原始数据文件为一系列二进制格式的加密数据文件

以上功能允许同时使用，相关命令行参数不要设计为互斥

脚本尽可能使用 Python 标准库，仅在以下场景引入第三方依赖：

- pycryptodome：AES 加密
- msgpack：MessagePack 格式序列化

命令行参数解析用标准库 argparse 库，TOML 解析使用标准库 tomllib 库

不考虑低版本 Python 兼容，不写兼容代码

## 下载更新依赖

命令行参数：`-u [LIB_DIR]`

- `LIB_DIR`：第三方库目录的位置，默认为 `./lib/`，若目录不存在则递归创建

依赖列表：

| 本地路径 | 下载地址 |
| --- | --- |
| `lib/msgpack.min.js` | <https://unpkg.com/@msgpack/msgpack/dist.umd/msgpack.min.js> |

## 转换数据文件

命令行参数：`-c [<INPUT_FILE> [DATA_DIR]] [-y]`

- `INPUT_FILE`：TOML 格式的原始数据文件的路径，默认为 `./data.toml`
- `DATA_DIR`：加密数据文件目录的位置，默认为 `./data/`，若目录不存在则递归创建

- `-y` 表示静默删除并重建 `DATA_DIR`，无需确认；未指定时若目录存在则交互询问

控制台输出转换的各类对象的总数，方便排查问题

### 原始数据文件 `data.toml`

#### 文件结构

```toml
# tokenFilePath 默认为本文件所在目录下的 token.toml
token_file = "[tokenFilePath]"

# 这里是空表
[user."<userName>"]

[group."<groupName>"]
# 允许空列表
users = ["<userName>"]

# file 仅表示文件记录
# 不会支持单独新增目录记录
[file."<virtualFilePath>"]
loc = "[externalRealFilePath]"
pwd = "[filePassword]"
desc = "[description]"
# authorName 与 userName 无关联
author = "[authorName]"
# 允许空列表
groups = ["<groupName>"]
```

#### 输入约束

有效性约束：

- `group.<groupName>.users` 中的每个 `userName` 必须在 `user` 表中有定义
- `file.groups` 中的每个 `groupName` 必须在 `group` 表中有定义
- `file` 的 `<virtualFilePath>` 必须遵守虚拟路径规范

#### 分配字段

- `user` 的每条记录在转换过程中，会被分配全局唯一的 `salt`、`iv`
- `group`、`file` 的每条记录在后续转换过程中，会被分配全局唯一的 `iv`、`key`，同时该记录在输出 `data` 数组中的位置下标（即该记录的 `id`）将被用作引用标识。例如，`user` 中的 `groupId` 和 `group` 中的 `fileId` 均指向对应记录在 `data` 数组中的下标值

#### Token

每个用户都有且仅有一个全局唯一的 Token

Token 不存放在对工具只读的原始数据文件中，而是存放于单独的可写的 Token 清单文件中，便于工具自动生成与回填。管理员只需查看清单文件

用户没有 Token 时，工具会生成分配新的 Token 并记录到清单文件中；否则使用清单文件中的 Token

### Token 清单文件 `token.toml`

#### 文件结构

```toml
"<userName>" = "<token>"
```

#### 输入约束

唯一性约束：

- 不同 `userName` 之间的 `token` 不可重复

有效性约束：

- `userName` 必须在原始数据文件的 `user` 表中有定义