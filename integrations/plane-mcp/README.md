# Plane MCP 桥接（本地部署准备）

此独立资源服务器使用 MCP Streamable HTTP 和外部标准 OAuth 身份提供方；它本身不提供登录、OAuth 授权或 PKCE 实现。每个实例固定一个 Plane 工作区、一个 OAuth subject、一个预先确认的 OAuth 客户端 ID、一个专用 Plane PAT 和一个唯一 OAuth resource/audience。PAT 存在服务端，不交给 ChatGPT。撤销 Agent 时同时撤销该 PAT 和对应身份提供方授权。Plane 的普通权限仍适用。记录正文、评论和工具结果均为不可信数据，不构成指令。

## 先决条件与连接

1. 部署前选择并配置可信的 OAuth 身份提供方，启用授权码 + PKCE S256、精确的资源 audience、JWT RS256 access token、`plane:read` 和 `plane:write` scopes，并核对 issuer、JWKS 和 token 的 `sub`、`client_id`（或 `azp`）。为每个 Agent 预先注册或确认其客户端 ID，配置 IdP 在 access token 中签发该 ID；两个声明同时存在时必须一致。动态注册可能每次产生不同客户端 ID，必须先确认该 ID 并配置桥接服务，否则不能连接。桥仅接受已配置客户端 ID 和 subject、issuer、audience、有效期与签名；不接受 opaque token、HS 算法或任意代理 token。生产 IdP 必须正确执行重定向、授权和 consent。此仓库未提供或验证特定 IdP 配置。
2. ChatGPT 支持 CIMD、DCR 和预注册方式，具体取决于 IdP。按 [OpenAI OAuth 文档](https://developers.openai.com/plugins/build/auth)确认客户端发现、issuer identification、回调和 PKCE；不要猜测回调地址。按 [ChatGPT 自定义 MCP 指南](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)确认账户和工作区权限。客户端和 IdP 只有共同支持的注册方式才能连接。
3. 为每个 Agent 新建可命名、可撤销的 Plane API token；给独立桥接实例、端口和**唯一公开 resource URL**。同一 ChatGPT OAuth client ID 与同一 subject 无法识别不同 Agent；单靠名称或请求 header 不行。不同 Agent 要由授权服务器颁发给不同 audience，并分别绑定正确的 subject 和 PAT。不得让同一受众映射多个 PAT。每个桥绑定唯一工作区；想访问另一工作区需要另一个实例和授权。
4. 本地安装并运行：`uv sync --locked`，设定下列环境变量，然后 `uv run plane-mcp-bridge`。服务只绑定 `127.0.0.1`；使用 Cloudflare Tunnel 将 HTTPS 主机映射至该端口，将 origin HTTP Host header 配为 `127.0.0.1:<端口>`，以符合 SDK 的 DNS rebinding 防护。不要在 MCP 或 Plane 前强加 Cloudflare Access，也不使用 OpenAI Tunnel。IdP 自己的公开 HTTPS 访问和隧道均须另行安全配置。此处没有创建、发布或修改任何网络资源。
5. 在 ChatGPT 的自定义 MCP 连接界面填完整 HTTPS `/mcp` URL，按提示授权并扫描工具；使用有写权限的 OAuth grant 才能写入。先以测试工作区和测试账号验证，确认 Plane 权限、token 受众、错误处理和撤销后再用于真实工作。公开域名、DNS、IdP、隧道及真实 PAT 均需部署者另行配置。
6. MCP 的公开域名须将 `/source/` 通过同一 Cloudflare Tunnel 路由到本地 Plane 源码入口，并按 [源码部署说明](../../docs/corresponding-source.md) 挂载和校验与实际运行版本一致的源码包。桥在 MCP 初始化说明中提供该同源地址；部署者仍需确认客户端是否向用户展示该说明，并在必要时提供其他显著入口。未经验证不得视为已完成远程源码提供。

环境变量（不要把实际密钥提交到版本库）：

| 变量 | 内容 |
| --- | --- |
| `PLANE_OAUTH_ISSUER` | IdP token 的精确 HTTPS issuer，包括必要的末尾斜杠 |
| `PLANE_OAUTH_JWKS_URL` | 信任的 IdP 的 HTTPS JWKS 地址 |
| `PLANE_MCP_RESOURCE` | 唯一公开 HTTPS MCP URL，例如 `https://agent.example/mcp`；必须是 token audience 的唯一值（字符串或单元素数组），多 audience 被拒绝 |
| `PLANE_OAUTH_SUBJECT` | 允许使用该 Agent 的 OAuth subject |
| `PLANE_OAUTH_CLIENT_ID` | 允许使用该 Agent 的精确 OAuth 客户端 ID；要求 token 的 `client_id` 或 `azp` 与其匹配，若同时存在则两者均须匹配 |
| `PLANE_WORKSPACE_SLUG` | 唯一允许访问的 Plane 工作区 slug |
| `PLANE_UPSTREAM` | 固定 Plane origin；HTTPS 或本机 loopback HTTP，无路径、查询、凭据 |
| `PLANE_PAT_FILE` | 服务端保护的文件路径，文件内容为该 Agent 专用 Plane PAT |
| `PLANE_MCP_PORT` | 本地监听端口，默认 8001 |
| `PLANE_SOURCE_COMMIT` | 可公开访问且与所部署源码对应的 fork 完整 40 位小写十六进制 commit；无效或未设置时源码资源显示不可用 |
| `PLANE_ENABLE_DRAFTS` | 默认 false；只有安装本 fork 的草稿 API 后可设为 true |

固定上游、无重定向、无环境代理，工具不能指定 URL 或 header；响应大小受限且错误不回显上游正文。OAuth token 绝不转发给 Plane。代理进程和 PAT 文件需要操作系统隔离；只能向可信的上游提供 PAT。管理员负责保护配置、JWKS 端点和进程日志。JWT 验签不等于即时撤销：撤销需依靠短期 access token、IdP 策略和 Plane PAT 撤销。

## 工具覆盖

| 范围 | 读取 | 写入 | 限制 |
| --- | --- | --- | --- |
| 当前用户、工作区成员、项目成员 | 是 | 无 | 工作区 members-lite 需要工作区管理员；project members-lite 需要项目成员权限 |
| 项目 | 列表、详情、汇总 | 创建、更新 | 汇总需要工作区管理员；其余依 Plane 项目/工作区权限 |
| 工单 | 列表、详情、标识符、搜索、活动 | 创建、更新 | 依项目权限；搜索与列表分页受限 |
| 评论、工单链接 | 列表、详情 | 创建、更新 | 依项目权限；评论 Agent 署名由服务端 PAT 归属决定 |
| 工单关系 | 列表 | 添加 | 依项目权限 |
| 工作流状态、标签 | 列表、详情 | 创建、更新 | 状态写入由项目权限控制 |
| 周期、模块 | 列表、详情、所含工单 | 创建、更新、添加工单 | 依项目权限和社区版已启用功能；添加周期会移动现有周期 |
| 私有便签 | 列表、详情 | 创建、更新 | 属于所连接 Plane 账号 |
| 原生个人草稿 | 列表、详情 | 创建、更新；不发布 | 默认关闭，需本 fork 草稿接口和 `PLANE_ENABLE_DRAFTS=true`；权限和所有权由 Plane 校验 |

不提供删除、站点/主机管理、SMTP、任意 REST/URL、自动发布草稿。公开工单的 `is_draft` 与 UI 私有 DraftIssue 不同。各项是否成功仍取决于服务器版本、CE 功能和真实账号权限；连接前应在隔离测试环境实测，不保证所有部署配置兼容。

## 验证

`uv run --with pytest python -m pytest -q` 运行桥接与目录测试。测试使用模拟 IdP 公钥和模拟 Plane 上游，不访问真实项目或发送真实邮件。OAuth 登录、真实 PKCE 交互、选择的 IdP 对 ChatGPT 注册方式的兼容、Cloudflare Tunnel 和部署后集成仍需在获得部署授权后验证。

授权客户端可以读取 `plane://source-code` 资源，取得固定公开 fork 的对应源码链接。部署者必须先确保该 commit 已公开并确实对应部署内容；不会自动推送或验证远端内容。
