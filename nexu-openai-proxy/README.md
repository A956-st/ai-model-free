# 🚀 Nexu OpenAI Proxy

专为 **Trae IDE** 设计的反向代理工具，将 Nexu 自带的 AI 模型转换为标准 OpenAI API 格式，支持 function calling。

> 💡 不知道怎么获取 Nexu API Key？问问 AI 或者查看配置文件。

## ✨ 特性

- ✅ 标准 OpenAI API 格式
- ✅ 支持 Agent / Function Calling
- ✅ Streaming 响应
- ✅ 多模型切换

## 📦 支持的模型

| 模型 | 模型 ID |
|------|---------|
| GPT-5.4 Mini | `gpt-5.4-mini` |
| DeepSeek V3.2 | `deepseek-v3.2` |
| Gemini 3 Flash | `gemini-3-flash-preview` |
| GLM-5 | `glm-5` |
| Kimi K2.5 | `kimi-k2.5` |
| Mimo V2 Pro | `mimo-v2-pro` |
| MiniMax M2.7 | `minimax-m2.7` |

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

复制 `.env.example` 为 `.env` 并填写配置：

```bash
NEXU_API_BASE=https://link.nexu.io/v1
NEXU_API_KEY=your_api_key_here  # 不知道怎么获取？问问 AI 或查看配置文件
PROXY_HOST=127.0.0.1
PROXY_PORT=8866
```

### 3. 运行

```bash
python main.py
```

服务启动后会在 `http://127.0.0.1:8866` 提供标准 OpenAI API。

### 4. 在 Trae 中使用

在 Trae 的设置中添加自定义 OpenAI API：

- **Base URL**: `https://127.0.0.1:8866/v1`
- **API Key**: 任意值（如 `sk-test`）
- **Model**: 任选一个支持的模型 ID

## 📄 License

MIT License
