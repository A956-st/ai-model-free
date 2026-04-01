import os
import sys
import ssl
import datetime
import subprocess
import time
import json
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
import httpx
from dotenv import load_dotenv
load_dotenv()
from typing import Optional, List, Dict, Any, Literal, Union
from pydantic import BaseModel
import logging

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ============================================================
# 配置
# ============================================================
CERT_DIR = Path(__file__).parent / "certs"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"
DOMAIN = "api.openai.com"

NEXU_API_BASE = os.getenv("NEXU_API_BASE", "https://link.nexu.io/v1")
NEXU_API_KEY = os.getenv("NEXU_API_KEY", "")
HTTP_PORT = int(os.getenv("PROXY_PORT", "8866"))

MODEL_MAPPING = {
    "gpt-5.4-mini": "gpt-5.4-mini",
    "deepseek-v3.2": "deepseek-v3.2",
    "gemini-3-flash-preview": "gemini-3-flash-preview",
    "gemini-3.1-flash-lite-preview": "gemini-3.1-flash-lite-preview",
    "glm-5": "glm-5",
    "glm-5-turbo": "glm-5-turbo",
    "kimi-k2.5": "kimi-k2.5",
    "mimo-v2-pro": "mimo-v2-pro",
    "minimax-m2.7": "minimax-m2.7",
}

def generate_cert():
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("\n  正在安装 cryptography 依赖...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

    CERT_DIR.mkdir(exist_ok=True)

    def certs_match(cert_path, key_path):
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open(key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == \
                   key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        except:
            return False

    # Try to use traeproxy certs if they exist AND match
    traeproxy_cert = Path(__file__).parent / "trae-proxy" / "certs" / "cert.pem"
    traeproxy_key = Path(__file__).parent / "trae-proxy" / "certs" / "key.pem"
    if traeproxy_cert.exists() and traeproxy_key.exists():
        if certs_match(str(traeproxy_cert), str(traeproxy_key)):
            import shutil
            shutil.copy2(str(traeproxy_cert), str(CERT_FILE))
            shutil.copy2(str(traeproxy_key), str(KEY_FILE))
            print("  使用 traeproxy 已有证书 (已验证匹配)")
            return True
        else:
            print("  traeproxy 证书不匹配，将重新生成")

    if CERT_FILE.exists() and KEY_FILE.exists() and certs_match(str(CERT_FILE), str(KEY_FILE)):
        return True

    print("\n  正在生成证书...")
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(DOMAIN),
                x509.DNSName("openai.com"),
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("  证书生成成功!")
        return True
    except Exception as e:
        print(f"  证书生成失败: {e}")
        return False

def uninstall_cert():
    """从系统信任库中移除旧证书"""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {$_.Subject -like '*api.openai.com*'} | ForEach-Object { Remove-Item -Path $_.PSPath -Force }"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10
        )
        if result.returncode == 0:
            return True
    except:
        pass
    return False

def check_cert_trusted():
    """检查证书是否已在系统信任库中"""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {$_.Subject -like '*api.openai.com*'} | Select-Object -ExpandProperty Thumbprint"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10
        )
        if result.stdout.strip():
            return True
    except:
        pass
    return False

def install_cert_trust():
    print("\n--- 证书信任配置 ---")

    if not CERT_FILE.exists():
        print("  [失败] 证书文件不存在")
        return False

    # 1. 先卸载旧证书
    if check_cert_trusted():
        print("  发现已安装的旧证书，正在卸载...")
        uninstall_cert()
        time.sleep(1)

    # 2. 尝试静默安装
    print("  正在尝试静默安装证书...")
    silent_ok = False
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["certutil", "-addstore", "Root", str(CERT_FILE)],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=15
            )
            if result.returncode == 0:
                silent_ok = True
        except:
            pass

    # 3. 验证是否安装成功
    if silent_ok and check_cert_trusted():
        print("  [成功] 证书已安装到系统信任库")
        return True

    # 4. 静默失败，打开证书让用户手动安装
    print("\n  静默安装未生效，正在打开证书文件...")
    print(f"  文件: {CERT_FILE}")
    try:
        os.startfile(str(CERT_FILE))
    except:
        print(f"  请手动打开: {CERT_FILE}")

    print("\n  安装步骤:")
    print("  1. 点击 [安装证书]")
    print("  2. 选择 [本地计算机] -> 下一步")
    print("  3. 选择 [将所有证书放入下列存储]")
    print("  4. 点击 [浏览] -> 选择 [受信任的根证书颁发机构]")
    print("  5. 点击 [确定] -> [下一步] -> [完成]")
    print("  6. 看到 [导入成功] 提示后按回车继续...")

    try:
        input()
    except:
        pass

    # 5. 再次验证
    if check_cert_trusted():
        print("  [成功] 证书已确认安装到信任库!")
        return True
    else:
        print("  [失败] 证书仍未被信任，请检查是否选对了存储位置")
        return False

def check_hosts_entry():
    """检查 hosts 文件中是否有正确的记录"""
    if sys.platform == "win32":
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    else:
        hosts_path = "/etc/hosts"

    try:
        with open(hosts_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and DOMAIN in line:
                    parts = line.split()
                    if parts and parts[0] == "127.0.0.1":
                        return True
    except:
        pass
    return False

def modify_hosts(add=True):
    print(f"\n--- hosts 文件{'配置' if add else '清理'} ---")
    if sys.platform == "win32":
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    else:
        hosts_path = "/etc/hosts"

    try:
        with open(hosts_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except PermissionError:
        print("  [失败] 无法读取 hosts 文件，请以管理员身份运行")
        return False
    except Exception as e:
        print(f"  [失败] 读取 hosts 失败: {e}")
        return False

    entry = f"127.0.0.1 {DOMAIN}"
    entry2 = f"127.0.0.1 openai.com"
    new_lines = []
    found = False

    for line in lines:
        stripped = line.strip()
        is_our_entry = (DOMAIN in stripped or stripped == "openai.com") and not stripped.startswith("#") and stripped.startswith("127.0.0.1")
        if is_our_entry:
            found = True
            if add:
                new_lines.append(f"{entry}\n")
                new_lines.append(f"{entry2}\n")
        else:
            new_lines.append(line)

    if add and not found:
        new_lines.append(f"\n{entry}\n")
        new_lines.append(f"{entry2}\n")

    try:
        with open(hosts_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        if add:
            if check_hosts_entry():
                print(f"  [成功] hosts 记录: 127.0.0.1 {DOMAIN}")
                return True
            else:
                print(f"  [失败] hosts 写入后验证失败")
                return False
        else:
            print("  [成功] hosts 记录已清理")
            return True
    except PermissionError:
        print("  [失败] 无法写入 hosts 文件，请以管理员身份运行")
        return False
    except Exception as e:
        print(f"  [失败] 写入 hosts 失败: {e}")
        return False

# ============================================================
# 端口检测与进程管理
# ============================================================
import socket

def is_port_in_use(port):
    """使用 socket 检测端口是否被占用，比解析 netstat 更可靠"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False

def get_pids_on_port(port):
    """获取占用指定端口的所有进程 PID"""
    try:
        cmd = f'Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique'
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10
        )
        pids = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and line.isdigit() and int(line) > 0:
                pids.append(int(line))
        return pids
    except:
        return []

def kill_port(port, retries=3):
    """强制结束占用端口的所有进程，带重试机制"""
    for attempt in range(retries):
        pids = get_pids_on_port(port)
        if not pids:
            if attempt > 0:
                return True
            return False

        killed = 0
        for pid in pids:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5
                )
                killed += 1
            except:
                pass

        time.sleep(0.5)
        if not get_pids_on_port(port):
            return True

    return False

# ============================================================
# 代理应用
# ============================================================
app = FastAPI(title="Nexu Proxy", version="1.0.0")

def make_model_list():
    return [{"id": k, "object": "model", "created": 1700000000, "owned_by": "openai"} for k in MODEL_MAPPING]

MODELS = make_model_list()

class FunctionDef(BaseModel):
    name: str
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

class ToolDef(BaseModel):
    type: Literal["function"]
    function: FunctionDef

class FunctionCall(BaseModel):
    name: str
    arguments: str

class ToolCall(BaseModel):
    id: str
    type: Literal["function"] = "function"
    function: FunctionCall

class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: Optional[Any] = None
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

def normalize_message(msg):
    """Normalize message content: convert array content to string, filter images"""
    d = msg.model_dump(exclude_none=True)
    content = d.get("content")
    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, dict):
                if "text" in item:
                    texts.append(item["text"])
                elif "content" in item:
                    texts.append(item["content"])
                # Skip image_url and other non-text types
            elif isinstance(item, str):
                texts.append(item)
        d["content"] = "\n".join(texts) if texts else ""
    elif content is None:
        d["content"] = ""
    return d

class ChatRequest(BaseModel):
    model: str
    messages: List[Message]
    temperature: Optional[float] = 1.0
    top_p: Optional[float] = 1.0
    n: Optional[int] = 1
    stream: Optional[bool] = False
    stop: Optional[Union[str, List[str]]] = None
    max_tokens: Optional[int] = None
    presence_penalty: Optional[float] = 0
    frequency_penalty: Optional[float] = 0
    tools: Optional[List[ToolDef]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    response_format: Optional[Dict[str, str]] = None
    user: Optional[str] = None

@app.get("/v1/models")
async def list_models():
    return {"object": "list", "data": MODELS}

@app.get("/v1/models/{model_id}")
async def get_model(model_id: str):
    for m in MODELS:
        if m["id"] == model_id:
            return m
    raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")

@app.post("/v1/chat/completions")
async def chat_completions(req: ChatRequest, request: Request):
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    logger = logging.getLogger("nexu-proxy")
    
    try:
        body = await request.json()
        logger.info(f"=== TRAE REQUEST ===")
        logger.info(f"Body: {json.dumps(body, ensure_ascii=False)}")
    except Exception as e:
        logger.info(f"Could not read body: {e}")
    
    # Always use the real NEXU_API_KEY for upstream, ignore Trae's dummy key
    api_key = NEXU_API_KEY
    model = MODEL_MAPPING.get(req.model, req.model)

    payload = {
        "model": model,
        "messages": [normalize_message(m) for m in req.messages],
        "temperature": req.temperature,
        "top_p": req.top_p,
        "n": req.n,
        "stream": req.stream,
        "max_tokens": req.max_tokens,
        "stop": req.stop,
        "presence_penalty": req.presence_penalty,
        "frequency_penalty": req.frequency_penalty,
    }
    if req.tools:
        payload["tools"] = [t.model_dump() for t in req.tools]
    if req.tool_choice:
        payload["tool_choice"] = req.tool_choice
    if req.response_format:
        payload["response_format"] = req.response_format
    if req.user:
        payload["user"] = req.user

    logger.info(f"=== PROXY PAYLOAD ===")
    logger.info(f"Payload: {json.dumps(payload, ensure_ascii=False)[:1000]}")

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = f"{NEXU_API_BASE}/chat/completions"

    if req.stream:
        logger.info(f"=== STREAMING MODE ===")
        client = httpx.AsyncClient(timeout=300.0)
        return StreamingResponse(
            stream_sse(client, url, headers, payload, logger),
            media_type="text/event-stream",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )
    else:
        async with httpx.AsyncClient(timeout=300.0) as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
                # Always return 200, even if upstream returns error
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=200,
                    content=resp.json(),
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    }
                )
            except Exception as e:
                # Return valid JSON error instead of HTTP error
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=200,
                    content={"id": "error", "object": "chat.completion", "created": 0, "model": req.model, "choices": [{"index": 0, "message": {"role": "assistant", "content": f"请求出错: {str(e)}"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    }
                )

async def stream_sse(client, url, headers, payload, logger=None):
    if logger is None:
        logger = logging.getLogger("nexu-proxy")
    try:
        logger.info(f"=== UPSTREAM REQUEST ===")
        logger.info(f"URL: {url}")
        async with client.stream("POST", url, headers=headers, json=payload) as resp:
            logger.info(f"=== UPSTREAM RESPONSE ===")
            logger.info(f"Status: {resp.status_code}")
            if resp.status_code != 200:
                # 上游报错，构造错误响应
                error_body = await resp.aread()
                try:
                    error_data = json.loads(error_body)
                except:
                    error_data = {"error": {"message": error_body.decode("utf-8", errors="replace")}}
                logger.error(f"=== UPSTREAM ERROR ===")
                logger.error(f"Error: {json.dumps(error_data, ensure_ascii=False)}")
                error_event = {
                    "id": "error",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "",
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": f"Error: {json.dumps(error_data)}"}, "finish_reason": "stop"}]
                }
                yield f"data: {json.dumps(error_event)}\n\n"
                yield "data: [DONE]\n\n"
                return

            seen_finish = False
            chunk_count = 0
            async for line in resp.aiter_lines():
                if not line:
                    continue
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str == "[DONE]":
                    yield "data: [DONE]\n\n"
                    break
                if seen_finish:
                    continue
                try:
                    data = json.loads(data_str)
                    choices = data.get("choices", [])
                    if choices:
                        fr = choices[0].get("finish_reason")
                        if fr:
                            seen_finish = True
                    chunk_count += 1
                    logger.info(f"=== SSE CHUNK {chunk_count} ===")
                    logger.info(f"Chunk: {line[:200]}")
                    yield f"{line}\n\n"
                except json.JSONDecodeError:
                    yield f"{line}\n\n"
    finally:
        await client.aclose()

@app.options("/v1/chat/completions")
async def options_handler():
    from fastapi.responses import Response
    return Response(
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400",
        }
    )

@app.get("/health")
async def health():
    return {"status": "ok"}

# ============================================================
# 测试功能
# ============================================================
def test_model(model_name):
    try:
        import requests
        resp = requests.post(
            f"http://127.0.0.1:{HTTP_PORT}/v1/chat/completions",
            json={"model": model_name, "messages": [{"role": "user", "content": "你好"}], "max_tokens": 30},
            timeout=30
        )
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return True, content[:100]
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)

# ============================================================
# 交互式菜单
# ============================================================
def print_header():
    print("\n" + "=" * 50)
    print("  Nexu 代理 - Trae 专用版")
    print("=" * 50)

def print_menu():
    print("\n--- 主菜单 ---")
    print("  1. 启动 Trae 代理 (HTTPS 443端口)")
    print("  2. 启动普通代理 (HTTP 8866端口)")
    print("  3. 测试模型连接")
    print("  4. 查看服务状态")
    print("  5. 查看配置信息")
    print("  6. 停止所有服务")
    print("  7. 清理环境 (恢复hosts/删除证书)")
    print("  8. 启动 Trae 代理 (调试模式 - 显示实时日志)")
    print("  0. 退出")
    print("-" * 50)

def check_status():
    https = is_port_in_use(443)
    http = is_port_in_use(HTTP_PORT)
    cert_trusted = check_cert_trusted()
    hosts_ok = check_hosts_entry()

    print("\n--- 服务状态 ---")
    print(f"  Trae 代理 (443):  {'运行中' if https else '未运行'}")
    print(f"  普通代理 ({HTTP_PORT}):  {'运行中' if http else '未运行'}")
    print(f"  证书文件:  {'存在' if CERT_FILE.exists() else '不存在'}")
    print(f"  证书信任:  {'已信任' if cert_trusted else '未信任'}")
    print(f"  hosts 配置:  {'已设置' if hosts_ok else '未设置'}")

    if https and cert_trusted and hosts_ok:
        print("\n  [OK] Trae 代理完全就绪")
    elif https and (not cert_trusted or not hosts_ok):
        print("\n  [警告] 代理运行中但配置不完整:")
        if not cert_trusted:
            print("    - 证书未被系统信任，Trae 会报 SSL 错误")
        if not hosts_ok:
            print(f"    - hosts 缺少 127.0.0.1 {DOMAIN} 记录")

def show_config():
    print("\n--- 配置信息 ---")
    print(f"  上游地址: {NEXU_API_BASE}")
    print(f"  API Key:  {NEXU_API_KEY[:15]}..." if NEXU_API_KEY else "  API Key:  (未设置)")
    print(f"  HTTP端口: {HTTP_PORT}")
    print(f"  可用模型:")
    for name in MODEL_MAPPING:
        print(f"    - {name}")
    print("\n--- Trae 配置 ---")
    print("  供应商: OpenAI")
    print("  API Key: nexu-proxy (任意字符)")
    print("  模型:  gpt-5.4-mini (或上方任意模型名)")

def cleanup():
    print("\n--- 清理环境 ---")
    if is_port_in_use(443):
        print("  正在停止 Trae 代理...")
        kill_port(443)
        time.sleep(1)
    if is_port_in_use(HTTP_PORT):
        print(f"  正在停止普通代理...")
        kill_port(HTTP_PORT)
        time.sleep(1)

    modify_hosts(add=False)

    for f in [CERT_FILE, KEY_FILE]:
        if f.exists():
            f.unlink()
            print(f"  {f.name} 已删除")

    print("  清理完成!")

def start_https():
    print("\n--- 启动 Trae 代理 ---")

    # Check if port 443 is truly occupied
    pids = get_pids_on_port(443)
    if pids:
        print(f"  443 端口被进程 {pids} 占用，正在清理...")
        kill_port(443)
        time.sleep(1.5)

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        if not generate_cert():
            print("  [失败] 证书生成失败")
            return

    if not install_cert_trust():
        print("  [失败] 证书未信任，Trae 将无法连接")
        return

    if not modify_hosts(add=True):
        print("  [失败] hosts 配置失败")
        return

    print("\n  正在启动 HTTPS 代理...")

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "0.0.0.0", "--port", "443",
         "--ssl-keyfile", str(KEY_FILE), "--ssl-certfile", str(CERT_FILE),
         "--log-level", "warning"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    time.sleep(2)

    if proc.poll() is not None:
        try:
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            stdout = proc.stdout.read().decode("utf-8", errors="replace")
            if stderr:
                print(f"\n  [失败] 启动错误:")
                for line in stderr.strip().split("\n")[-10:]:
                    print(f"    {line}")
            if stdout:
                for line in stdout.strip().split("\n")[-5:]:
                    print(f"    {line}")
        except:
            print("  [失败] 进程已退出，无法获取错误信息")
        return

    pids = get_pids_on_port(443)
    if pids:
        print("  [成功] HTTPS 代理已启动!")
        print(f"  地址: https://127.0.0.1:443")
        print(f"  进程 PID: {pids}")
        print("\n  Trae 配置:")
        print("    供应商: OpenAI")
        print("    API Key: nexu-proxy (任意字符)")
        print("    模型: gpt-5.4-mini")
        print("\n  服务正在后台运行，返回主菜单\n")
    else:
        print("  [失败] 进程已启动但端口 443 未监听")
        try:
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            if stderr:
                for line in stderr.strip().split("\n")[-10:]:
                    print(f"    {line}")
        except:
            pass
        proc.kill()

def start_https_debug():
    print("\n--- 启动 Trae 代理 (调试模式) ---")
    
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        if not generate_cert():
            print("  [失败] 证书生成失败")
            return

    if not install_cert_trust():
        print("  [失败] 证书未信任，Trae 将无法连接")
        return

    if not modify_hosts(add=True):
        print("  [失败] hosts 配置失败")
        return

    print("\n  正在启动 HTTPS 代理 (调试模式)...")
    print("  日志将实时显示，按 Ctrl+C 停止\n")

    try:
        import uvicorn
        from main import app
        uvicorn.run(app, host="0.0.0.0", port=443, ssl_keyfile=str(KEY_FILE), ssl_certfile=str(CERT_FILE), log_level="info")
    except KeyboardInterrupt:
        print("\n  已停止")

def start_http():
    print("\n--- 启动普通代理 ---")

    pids = get_pids_on_port(HTTP_PORT)
    if pids:
        print(f"  {HTTP_PORT} 端口被进程 {pids} 占用，正在清理...")
        kill_port(HTTP_PORT)
        time.sleep(1.5)

    print(f"\n  正在启动 HTTP 代理...")

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "0.0.0.0", "--port", str(HTTP_PORT),
         "--log-level", "warning"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    time.sleep(2)

    if proc.poll() is not None:
        try:
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            stdout = proc.stdout.read().decode("utf-8", errors="replace")
            if stderr:
                print(f"\n  [失败] 启动错误:")
                for line in stderr.strip().split("\n")[-10:]:
                    print(f"    {line}")
            if stdout:
                for line in stdout.strip().split("\n")[-5:]:
                    print(f"    {line}")
        except:
            print("  [失败] 进程已退出，无法获取错误信息")
        return

    pids = get_pids_on_port(HTTP_PORT)
    if pids:
        print("  [成功] HTTP 代理已启动!")
        print(f"  地址: http://127.0.0.1:{HTTP_PORT}")
        print(f"  进程 PID: {pids}")
        print("\n  Cline / OpenCode 配置:")
        print(f"    Base URL: http://127.0.0.1:{HTTP_PORT}/v1")
        print("    API Key: nexu-proxy")
        print("\n  服务正在后台运行，返回主菜单\n")
    else:
        print("  [失败] 进程已启动但端口未监听")
        try:
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            if stderr:
                for line in stderr.strip().split("\n")[-10:]:
                    print(f"    {line}")
        except:
            pass
        proc.kill()

def stop_all():
    print("\n--- 停止所有服务 ---")
    killed = 0
    for port in [443, HTTP_PORT, 8000, 8080, 3000]:
        pids = get_pids_on_port(port)
        if pids:
            for pid in pids:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5
                    )
                    killed += 1
                except:
                    pass
    if killed > 0:
        print(f"  [成功] 已停止 {killed} 个进程")
    else:
        print("  没有发现运行中的服务")

def test_models():
    print("\n--- 测试模型连接 ---")
    print("  注意: 需要先启动普通代理 (选项2)\n")

    for i, (name, _) in enumerate(MODEL_MAPPING.items(), 1):
        print(f"  {i}. {name}")

    try:
        choice = input("\n  选择模型 (输入序号，回车测试全部): ").strip()
        if not choice:
            models = list(MODEL_MAPPING.keys())
        else:
            idx = int(choice) - 1
            models = [list(MODEL_MAPPING.keys())[idx]]
    except (ValueError, IndexError):
        print("  无效输入")
        return

    for model in models:
        print(f"\n  测试 {model}...", end=" ")
        success, result = test_model(model)
        if success:
            print("成功!")
            print(f"  回复: {result}")
        else:
            print(f"失败: {result}")

def main():
    print_header()

    while True:
        try:
            print_menu()
            choice = input("  请选择 [0-8]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  再见!")
            break

        if choice == "1":
            start_https()
        elif choice == "2":
            start_http()
        elif choice == "3":
            test_models()
        elif choice == "4":
            check_status()
        elif choice == "5":
            show_config()
        elif choice == "6":
            stop_all()
        elif choice == "7":
            cleanup()
        elif choice == "8":
            start_https_debug()
        elif choice == "0":
            print("\n  正在停止所有服务...")
            stop_all()
            print("  再见!")
            break
        else:
            print("  无效选项，请重新输入")
            print("  无效选项，请重新输入")

if __name__ == "__main__":
    main()
