"""Canonical simple-mode SMUGGLE renderer and artifact metadata."""

# Generated HTML/JavaScript intentionally contains long literal lines.
# ruff: noqa: E501

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from html import escape

from ..security.crypto import aes_encrypt, xor_encrypt
from .constructor import ConstructorRenderResult, render_constructor
from .policy import SafeSmuggleBuilderConfig, resolve_download_filename


@dataclass(frozen=True, slots=True)
class SmuggleArtifact:
    """Generated artifact and the effective canonical builder settings."""

    content: bytes
    extension: str
    output_format: str
    download_name: str
    payload_encoding: str
    trigger_method: str
    trigger_event: str
    trigger_event_custom: bool
    download_variant: str
    page_template: str
    mime_type: str
    null_byte: bool
    encrypted: bool
    encryption: str
    password: str | None
    password_captcha: str | None
    effective_mode: str
    effective_preset: str
    notice_shown: bool
    locale: str
    download_name_applied: bool


@dataclass(frozen=True, slots=True)
class SimpleRenderResult:
    content: bytes
    download_name: str


def render_artifact(
    file_data: bytes,
    filename: str,
    builder: SafeSmuggleBuilderConfig,
    *,
    password: str | None = None,
    password_captcha: str | None = None,
) -> SmuggleArtifact:
    """Render either explicit simple or explicit constructor mode."""
    if builder.mode == "constructor":
        result = render_constructor(
            file_data,
            filename,
            builder,
            password=password,
            password_captcha=password_captcha,
        )
        return SmuggleArtifact(
            content=result.content,
            extension=result.extension,
            output_format=result.output_format,
            download_name=result.download_name,
            payload_encoding=result.payload_encoding,
            trigger_method=result.trigger_method,
            trigger_event=result.trigger_event,
            trigger_event_custom=result.trigger_event_custom,
            download_variant=result.download_variant,
            page_template=result.page_template,
            mime_type=result.mime_type,
            null_byte=result.null_byte,
            encrypted=builder.encryption != "none",
            encryption=builder.encryption,
            password=password,
            password_captcha=password_captcha,
            effective_mode="constructor",
            effective_preset=builder.preset,
            notice_shown=builder.show_notice,
            locale=builder.locale,
            download_name_applied=result.download_name_applied,
        )

    if builder.mode != "simple":
        raise ValueError(f"Unsupported SMUGGLE mode: {builder.mode}")
    if builder.encryption == "none" and password is not None:
        raise ValueError("SMUGGLE encryption=none cannot carry a password")
    if builder.encryption != "none" and not password:
        raise ValueError(f"SMUGGLE encryption={builder.encryption} requires a password")

    download_name = resolve_download_filename(
        source_filename=filename,
        download_name=builder.download_name,
        download_ext=builder.download_ext,
    )
    protected = _protect(file_data, builder.encryption, password)
    content = _render_simple_html(
        protected,
        download_name,
        builder,
        password_captcha=password_captcha,
    ).encode("utf-8")
    return SmuggleArtifact(
        content=content,
        extension=".html",
        output_format="html",
        download_name=download_name,
        payload_encoding="base64",
        trigger_method="svg",
        trigger_event="onload",
        trigger_event_custom=False,
        download_variant="blob-anchor",
        page_template="default",
        mime_type="application/octet-stream",
        null_byte=False,
        encrypted=builder.encryption != "none",
        encryption=builder.encryption,
        password=password,
        password_captcha=password_captcha,
        effective_mode="simple",
        effective_preset=builder.preset,
        notice_shown=builder.show_notice,
        locale=builder.locale,
        download_name_applied=True,
    )


def _protect(data: bytes, encryption: str, password: str | None) -> bytes:
    if encryption == "none":
        return data
    assert password is not None
    if encryption == "xor":
        return xor_encrypt(data, password)
    if encryption == "aes":
        return aes_encrypt(data, password)
    raise ValueError(f"Unsupported SMUGGLE encryption: {encryption}")


def _render_simple_html(
    protected: bytes,
    filename: str,
    builder: SafeSmuggleBuilderConfig,
    *,
    password_captcha: str | None,
) -> str:
    encrypted = builder.encryption != "none"
    copy = _copy(builder.locale, encrypted=encrypted)
    title = escape(builder.title or copy["title"], quote=True)
    message = escape(builder.message or copy["message"], quote=True)
    cta = escape(builder.cta_label or copy["cta"], quote=True)
    safe_filename = escape(filename, quote=True)
    notice = (
        f'<p class="notice">{escape(copy["notice"], quote=True)}</p>' if builder.show_notice else ""
    )
    captcha = ""
    if password_captcha:
        captcha = (
            f'<img class="captcha" alt="{escape(copy["password"], quote=True)}" '
            f'src="{escape(password_captcha, quote=True)}">'
        )

    countdown = ""
    if builder.preset == "card_auto":
        countdown = (
            '<p class="countdown">'
            f"{escape(copy['countdown'], quote=True)} "
            '<span id="smuggleCountdown"></span>'
            f"{escape(copy['seconds'], quote=True)}</p>"
        )

    if encrypted:
        action = (
            f'<input id="smugglePassword" type="password" autocomplete="off" '
            f'placeholder="{escape(copy["password"], quote=True)}">'
            f'<button type="button" id="downloadBtn">{cta}</button>'
            f'<p id="smuggleStatus">{escape(copy["enter_password"], quote=True)}</p>'
        )
    elif builder.preset == "card_manual":
        action = f'<button type="button" id="downloadBtn">{cta}</button><p id="smuggleStatus"></p>'
    else:
        action = f'<p id="smuggleStatus">{escape(copy["preparing"], quote=True)}</p>'

    payload_b64 = base64.b64encode(protected).decode("ascii")
    script = _simple_script(
        payload_b64,
        filename,
        builder.encryption,
        builder.delay_ms
        if builder.preset == "card_auto"
        else (500 if builder.preset == "direct" else 0),
        builder.preset in {"direct", "card_auto"},
        copy,
    )
    return f"""<!DOCTYPE html>
<html lang="{escape(builder.locale, quote=True)}">
<head>
<meta charset="UTF-8">
<meta name="xferry-smuggle-encryption" content="{escape(builder.encryption, quote=True)}">
<title>{title}</title>
<style>
body{{font-family:Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
.shell{{max-width:640px;margin:40px auto;padding:24px}}
.card{{background:#111827;border:1px solid #334155;border-radius:16px;padding:24px;box-shadow:0 18px 45px rgba(15,23,42,.35)}}
.badge{{display:inline-block;margin:0 0 12px;padding:6px 10px;border-radius:999px;background:#1d4ed8;color:#eff6ff;font-size:.78rem;font-weight:bold;letter-spacing:.04em;text-transform:uppercase}}
.notice{{margin:0 0 16px;padding:12px 14px;border-radius:12px;background:#1e293b;color:#bfdbfe}}
h1{{margin:0 0 8px;color:#f8fafc;font-size:1.35rem}}
.message{{margin:0 0 16px;color:#cbd5e1;line-height:1.6}}
.file{{margin:0 0 16px;color:#94a3b8}}.file strong{{color:#f8fafc}}
input{{width:100%;padding:12px;margin:10px 0;border:1px solid #475569;border-radius:12px;box-sizing:border-box;background:#020617;color:#fff;font-size:1rem}}
button{{width:100%;padding:12px;background:#38bdf8;color:#082f49;border:none;border-radius:12px;cursor:pointer;font-size:1rem;font-weight:bold}}
.status{{color:#93c5fd;min-height:1.2em}}.captcha{{max-width:100%;height:auto;border-radius:4px;margin:.5rem 0}}
</style>
</head>
<body>
<div class="shell"><div class="card">
<p class="badge">{escape(copy["badge"], quote=True)}</p>
{notice}
<h1>{title}</h1><p class="message">{message}</p>
<p class="file">{escape(copy["file"], quote=True)} <strong>{safe_filename}</strong></p>
    {captcha}{countdown}{action}
</div></div>
<script>{script}</script>
</body>
</html>"""


def _simple_script(
    payload_b64: str,
    filename: str,
    encryption: str,
    delay_ms: int,
    auto_start: bool,
    copy: dict[str, str],
) -> str:
    payload = _script_json(payload_b64)
    name = _script_json(filename)
    text = {key: _script_json(value) for key, value in copy.items()}
    if encryption == "none":
        decode = """
var raw=atob(payload),bytes=new Uint8Array(raw.length);
for(var i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
"""
    elif encryption == "xor":
        decode = """
var raw=atob(payload),wire=new Uint8Array(raw.length);
for(var i=0;i<raw.length;i++)wire[i]=raw.charCodeAt(i);
if(!crypto||!crypto.subtle)throw new Error('WebCrypto is unavailable');
var digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(password)));
var bytes=new Uint8Array(wire.length);
for(var i=0;i<wire.length;i++)bytes[i]=wire[i]^digest[i%digest.length];
"""
    else:
        decode = """
var raw=atob(payload),wire=new Uint8Array(raw.length);
for(var i=0;i<raw.length;i++)wire[i]=raw.charCodeAt(i);
if(!crypto||!crypto.subtle)throw new Error('WebCrypto AES-GCM is unavailable');
if(wire.length<45||wire[0]!==1)throw new Error('Invalid AES artifact');
var salt=wire.slice(1,17),nonce=wire.slice(17,29),cipher=wire.slice(29);
var material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
var aesKey=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:salt,iterations:600000},material,{name:'AES-GCM',length:256},false,['decrypt']);
var bytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,tagLength:128},aesKey,cipher));
"""
    return f"""
'use strict';
var payload={payload},filename={name},encryption={_script_json(encryption)};
var busy=false;
async function startDownload(){{
if(busy)return;
var input=document.getElementById('smugglePassword');
var status=document.getElementById('smuggleStatus');
var password=input?input.value:'';
if(encryption!=='none'&&!password){{if(status)status.textContent={text["enter_password"]};return;}}
busy=true;
try{{
{decode}
var blob=new Blob([bytes],{{type:'application/octet-stream'}});
var url=window.URL.createObjectURL(blob),el=document.createElement('a');
el.href=url;el.download=filename;document.body.appendChild(el);el.click();el.remove();
window.URL.revokeObjectURL(url);
if(status)status.textContent={text["downloaded"]}+filename;
}}catch(error){{if(status)status.textContent={text["error"]}+String(error&&error.message||error);busy=false;}}
}}
var button=document.getElementById('downloadBtn');
if(button)button.addEventListener('click',startDownload,{{once:encryption==='none'}});
var countdownTarget=document.getElementById('smuggleCountdown');
var countdownStart=Date.now(),countdownDuration={str(delay_ms)};
function updateCountdown(){{
if(!countdownTarget)return;
var remaining=Math.max(0,countdownDuration-(Date.now()-countdownStart));
countdownTarget.textContent=(remaining/1000).toFixed(1);
if(remaining>0)window.requestAnimationFrame(updateCountdown);
}}
if(countdownTarget)updateCountdown();
if(encryption==='none'&&{str(auto_start).lower()})setTimeout(startDownload,{str(delay_ms)});
"""


def _copy(locale: str, *, encrypted: bool) -> dict[str, str]:
    if locale == "ru":
        return {
            "badge": "Тестовый артефакт",
            "title": "Защищенный тестовый артефакт" if encrypted else "Тестовый артефакт готов",
            "message": (
                "Введите проверочный пароль, чтобы скачать внутренний контролируемый тестовый файл."
                if encrypted
                else "Внутренний контролируемый тестовый файл"
            ),
            "cta": "Скачать тестовый артефакт",
            "notice": "Внутренняя контролируемая тестовая страница.",
            "file": "Имя файла:",
            "password": "Пароль:",
            "enter_password": "Введите пароль",
            "preparing": "Подготовка загрузки...",
            "downloaded": "Скачано: ",
            "error": "Ошибка: ",
            "countdown": "Автозагрузка через",
            "seconds": "с.",
        }
    return {
        "badge": "Test artifact",
        "title": "Protected test artifact" if encrypted else "Test artifact ready",
        "message": (
            "Enter the verification password to download the internal controlled test file."
            if encrypted
            else "Internal controlled test file"
        ),
        "cta": "Download test artifact",
        "notice": "Internal controlled test page.",
        "file": "Download name:",
        "password": "Password:",
        "enter_password": "Enter a password",
        "preparing": "Preparing download...",
        "downloaded": "Downloaded: ",
        "error": "Error: ",
        "countdown": "Automatic download in",
        "seconds": "s.",
    }


def _script_json(value: str) -> str:
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


__all__ = [
    "ConstructorRenderResult",
    "SimpleRenderResult",
    "SmuggleArtifact",
    "render_artifact",
]
