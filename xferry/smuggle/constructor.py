"""Canonical constructor-mode SMUGGLE renderer.

The constructor consumes a validated SafeSmuggleBuilderConfig; it never
decides whether constructor mode should be selected. That decision is made by
request.py and is visible in the public request contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape

from ..security.crypto import aes_encrypt, xor_encrypt

# Reuse the low-level fixed template/variant catalogue as rendering
# primitives. All options have already been selected by the canonical policy.
from ._constructor_primitives import (
    _constructor_default_copy,
    _constructor_download_js,
    _convert_constructor_format,
    _encode_constructor_payload,
    _render_constructor_template,
    _render_custom_constructor_trigger,
    _resolve_constructor_trigger,
)
from .policy import SafeSmuggleBuilderConfig, resolve_download_filename


@dataclass(frozen=True, slots=True)
class ConstructorRenderResult:
    """Rendered constructor bytes and effective browser metadata."""

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
    download_name_applied: bool


def render_constructor(
    file_data: bytes,
    filename: str,
    builder: SafeSmuggleBuilderConfig,
    *,
    password: str | None = None,
    password_captcha: str | None = None,
) -> ConstructorRenderResult:
    """Render a validated constructor request.

    XOR is the named compatibility obfuscation mode and AES is the canonical
    AES-256-GCM wire format. Both are supported in constructor mode; neither
    silently falls back to another algorithm.
    """
    if builder.mode != "constructor":
        raise ValueError("Constructor renderer requires mode=constructor")
    if builder.encryption == "none" and password is not None:
        raise ValueError("SMUGGLE encryption=none cannot carry a password")
    if builder.encryption != "none" and not password:
        raise ValueError(f"SMUGGLE encryption={builder.encryption} requires a password")

    download_name = resolve_download_filename(
        source_filename=filename,
        download_name=builder.download_name,
        download_ext=builder.download_ext,
    )
    payload = _protect(file_data, builder.encryption, password)
    decode_js, encoding_markup = _encode_constructor_payload(payload, builder.payload_encoding)

    trigger_method, trigger_event, trigger_custom, body_attrs, trigger_template = (
        _resolve_constructor_trigger(builder.trigger_method, builder.trigger_event)
    )
    default_copy = _constructor_default_copy(builder.locale)
    download_js = _constructor_download_js(
        builder.download_variant,
        builder.mime_type,
        download_name,
    )

    if builder.encryption == "none":
        executable_js = decode_js + download_js
        extra_markup = encoding_markup
    else:
        # Decode the protected wire first, then decrypt in the browser. A
        # visible gate keeps auto-fired triggers from guessing a password.
        executable_js = _encrypted_start_script(
            decode_js,
            builder.encryption,
            download_js,
        )
        extra_markup = encoding_markup + _password_gate_markup(
            password_captcha,
            builder.locale,
        )

    event_js = "void __xferryStart();" if builder.encryption != "none" else executable_js
    if trigger_custom:
        body_attrs = ""
        trigger_element = _render_custom_constructor_trigger(
            trigger_method,
            trigger_event,
            event_js,
        )
    else:
        attribute_js = escape(event_js, quote=True)
        body_attrs = body_attrs.format(js=attribute_js) if body_attrs else ""
        trigger_element = trigger_template.format(js=attribute_js) if trigger_template else ""

    # The encrypted start function must be defined before an event can fire.
    if builder.encryption != "none":
        extra_markup += f"<script>{executable_js}</script>"

    html = _render_constructor_template(
        template_name=builder.page_template,
        title=builder.title or default_copy["title"],
        message=builder.message or default_copy["message"],
        download_name=download_name,
        body_attrs=body_attrs,
        extra_html=extra_markup,
        trigger_element=trigger_element,
        show_notice=builder.show_notice,
        locale=builder.locale,
    )
    content = _convert_constructor_format(html, builder.output_format)
    if builder.null_byte:
        content = b"\x00" + content

    return ConstructorRenderResult(
        content=content,
        extension=f".{builder.output_format}",
        output_format=builder.output_format,
        download_name=download_name,
        payload_encoding=builder.payload_encoding,
        trigger_method=trigger_method,
        trigger_event=trigger_event,
        trigger_event_custom=trigger_custom,
        download_variant=builder.download_variant,
        page_template=builder.page_template,
        mime_type=builder.mime_type,
        null_byte=builder.null_byte,
        download_name_applied=builder.download_variant != "loc-assign",
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


def _password_gate_markup(captcha: str | None, locale: str) -> str:
    if locale == "ru":
        label, placeholder, button, status = "Пароль", "Пароль", "Скачать", "Введите пароль"
    else:
        label, placeholder, button, status = "Password", "Password", "Download", "Enter a password"
    captcha_markup = ""
    if captcha:
        captcha_markup = (
            f'<img alt="{escape(label, quote=True)}" '
            f'src="{escape(captcha, quote=True)}" style="max-width:100%">'
        )
    return (
        '<div id="smugglePasswordGate" style="display:grid;gap:.5rem;max-width:24rem;'
        'margin:1rem auto;padding:1rem;border:1px solid #ccd6e0;border-radius:.5rem">'
        f'{captcha_markup}<label for="smugglePassword">{escape(label)}</label>'
        f'<input id="smugglePassword" type="password" autocomplete="off" '
        f'placeholder="{escape(placeholder, quote=True)}">'
        f'<button type="button" onclick="void __xferryStart()">{escape(button)}</button>'
        f'<output id="smugglePasswordStatus">{escape(status)}</output></div>'
    )


def _encrypted_start_script(decode_js: str, encryption: str, download_js: str) -> str:
    """Build an async browser decrypt-and-download function."""
    if encryption == "xor":
        decrypt_body = (
            "var digest=new Uint8Array(await crypto.subtle.digest('SHA-256',"
            "new TextEncoder().encode(password))),out=new Uint8Array(a.length);"
            "for(var j=0;j<a.length;j++)out[j]=a[j]^digest[j%digest.length];a=out;"
        )
    else:
        decrypt_body = """
var wire=a;
if(wire.length<45||wire[0]!==1)throw new Error('Invalid AES artifact');
var salt=wire.slice(1,17),nonce=wire.slice(17,29),cipher=wire.slice(29);
var material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),
 'PBKDF2',false,['deriveKey']);
var key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:salt,iterations:600000},
 material,{name:'AES-GCM',length:256},false,['decrypt']);
a=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,tagLength:128},key,cipher));
"""
    return f"""
var __xferryBusy=false;
async function __xferryStart(){{
if(__xferryBusy)return;
var input=document.getElementById('smugglePassword');
var status=document.getElementById('smugglePasswordStatus');
var password=input?input.value:'';
if(!password){{if(status)status.textContent='Enter a password';return;}}
__xferryBusy=true;
try{{
if(!crypto||!crypto.subtle)throw new Error('WebCrypto is unavailable');
{decode_js}
{decrypt_body}
{download_js}
if(status)status.textContent='Download started';
}}catch(error){{if(status)status.textContent=String(error&&error.message||error);__xferryBusy=false;}}
}}
"""


__all__ = ["ConstructorRenderResult", "render_constructor"]
