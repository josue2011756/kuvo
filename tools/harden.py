#!/usr/bin/env python3
"""Regenera la politica de seguridad (CSP con hashes) y vercel.json.

Ejecutar SIEMPRE despues de editar index.html y antes de desplegar:
    python3 tools/harden.py

Calcula el hash SHA-256 de cada <script> y <style> en linea, escribe la
etiqueta <meta> de CSP dentro de index.html (sirve tambien para GitHub Pages)
y genera vercel.json con todas las cabeceras de seguridad.
"""
import base64, hashlib, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "index.html")
s = open(HTML, encoding="utf-8").read()

def sha(txt):
    return "'sha256-" + base64.b64encode(hashlib.sha256(txt.encode("utf-8")).digest()).decode() + "'"

# scripts en linea ejecutables (sin src ni type de datos)
scripts = [m.group(1) for m in re.finditer(r"<script(?![^>]*\bsrc=)(?![^>]*type=\"(?:application/ld\+json|importmap)\")[^>]*>(.*?)</script>", s, re.S)]
styles = [m.group(1) for m in re.finditer(r"<style[^>]*>(.*?)</style>", s, re.S)]
script_h = " ".join(sha(t) for t in scripts)
style_h = " ".join(sha(t) for t in styles)

policy = [
    ("default-src", "'self'"),
    ("script-src", "'self' %s https://cdn.jsdelivr.net" % script_h),
    ("style-src", "'self' https://fonts.googleapis.com %s" % style_h),
    ("style-src-elem", "'self' https://fonts.googleapis.com %s" % style_h),
    ("style-src-attr", "'unsafe-inline'"),
    ("font-src", "'self' https://fonts.gstatic.com"),
    ("img-src", "'self' data:"),
    ("connect-src", "'self'"),
    ("media-src", "'none'"),
    ("object-src", "'none'"),
    ("frame-src", "'none'"),
    ("worker-src", "'none'"),
    ("manifest-src", "'self'"),
    ("base-uri", "'none'"),
    ("form-action", "'none'"),
]
meta_csp = "; ".join("%s %s" % kv for kv in policy)
header_csp = meta_csp + "; frame-ancestors 'none'; upgrade-insecure-requests"

# etiqueta <meta> entre marcadores
block = '<!--CSP-START--><meta http-equiv="Content-Security-Policy" content="%s"><!--CSP-END-->' % meta_csp.replace('"', "&quot;")
if "<!--CSP-START-->" in s:
    s = re.sub(r"<!--CSP-START-->.*?<!--CSP-END-->", lambda m: block, s, flags=re.S)
else:
    s = s.replace("<head>", "<head>\n" + block, 1)
open(HTML, "w", encoding="utf-8").write(s)

PERMS = "accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), xr-spatial-tracking=()"
headers = [
    ("Content-Security-Policy", header_csp),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", PERMS),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    ("X-DNS-Prefetch-Control", "off"),
]
cfg = {"headers": [{"source": "/(.*)", "headers": [{"key": k, "value": v} for k, v in headers]}]}
open(os.path.join(ROOT, "vercel.json"), "w", encoding="utf-8").write(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
print("CSP listo: %d script(s) y %d style(s) en linea con hash." % (len(scripts), len(styles)))
