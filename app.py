from Script import Sanic, os, sys
from sanic_ext import Config
from Script.sanic_Compress import Compress
from Script.router import Router
from Script.function import Function

cwd = os.getcwd()
sys.path.append(cwd)
with open(Function.path + 'dir', 'w') as F: F.write(cwd)


class secAPI:
    app = Sanic(name="secAPI", env_prefix='Sec', inspector=True)
    app.extend(config=Config(oas=False))
    Compress(app)  # 将中间件函数注册到Sanic应用

    @classmethod
    def add_custom_headers(cls, request, response):
        response.headers.update({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET,POST",
            "Access-Control-Allow-Headers": "*",
            "SameSite": "Secure",
            "X-Content-Type-Options": "nosniff",
            "X-Dns-Prefetch-Control": "off",
            "X-Download-Options": "noopen",
            "X-Frame-Options": "DENY",
            "X-Permitted-Cross-Domain-Policies": "master-only",
            "X-XSS-Protection": "1;mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        })


app = secAPI.app
app.register_middleware(secAPI.add_custom_headers, 'response')
Router(app)
