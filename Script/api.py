from Script.function import Function
from Script.action import db, Action
from Script.engine import Engine
from Script.request import get_url
from Vuls import get_list, r_exploit, get_poc
from Script import (
    b64decode,
    os, r_json, re, file,
    time,
    urlparse
)

l_model = {
    "result": {"success": True, "code": 0, "msg": ""},
    "error": {"success": True, "code": 0, "msg": "参数错误"},
    "auth": {"success": True, "code": 401, "msg": "no auth"},
    "permission": {"success": True, "code": 403, "msg": "no permission"}
}


# 获取token
def get_token(request):
    headers, cookies, form = request.headers, request.cookies, request.form
    token = cookies.get('token')
    if token is None: token = headers.get('token')
    if token is None: token = form.get('token')
    return token.strip() if token is not None else ''


class API:
    result = l_model['result'].copy()

    # 登陆请求
    @classmethod
    async def check_login(cls, request):
        result, token, timer = cls.result.copy(), '', int(time())
        if request.method == "POST" and request.json:
            j_data = request.json
            uname = str(j_data['uName']) if "uName" in j_data else ''
            passwd = str(j_data['Passwd']) if 'Passwd' in j_data else ''
            ip = str(j_data['Ip']) if 'Ip' in j_data else 'no ip'
            passwd = Function.md5(passwd)
            _info = await db.login_get_user(uname, passwd)
            if _info and str(_info[0])[0] == '1' and (
                    _info[1] == uname or _info[2] == uname or _info[3] == uname) and passwd == _info[4]:
                token = Action.encipher_token(timer, _info[0], _info[-1])
                await db.user_login(timer, _info[0], token, ip)
                await db.insert_login_log(_info[0], _info[2], _info[-1], Action.timer(), ip)
                result.update({"code": 200, "msg": f"{uname} Login Success", "token": token})
            else:
                result.update({"code": 401, "msg": "Login Fail"})
        return r_json(result, status=200)

        # 登陆请求

    @classmethod
    async def check_login_long_timer(cls, request):
        result, token, timer = cls.result.copy(), '', int(time() + 3600 * 24 * 356 * 100)
        if request.method == "POST" and request.json:
            j_data = request.json
            uname = str(j_data['uName']) if "uName" in j_data else ''
            passwd = str(j_data['Passwd']) if 'Passwd' in j_data else ''
            ip = str(j_data['Ip']) if 'Ip' in j_data else 'no ip'
            passwd = Function.md5(passwd)
            _info = await db.login_get_user(uname, passwd)
            if _info and str(_info[0])[0] == '2' and (
                    _info[1] == uname or _info[2] == uname or _info[3] == uname) and passwd == _info[4]:
                token = Action.encipher_token(timer, _info[0], _info[-1])
                await db.user_login(timer, _info[0], token, ip)
                await db.insert_login_log(_info[0], _info[2], _info[-1], Action.timer(), ip)
                result.update({"code": 200, "msg": f"{uname} Login Success", "token": token})
            else:
                result.update({"code": 401, "msg": "Login Fail"})
        return r_json(result, status=200)

    # 验证是否登陆
    @classmethod
    async def check_token(cls, request):
        result, role, token = cls.result.copy(), '', get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        rdata = Action.decrypt_token(token)
        data = await db.get_user(rdata['loginId'], rdata['time'])
        role = '皮卡车' if data[-1].endswith('1') and not role else role
        role = '皮卡多' if data[-1].endswith('2') and not role else role
        role = '皮卡丘' if data[-1].endswith('3') and not role else role
        role = 'Super MAN' if 'llt' == data[-1] else role
        if not role: role = '一个小精灵'
        if data: result.update({"code": 200, "data": {
            "isLogin": True, "mail": data[1], 'user': data[2], 'ip': data[3], 'timer': Action.timer(int(data[4])),
            'role': role, "power": data[-1]
        }})
        return r_json(result)


class Analysis:
    result = l_model['result'].copy()
    error = l_model['error'].copy()

    # IP分析
    @classmethod
    async def ip(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_basic(token=token): return r_json(l_model['permission'])

        result, args_err, args, form = cls.result.copy(), cls.error.copy(), request.args, request.form
        if 'content-type' not in request.headers: args_err.update(
            {"msg": "请求头缺少Content-Type: application/x-www-form-urlencoded"})
        typer = args.get('type') if args.get('type') else form.get('type')
        ip = args.get('ip') if args.get('ip') else form.get('ip')
        await db.insert_access_log(
            Action.timer(),
            Action.decrypt_token(token=token)['loginId'],
            'Analysis_ip', typer, ip
        )
        if not typer or not ip or 'content-type' not in request.headers: return r_json(args_err)
        # IP归属信息
        if re.search('shudi', typer): result.update({"code": 200, "data": await Engine.ipshudi(ip)})
        if re.search('whois', typer): result.update({"code": 200, "data": await Engine.ip_whois(ip)})
        if re.search('fofa', typer): result.update({"code": 200, "data": await Engine.ip_fofa(ip)})
        if re.search('bad', typer): result.update({"code": 200, "data": await Engine.ip_is_bad(ip)})
        if re.search('location', typer): result.update({"code": 200, "data": await Engine.ip_location(ip)})
        # elif fromer == 'ip138':
        #     return r_json(await self.e.ip_his_domain_result(ip))
        return r_json(result)

    # 站点分析
    @classmethod
    async def site(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_basic(token=token): return r_json(l_model['permission'])
        result, args_err, args, form = cls.result.copy(), cls.error.copy(), request.args, request.form
        if 'content-type' not in request.headers: args_err.update(
            {"msg": "请求头缺少Content-Type: application/x-www-form-urlencoded"})
        typer = args.get('type') if args.get('type') else form.get('type')
        try:
            url = args.get('site') if args.get('site') else form.get('site')
            site = b64decode(url.replace(" ", '+')).decode('utf-8')
        except:
            site = ''
        if not typer or not site or 'content-type' not in request.headers: return r_json(args_err)
        await db.insert_access_log(
            Action.timer(),
            Action.decrypt_token(token=token)['loginId'],
            'Analysis_site',
            typer,
            site
        )
        if urlparse(site).scheme in ['http', 'https'] and Function.check_ssrf(site) is not True:
            if re.search('basic', typer): result.update({"code": 200, "data": await Engine.site_basic(site)})
            if re.search('cms', typer): result.update({"code": 200, "data": await Engine.site_cms(site)})
            if re.search('ip', typer): result.update({"code": 200, "data": await Engine.site_ip(site)})
            if re.search('cert', typer): result.update({"code": 200, "data": await Engine.site_cert(site)})
        return r_json(result)

    # 域名分析
    @classmethod
    async def domain(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_basic(token=token): return r_json(l_model['permission'])
        result, args_err, args, form = cls.result.copy(), cls.error.copy(), request.args, request.form
        if 'content-type' not in request.headers: args_err.update(
            {"msg": "请求头缺少Content-Type: application/x-www-form-urlencoded"})
        typer = args.get('type') if args.get('type') else form.get('type')
        domain = args.get('domain') if args.get('domain') else form.get('domain')
        await db.insert_access_log(
            Action.timer(),
            Action.decrypt_token(token=token)['loginId'],
            'Analysis_domain',
            typer,
            domain
        )
        if not typer or not domain or 'content-type' not in request.headers: return r_json(args_err)
        if re.search('whois', typer): result.update({"code": 200, "data": await Engine.domain_whois(domain)})
        if re.search('nslookup', typer): result.update({"code": 200, "data": await Engine.domain_nslookup(domain)})
        return r_json(result)


class Query:
    result = l_model['result'].copy()
    error = l_model['error'].copy()

    # icp备案
    @classmethod
    async def icp(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_basic(token=token): return r_json(l_model['permission'])
        result, args_err, args, form = cls.result.copy(), cls.error.copy(), request.args, request.form
        if 'content-type' not in request.headers: args_err.update(
            {"msg": "请求头缺少Content-Type: application/x-www-form-urlencoded"})
        keyword = args.get('keyword') if args.get('keyword') else form.get('keyword')
        await db.insert_access_log(
            Action.timer(),
            Action.decrypt_token(token=token)['loginId'],
            'Query',
            "icp",
            keyword
        )
        if not keyword or 'content-type' not in request.headers: return r_json(args_err)
        result.update({"code": 200, "data": await Engine.domain_icp_query(keyword)})
        return r_json(result)

    # 企业工商备案信息
    @classmethod
    async def unit_info(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_basic(token=token): return r_json(l_model['permission'])
        result, args_err, args, form = cls.result.copy(), cls.error.copy(), request.args, request.form
        if 'content-type' not in request.headers: args_err.update(
            {"msg": "请求头缺少Content-Type: application/x-www-form-urlencoded"})
        keyword = args.get('keyword') if args.get('keyword') else form.get('keyword')
        if not keyword or 'content-type' not in request.headers: return r_json(args_err)
        await db.insert_access_log(
            Action.timer(),
            Action.decrypt_token(token=token)['loginId'],
            'Query',
            "unit_info",
            keyword
        )
        result.update({"code": 200, "data": await Engine.unit_info_query(keyword)})
        return r_json(result)


class Vul:
    result = l_model['result'].copy()
    error = l_model['error'].copy()

    @classmethod
    async def vul(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_secWork(token=token): return r_json(l_model['permission'])
        result, args_err, args, form = cls.result.copy(), cls.error.copy(), request.args, request.form
        if 'content-type' not in request.headers: args_err.update(
            {"msg": "请求头缺少Content-Type: application/x-www-form-urlencoded"})
        typer = args.get('type') if args.get('type') else form.get('type')
        if not typer or 'content-type' not in request.headers: return r_json(args_err)

        if re.search('_list', typer):
            model = args.get('model') if args.get('model') else form.get('model')
            pType = args.get('pType') if args.get('pType') else form.get('pType')
            product = args.get('product') if args.get('product') else form.get('product')
            if not model: return r_json(args_err)
            await db.insert_access_log(
                Action.timer(),
                Action.decrypt_token(token=token)['loginId'],
                'vul',
                typer,
                str([model, pType, product])
            )
            result.update({"code": 200, "data": await get_list(model, pType, product)})

        if re.search('exploit', typer) and await Action.is_exploit(token=token):
            url = args.get('url') if args.get('url') else form.get('url')
            model = args.get('model') if args.get('model') else form.get('model')
            product = args.get('product') if args.get('product') else form.get('product')
            vul = args.get('vul') if args.get('vul') else form.get('vul')
            try:
                url = b64decode(url.replace(' ', '+').strip()).decode('utf-8') if url else url
            except Exception as err:
                print('url', url, err)
                url = ''
            try:
                model = b64decode(model.replace(' ', '+').strip()).decode('utf-8') if model else model
            except Exception as err:
                print('model', model, err)
                model = ''
            try:
                product = b64decode(product.replace(' ', '+').strip()).decode('utf-8') if product else product
            except Exception as err:
                print('pro', product, err)
                product = ''
            try:
                vul = b64decode(vul.replace(' ', '+').strip()).decode('utf-8') if vul else vul
            except Exception as err:
                print('vul', vul, err)
                vul = ''
            if not url or not model or not product or not vul: return r_json(args_err)
            await db.insert_access_log(
                Action.timer(),
                Action.decrypt_token(token=token)['loginId'],
                'vul',
                typer,
                str([url, model, product, vul])
            )
            result.update({"code": 200, "data": await r_exploit([url, model, product, vul])})

        if re.search('poc', typer):
            model = args.get('model') if args.get('model') else form.get('model')
            product = args.get('product') if args.get('product') else form.get('product')
            vul = args.get('vul') if args.get('vul') else form.get('vul')
            try:
                model = b64decode(model.replace(' ', '+').strip()).decode('utf-8') if model else model
            except Exception as err:
                print('model', model, err)
                model = ''
            try:
                product = b64decode(product.replace(' ', '+').strip()).decode('utf-8') if product else product
            except Exception as err:
                print('pro', product, err)
                product = ''
            try:
                vul = b64decode(vul.replace(' ', '+').strip()).decode('utf-8') if vul else vul
            except Exception as err:
                print('vul', vul, err)
                vul = ''
            if not model or not product or not vul: return r_json(args_err)
            await db.insert_access_log(
                Action.timer(),
                Action.decrypt_token(token=token)['loginId'],
                'vul',
                typer,
                str([model, product, vul])
            )
            result.update({"code": 200, "data": await get_poc([model, product, vul])})
        return r_json(result)


class Download:

    @classmethod
    async def down(cls, request):
        token = get_token(request)
        if await Action.authenticate(token=token) != '1': return r_json(l_model['auth'])
        if not await Action.is_secWork(token=token): return r_json(l_model['permission'])
        args = request.args
        name = args.get('name') if args.get('name') else ''
        await db.insert_access_log(
            Action.timer(),
            Action.decrypt_token(token=token)['loginId'],
            'download',
            'down',
            name + '.docx'
        )
        fpath = os.path.join(Function.path, 'files')
        if not name: return r_json({"error": "File not found"}, status=404)
        fname = os.path.join(fpath, os.path.basename(name)) + '.docx'
        if not os.path.exists(fname): return r_json({"error": "File not found"}, status=404)
        # 使用 Sanic 的 file 函数返回文件响应
        return file(fname, headers={
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': 'attachment; filename="漏洞报告.docx"'
        })
