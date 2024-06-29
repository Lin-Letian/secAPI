from Script.request import async_get, r_get, r_post
from Script.function import Function
from Config import fofa, quake
from datetime import datetime
from Script.action import db
from Script import (
    create_connection,
    gaierror, gethostbyname,
    resolver as dns, re, random, ssl, tldextract,
    unescape, unquote, urlparse,
    whois
)


class Engine:
    shudi = {"Country": "", "Province": "", "City": "", "County": "", "Operator": "", "lineType": ""}
    icp_model = {
        "SiteName": "", "SiteIndex": "", "natureName": "", "unitName": "", "mainLicence": "", "serviceLicence": "",
        "updateRecordTime": "", "domain": ""
    }
    wangan_model = {
        "unitName": "", "wanganId": "", "domain": "", "unitType": "", "department": "", "webName": "",
        "time": "", "webType": ""
    }
    unit_info_model = {
        "Cname": "", "Ctype": "", "SiteName": "", "SitePrincipal": "", "SiteIndex": "", "ReviewTime": "",
        "person": "", "RegCapital": "", "RegTimer": "", "GsStatus": "", "GsType": "", "GsRegID": "",
        "Industry": "", "taxpayerID": "", "VerifyTime": "", "RegAddr": "", "Operators": ""
    }
    ServerNames = ['阿里云', '腾讯云']
    municipality = ['北京', "天津", "重庆", "上海"]
    ip_remove = []
    ip_day = 0
    ip_hour = 0
    _timeout = 10

    # 获取IP属地信息
    @classmethod
    async def ipshudi(cls, ip: str):
        result = cls.shudi.copy()
        result.update(await db.ip_get_shudi(ip))
        if result['Country']: return result
        # # 当数据库存在时，直接返回数据
        run = sorted([i for i in [cls.ip_shudi, cls.ip_cip_cc, cls.ip_ipdatacloud, cls.ip_qqsuu
                                  ] if i not in cls.ip_remove], key=lambda x: random.random())
        if cls.ip_day != datetime.now().day and cls.ip_hour != datetime.now().hour:
            cls.ip_day = datetime.now().day
            cls.ip_hour = datetime.now().hour
            cls.ip_remove = []
        if not bool(run): return result
        fun = run.pop()
        res = fun(ip)
        if 'ipshudi' in res and 'ips' in res:
            res, ips = res['ipshudi'], res['ips']
            if not res:
                cls.ip_remove.append(fun)
                res = await cls.ipshudi(ip)
            result.update(res)
        if 'Country' not in res or not res['Country']:
            cls.ip_remove.append(fun) if fun is not cls.ip_qqsuu else None
            res = await cls.ipshudi(ip)
        if res['Country']: result.update(res)
        if result['Country']: result = await db.ip_insert_shudi(ip, Function.format_ipshudi(result))
        # run = sorted([cls.ip_api_1], key=lambda x: random.random())
        # for fun in run:
        #     result.update(await fun(ip))
        #     if result['Country']:
        #         await db.ip_insert_shudi(ip, Function.format_ipshudi(result))
        #         return result
        return result

    # ipshudi.com 获取IP信息
    @classmethod
    def ip_shudi(cls, ip: str):
        result, res = cls.shudi.copy(), r_get(url=f"https://www.ipshudi.com/{ip}.htm", timeout=cls._timeout)
        if res is None or res.status_code != 200: return result
        soup = Function.beautifulsoup(res.text, res.content, dict(res.headers))
        div = soup.find('div', class_='ft')
        if not div: return result
        tables = div.find('tbody')
        if not tables: return result
        trs = tables.find_all('tr')
        datas = [i.get_text().lstrip('').replace('\n', '').rstrip(' 上报纠错') for i in trs]
        while datas:
            d = datas.pop()
            if d.startswith('iP地址'): continue
            if d.startswith('归属地'):
                addr = d.lstrip('归属地').split(' ')
                result.update(Function.extract_Addr(d))
                if len(addr) > 0 and not result['Country']: result['Country'] = addr[0]
                if len(addr) > 1 and not result['Province']: result['Province'] = addr[1]
                if len(addr) > 2 and not result['City']: result['City'] = addr[2].rstrip('市')
                if len(addr) > 3 and not result['County']: result['County'] = addr[3]
            if d.startswith('运营商'): result['Operator'] = d.lstrip('运营商')
            if d.startswith('iP类型'): result['lineType'] = d.lstrip('iP类型')
        result['Province'] = result['Province']
        result['City'] = result['City'].rstrip("市")
        return result

    # cip.cc 获取IP信息
    @classmethod
    def ip_cip_cc(cls, ip: str):
        result, res = cls.shudi.copy(), r_get(url=f"http://www.cip.cc/" + ip, timeout=cls._timeout)
        if res is None or res.status_code != 200: return result
        soup = Function.beautifulsoup(res.text, res.content, dict(res.headers))
        div = soup.find('div', class_='data kq-well')
        if not div: return result
        data = [i.replace("\t", '') for i in div.pre.get_text().split('\n') if i][1:-1]
        while data:
            d = data.pop().split(':')
            if d[0] == "地址":
                result.update(Function.extract_Addr(d[1]))
                addr = d[1].lstrip(" ").rstrip(" ").split('  ')
                if addr[-1] in cls.ServerNames: addr.pop()
                if len(addr) > 0:
                    if '省' not in addr[0] and "市" not in addr[0] and not result['Country']:
                        result["Country"] = addr[0].replace(" ", '')  # 判断关键字不存在时为国家
                    elif '省' in addr[0] or addr[0].split("市")[0] in cls.municipality and not result['Province']:
                        result["Province"] = addr[1]  # 判断关键字存在时为省,或者为直辖市
                    elif '市' in addr[0] and not result['City']:
                        result["City"] = addr[-1].replace(" ", '').split("市")[0]  # 判断市关键字存在时为市
                if len(addr) > 1 and addr[0] != addr[1] and not result["Province"]:
                    result["Province"] = addr[1].replace(" ", '').split("州")[0]
                if len(addr) > 2 and not result["City"]: result["City"] = addr[-1].replace(" ", '')
            if d[0] == "运营商" and not result['Operator']: result['Operator'] = d[-1].replace(" ", '')
            if d[0] == "数据二":
                data2 = d[1].replace(" ", '').split('|')
                if len(data2) > 0:
                    if data2[-1] in cls.ServerNames: data2.pop()
                    res = Function.extract_Addr(data2[0])
                    if not result['Country'] and "Country" in res: result['Country'] = res['Country']
                    if not result['Province'] and "Province" in res: result['Province'] = res['Province']
                    if not result['City'] and "City" in res: result['City'] = res['City']
                    if not result['County'] and "County" in res: result['County'] = res['County']
                    if '省' not in data2[0] and "市" not in data2[0] and not result["Country"]:  # 判断关键字不存在时为国家
                        result["Country"] = data2[0].replace(" ", '')
                    if ('省' in data2[0] or data2[0].split("市")[0] in cls.municipality) and not result["Province"]:
                        result["Province"] = data2[0].split("州")[0]
                    if '市' in data2[0] and not result["City"]:
                        result["City"] = data2[0].split('省')[-1].split("市")[0]
                    if ('区' in data2[0] or '县' in data2[0]) and not result["County"]:
                        result["County"] = data2[0].split('市')[-1].replace(" ", '')
                if len(data2) > 1: result["lineType"] = data2[1].lstrip("/")
        result['Province'] = result['Province'].rstrip("州")
        result['City'] = result['City'].rstrip("市")
        return result

    @classmethod
    def ip_ipdatacloud(cls, ip: str):
        result, res = cls.shudi.copy(), r_get(f'https://app.ipdatacloud.com/v2/free_query?ip={ip}',
                                              timeout=cls._timeout)
        if res is None or res.status_code != 200: return result
        try:
            data = res.json()
        except:
            return result
        if data['code'] != 200 or not re.search('province', res.text): return result
        info = data['data']
        result.update({
            "Country": info['country_english'], "Province": info['province'], "City": info['city'],
            'Operator': info['isp']
        })
        return result

    @classmethod
    def ip_qqsuu(cls, ip: str):
        result, res = cls.shudi.copy(), r_get(f'https://api.qqsuu.cn/api/dm-ipquery?ip={ip}', timeout=cls._timeout)
        if res is None or res.status_code != 200: return result
        try:
            data = res.json()
        except:
            return result
        if data['code'] != 200 or data["msg"] != "success": return result
        info = data['data']
        result.update({
            "Country": info['country'], "Province": info['province'], "City": info['city'], "County": info['district'],
            'Operator': info['isp']
        })
        return result

    # 获取IP whois信息
    @classmethod
    async def ip_whois(cls, ip: str):
        sublist, result, rjson = [], [], {}
        sql_r = await db.ip_get_whois(ip)
        if sql_r: return sql_r
        res = await async_get(
            f'https://ipwhois.cnnic.cn/bns/query/Query/ipwhoisQuery.do?txtquery={ip}&queryOption=ipv4')
        if res is None or res.status != 200 and len(await res.text()) > 0: return rjson
        soup = Function.beautifulsoup(await res.text(), res._body, dict(res.headers))
        table = soup.find('table')
        if not table: return rjson
        trs = table.find_all('tr')
        if not trs: return rjson
        while table and trs:
            item = trs.pop().text.replace('\xa0', '').split('\n')[1:-1]
            if item[0] in ['inetnum:', 'netname:', 'descr:', 'status:']:
                if item[0] == 'descr:' and "descr:" != item[1] and 'descr' not in rjson and not re.search("NULL",
                                                                                                          item[1]):
                    rjson.update({item[0].rstrip(':'): item[1]})
                elif not item[0].startswith('descr'):
                    rjson.update({item[0].rstrip(':'): item[1]})
            if item == ['', '']:
                if sublist and sublist[0][0] == 'person:':
                    for i in sublist:
                        if i[0].startswith("person"): rjson.update({"person": i[-1]})
                        if i[0].startswith("phone"): rjson.update({"phone": i[-1]})
                if sublist:
                    result.append(sublist)
                    sublist = []
            else:
                sublist.append(item)
        if sublist: result.append(sublist)
        last_modified = list()
        for r in sorted(result, key=lambda x: x[-2], reverse=True)[0]:
            if 'org-name' in r[0]: rjson.update({r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
            if 'org-type' in r[0]: rjson.update({r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
            if 'country or economy' in r[0]: rjson.update({'country': r[-1]})
            if 'address' in r[0]: rjson.update({r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
            if 'phone' in r[0] and 'phone' not in rjson: rjson.update(
                {r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
            if 'fax-no' in r[0]: rjson.update({r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
            if 'e-mail' in r[0]: rjson.update({r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
            if 'last-modified' in r[0]: last_modified.append(
                f"{r[-1].split('T')[0]} {r[-1].split('T')[1].split('Z')[0]}")
            if 'source' in r[0]: rjson.update({r[0].rstrip(':').replace('-', '_').replace('-', '_'): r[-1]})
        if last_modified: rjson.update({"last-modified": sorted(last_modified, reverse=True)[0]})
        rjson['source'] = rjson['source'] if rjson['source'] != 'APNIC' else "亚太互联网信息中心"
        await db.ip_insert_whois(ip, rjson)
        return rjson

    # 获取FOFA平台IP信息
    @classmethod
    async def ip_fofa(cls, ip: str):
        res, result = await async_get(url=f"{fofa['api']}/api/v1/host/{ip}", header=Function.header(types='json'),
                                      params={"email": fofa['email'], "key": fofa['key'],
                                              "detail": fofa['full']}), dict()
        if res is None or res.status != 200: return result
        return await res.json()

    # 获取是否为恶意IP
    @classmethod
    async def ip_is_bad(cls, ip: str):
        result, res = 0, await async_get(url=f"https://www.bjos.cn/cha_{ip}.html")
        if res is None or res.status != 200: return result
        try:
            soup = Function.beautifulsoup(await res.text(), res._body, dict(res.headers))
            r_data = soup.find('center').get_text().replace('\n', '').split(': ')[-1].split(' ')[0]
            result = int(r_data) if r_data != '无数据' else result
        except Exception as err:
            print(f"\r[{Function.timer()}] ERR::bjos.cn获取IP信息: {err}", ip)
        return result

    # 获取ip的经纬度信息
    @classmethod
    async def ip_location(cls, ip: str):
        result = {}
        sql_r = await db.ip_get_location(ip)
        if sql_r: return sql_r
        res = await async_get(url="https://ipinfo.io/{}/json".format(ip))
        if res is None or not re.search('region', await res.text()): return result
        try:
            res = await res.json()
        except:
            return result
        if 'status' in res: return result
        try:
            result = {"region": res['region'], "city": res['city'], "loc": res['loc'], "org": res['org']}
            await db.ip_insert_location(ip, result)
            return result
        except:
            return result

    # 获取站点基本信息
    @classmethod
    async def site_basic(cls, site: str):
        result = {"title": "", "status": 0, "server": "", 'length': 0, "anlian": [], "domains": [], "ips": [],
                  'sCode': "", "vul": [],
                  'header': "", 'link': '', 'keywords': '', 'description': '', 'emails': []}
        al_rule = await db.site_bad_keywords()
        res = r_get(url=site, header=Function.header(yq=True), allow_redirects=True)
        if res is None: return result
        html = Function.beautifulsoup(res.text, res.content, dict(res.headers))
        text = html.decode()
        if re.search('WAF', text) and re.search('拦截提示', text):
            res = r_get(url=site, allow_redirects=True)
            if res is None: return result
            html = Function.beautifulsoup(res.text, res.content, dict(res.headers))
            text = html.decode()
        result.update({
            "link": str(res.url), "status": str(res.status_code),
            'server': res.headers.get('Server') if res.headers.get('Server') else ''
        })
        try:
            result.update({"length": len(text)}) if res.status_code == 200 else result.update({"length": 0})
        except:
            result.update({"length": 0})
        result['header'] = f'HTTP/1.1 {res.status_code} {res.reason}\n'
        for i in res.headers: result['header'] += f"{i}: {res.headers[i]}\n"
        result['vul'] = await cls.site_vul(site=site, r_headers=res.headers)
        res_text = unescape(html.decode().lower().replace('\n', '').replace(' ', ''))
        result['anlian'] = [i for i in al_rule if re.search(i.lower(), res_text)]
        try:
            result['sCode'] = html.prettify()
        except:
            result['sCode'] = ''
        result['ips'].extend(sorted(list(set([
            i.strip() for i in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', unquote(html.decode())) if
            Function.is_ipv4(i.strip())
        ]))))
        try:
            result['title'] = html.title.string if re.search('<title', html.decode()) else ''
        except:
            result['title'] = ''
        try:
            result['keywords'] = html.find('meta', attrs={"name": "keywords"}).get('content')
        except:
            result['keywords'] = ''
        if re.search('description', result['sCode']) and re.search('meta', result['sCode']):
            temp = html.find('meta', attrs={"name": "description"})
            result['description'] = temp.get('content') if temp else ''
        for link in html.find_all("a", href=True):
            domain = tldextract.extract(link["href"]).registered_domain
            if domain and domain not in result['domains']: result['domains'].append(domain)
            # 正则表达式优化版，匹配<a>标签内不含其他<a>标签的文本
            pattern = r'<a\b[^>]*\bhref=[\'"](?:[^"\'>]+)["\'][^>]*>([^<]+)</a>'
            matches = re.findall(pattern, text, re.IGNORECASE)
            result['domains'].extend([
                i.strip().split('@')[-1] for i in matches if
                len(i.split('.')) > 1 and Function.is_domain(i.strip().split('@')[-1])])
        domains = []
        [domains.append(i) for i in result['domains'] if i not in domains]
        result['domains'] = sorted(domains)
        result['emails'] = sorted(
            list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', html.decode()))))
        result['emails'] = [i for i in result['emails'] if (not i.endswith('.js') and not i.endswith('.css'))]
        return result

    # 分析站点漏洞
    @classmethod
    async def site_vul(cls, site: str, r_headers=None):
        result = list()
        vuls = {
            "Access-Control-Allow-Origin": {
                "name": "跨域资源共享（CORS）漏洞",
                "describe": "CORS跨域资源共享漏洞与JSONP劫持漏洞类似，都是程序员在解决跨域问题中进行了错误的配置。攻击者可以利用Web应用对用户请求数据包的Origin头校验不严格，诱骗受害者访问攻击者制作好的恶意网站，从而跨域获取受害者的敏感数据，包括转账记录、交易记录、个人身份证号信息、订单信息等等。",
                "link": "https://cloud.tencent.com/developer/article/2225047",
                "repair": [
                    "Access-Control-Allow-Origin中指定的来源只能是受信任的站点，避免使用Access-Control-Allow-Origin: *，避免使用Access-Control-Allow-Origin: null，否则攻击者可以伪造来源请求实现跨域资源窃取",
                    "严格校验“Origin”值，校验的正则表达式一定要编写完善，避免出现绕过的情况",
                    "减少“Access-Control-Allow-Methods”所允许的请求方法",
                    "除了正确配置CORS之外，Web服务器还应继续对敏感数据进行保护，例如身份验证和会话管理等"
                ],
                "data": "Access-Control-Allow-Origin:"
            },
            "Set-Cookie": {
                "name": "SameSite 未设置",
                "describe": "为了从源头上解决CSRF（跨站请求伪造）攻击，Google起草了一份草案来改进HTTP协议，那就是为Set-Cookie响应头新增Samesite属性，它用来标明这个 Cookie是个“同站 Cookie”，同站Cookie只能作为第一方Cookie，不能作为第三方Cookie，Samesite 有两个属性值，分别是 Strict 、Lax和None",
                "link": "https://blog.csdn.net/qq_61812944/article/details/131852706",
                "repair": ["在Cookie中增加并正确设置SameSite"], "risk": "1",
                "data": r_headers['Set-Cookie'] if 'Set-Cookie' in r_headers else ''
            },
            "X-Content-Type-Options": {
                "name": "HTTP X-Content-Type-Options 缺失",
                "describe": "Web 服务器对于 HTTP 请求的响应头缺少 X-Content-Type-Options，这意味着此网站更易遭受跨站脚本攻击（XSS）。X-Content-Type-Options 响应头相当于一个提示标志，被服务器用来提示客户端一定要遵循在 Content-Type 首部中对 MIME 类型 的设定，而不能对其进行修改，这就禁用了客户端的 MIME 类型嗅探行为。浏览器通常会根据响应头 Content-Type 字段来分辨资源类型，有些资源的 Content-Type 是错的或者未定义，这时浏览器会启用 MIME-sniffing 来猜测该资源的类型并解析执行内容。利用这个特性，攻击者可以让原本应该解析为图片的请求被解析为 JavaScript 代码",
                "link": "https://cloud.tencent.com/developer/article/2182642",
                "repair": ["修改网站配置文件，推荐在所有传出请求上发送值为 nosniff 的 X-Content-Type-Options 响应头"],
                "data": r_headers["X-Content-Type-Options"] if "X-Content-Type-Options" in r_headers else "",
                "risk": "1"
            },
            "X-Dns-Prefetch-Control": {
                "name": "可利用DNS预读取技术绕过CSP(X-Dns-Prefetch-Control)",
                "describe": "X-Dns-Prefetch-Control 是一个 HTTP 响应头，它控制着浏览器的 DNS 预读取功能。DNS 预读取是一项使浏览器主动去执行域名解析的功能，其范围包括文档的所有链接，无论是图片、CSS、还是 JavaScript 等其他用户能够点击的 URL，这个功能可以减少用户点击链接时的延迟。如果 X-Dns-Prefetch-Control 缺失或设置不当，可能会带来潜在的风险",
                "link": "https://blog.csdn.net/linjingyg/article/details/122666205",
                "repair": ["建议在所有传出请求上发送值为 off 的 X-Dns-Prefetch-Control 响应头"],
                "data": r_headers['X-Dns-Prefetch-Control'] if 'X-Dns-Prefetch-Control' in r_headers else '',
                "risk": "1"
            },
            "X-Download-Options": {
                "name": "X-Download-Options 缺失",
                "describe": "web浏览器在响应头中缺少 X-Download-Options，这将导致浏览器提供的安全特性失效，更容易遭受 Web 前端黑客攻击的影响",
                "link": "https://tech.powereasy.net/cpzsk/siteazurecjwt/content_23702",
                "repair": ['添加header内容 X-Download-Options "noopen"'],
                "data": "", "risk": "1"
            },
            "X-Frame-Options": {
                "name": "点劫持漏洞(X-Frame-Options)",
                "describe": "返回的响应头信息中没有包含x-frame-options头信息设置，点击劫持(ClickJacking)允许攻击者使用一个透明的iframe，覆盖在一个网页上，然后诱使用户在该页面上进行操作，此时用户将在不知情的情况下点击透明的iframe页面",
                "link": "https://cloud.tencent.com/developer/article/1541698",
                "repair": ["在所有页面上发送 X-Frame-Options 响应头"],
                "data": "",
                "risk": "1"
            },
            "X-Permitted-Cross-Domain-Policies": {
                "name": "HTTP X-Permitted-Cross-Domain-Policies 响应头缺失",
                "describe": "系统响应头缺少X-Permitted-Cross-Domain-Policies，将会导致浏览器的安全特性失效",
                "link": "https://blog.csdn.net/liwan09/article/details/130248003",
                "repair": ["在服务器响应头中添加 X-Permitted-Cross-Domain-Policies"],
                "data": "", "risk": "1"
            },
            "X-Powered-By": {
                "name": "X-Powered-By信息泄露",
                "describe": "返回的响应头信息中暴露了具体的容器版本，攻击者可针对中间件的特性进行利用",
                "link": "https://www.jianshu.com/p/505b391bd022",
                "repair": ["修改配置文件，取消响应包的X-Powered-By头字段"],
                "data": r_headers['X-Powered-By'] if 'X-Powered-By' in r_headers else '', "risk": "1"
            },
            "X-XSS-Protection": {
                "name": "缺少“X-XSS-Protection“头",
                "describe": "X-XSS-Protection 是一个 HTTP 响应头，它用来防止浏览器中的反射性 XSS。现在，只有 IE，Chrome 和 Safari（WebKit）支持这个响应头",
                "link": "https://blog.csdn.net/qq_33468857/article/details/131051643",
                "repair": ["添加响应头 X-XSS-Protection 并正确配置"],
                "data": "", "risk": "1"
            }
        }
        if 'Access-Control-Allow-Origin' in r_headers:
            vul = vuls["Access-Control-Allow-Origin"]
            vul['data'] += r_headers['Access-Control-Allow-Origin']
            if r_headers['Access-Control-Allow-Origin'] == '*':
                vul.update({"risk": "1"})
            elif r_headers['Access-Control-Allow-Origin'] == 'null':
                vul.update({"risk": "3"})
            result.append(vul)
        if 'Set-Cookie' in r_headers and 'SameSite=None' in r_headers['Set-Cookie']: result.append(vuls["Set-Cookie"])
        if "X-Content-Type-Options" not in r_headers or r_headers['X-Content-Type-Options'].rstrip(';') != 'nosniff':
            result.append(vuls["X-Content-Type-Options"])
        if site.startswith('http:') and (
                "X-Dns-Prefetch-Control" not in r_headers or r_headers["X-Dns-Prefetch-Control"] != "off"):
            result.append(vuls['X-Dns-Prefetch-Control'])
        if "X-Download-Options" not in r_headers: result.append(vuls['X-Download-Options'])
        if "X-Frame-Options" not in r_headers: result.append(vuls['X-Frame-Options'])
        if "X-Permitted-Cross-Domain-Policies" not in r_headers: result.append(
            vuls['X-Permitted-Cross-Domain-Policies'])
        if "X-Powered-By" in r_headers and r_headers['X-Powered-By']: result.append(vuls['X-Powered-By'])
        if "X-XSS-Protection" not in r_headers: result.append(vuls['X-XSS-Protection'])
        return result

    # 获取站点CMS
    @classmethod
    async def site_cms(cls, site: str):
        result, res = {'cms': ''}, r_get(url=site, allow_redirects=True)
        if res is None: return result
        soup = Function.beautifulsoup(res.text, res.content, dict(res.headers))
        title = soup.title.text if re.search('<title', soup.decode()) else ''
        r_header = ''
        for r in res.headers: r_header += f"{r}:{res.headers.get(r)}\n"
        result['cms'] = Function.get_finger(html=soup.decode(), title=title, header=r_header.rstrip('\n'))
        return result

    # 获取站点解析IP信息
    @classmethod
    async def site_ip(cls, site: str):
        domain = site.split('://')[-1].split('/')[0].split(':')[0]
        try:
            return {"ip": gethostbyname(domain)}
        except gaierror:
            return {"ip": "无"}

    # 获取站点ssl证书
    @classmethod
    async def site_cert(cls, site: str):
        if site.startswith('https://'):
            domain = urlparse(site)
            hostname = domain.netloc
            port = domain.port
            if not port: port = 443 if domain.scheme == 'https' else 0
            if hostname and port:
                try:
                    context = ssl.create_default_context()
                    with create_connection((hostname, port), timeout=cls._timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                            cert = ssl_sock.getpeercert()
                        domains = []
                        [domains.append(i[1].replace('*.', '')) for i in cert['subjectAltName'] if
                         i[1].replace('*.', '') not in domains]
                        domains.sort()
                        try:
                            cname = cert['subject'][-1][0][-1]
                        except:
                            cname = ''
                        try:
                            org = cert['subject'][-2][0][-1]
                        except:
                            org = ''
                        start = cert['notBefore'] if 'notBefore' in cert else ''
                        stop = cert['notAfter'] if 'notAfter' in cert else ''
                    return {"Cname": cname, "org": org, "start": start, "stop": stop, "domains": domains}
                except:
                    return {}
        return {}

    # 获取域名whois信息
    @classmethod
    async def domain_whois(cls, domain: str):
        data = {
            "domain": '',
            'registrar': '',
            'registrant': '',
            'whois_server': '',
            'creation_date': '',
            'expiration_date': '',
            'last_updated': '',
            "emails": '',
            'ns_server': [],
            'status': 'None',
            'registrant_country': ''
        }
        res = await db.domain_get_whois(domain)
        if res:
            data.update(res)
            return data
        try:
            w = whois.whois(domain)
            if 'domain_name' in w: data['domain'] = Function.whois_get_str(w.domain_name)
            if 'registrar' in w: data['registrar'] = Function.whois_get_str(w.registrar)
            if 'name' in w: data['registrant'] = Function.whois_get_str(w.name)
            if 'whois_server' in w: data['whois_server'] = Function.whois_get_str(w.whois_server)
            if 'name_servers' in w: data['ns_server'] = w.name_servers
            if 'status' in w and type(w.status) is str: data['status'] = Function.whois_get_str(w.status)
            if 'emails' in w: data['emails'] = Function.whois_get_str(w.emails)
            if 'org' in w: data['org'] = Function.whois_get_str(w.org)
            if 'state' in w: data['province'] = Function.whois_get_str(w.state)
            if 'country' in w: data['registrant_country'] = Function.whois_get_str(w.country)
            if 'creation_date' in w:
                data['creation_date'] = Function.whois_get_str(w.creation_date).strftime("%Y-%m-%d %H:%M:%S")
            if 'expiration_date' in w:
                data['expiration_date'] = Function.whois_get_str(w.expiration_date).strftime("%Y-%m-%d %H:%M:%S")
            if 'updated_date' in w:
                data['last_updated'] = Function.whois_get_str(w.updated_date).strftime("%Y-%m-%d %H:%M:%S")
            await db.domain_insert_whois(domain, data)
        except Exception as err:
            print("Error", err)
        return data

    # 获取域名的dns解析记录
    @classmethod
    async def domain_nslookup(cls, domain: str):
        result = {'NS': [], 'A': [], 'CNAME': [], 'AAAA': [], 'TXT': []}
        try:
            res = dns.resolve(domain, rdtype='NS', lifetime=5)
            for o in res.rrset:
                server = str(o).rstrip('.')
                if server not in result["NS"]: result["NS"].append(server)
        except:
            pass
        try:
            _a = dns.resolve(domain, rdtype='A', lifetime=5).rrset
            while _a: result['A'].append(str(_a.pop()).strip())
        except:
            pass
        try:
            cname = dns.resolve(domain, rdtype='CNAME').rrset
            while cname: result['CNAME'].append(str(cname.pop()).strip().rstrip('.'))
        except:
            pass
        try:
            cname = dns.resolve(domain, rdtype='AAAA').rrset
            while cname: result['AAAA'].append(str(cname.pop()).strip().rstrip('.'))
        except:
            pass
        try:
            cname = dns.resolve(domain, rdtype='TXT').rrset
            while cname: result['TXT'].append(str(cname.pop()).strip().strip('"'))
        except:
            pass
        return result

    # 获取域名icp备案信息
    @classmethod
    async def domain_icp_query(cls, domain: str):
        result = {"list": [], "size": 0}
        list1 = [cls.domain_icp_icplishi, cls.domain_icp_phehmt, cls.domain_icp_beianx, Quake.get_icp,
                 cls.domain_icp_fzhan,  # cls.domain_icp_aa1
                 ]
        db_res = await db.domain_icp_query(unquote(domain))
        if db_res:
            result['list'].extend(db_res)
            result['size'] = len(result['list'])
            return result
        dom = Function.is_domain(domain)
        run = sorted(list1, key=lambda x: random.random())[:5]
        while dom and run:
            try:
                res = [i for i in run.pop()(dom) if
                       i['natureName'] != "未备案" and i['mainLicence'] not in ["-", "暂无"]]
            except:
                res = None
            if res:
                result['list'].extend(res)
                result['size'] = len(result['list'])
                await db.domain_insert_icp(res)
                return result
        return result

    # 通过phehmt.laf.run 接口获取备案
    @classmethod
    def domain_icp_phehmt(cls, dom: str):
        result, token = list(), '637e79b77fd9b2915dfb7e6c'
        res = r_get(f'https://phehmt.laf.run:443/icp?token={token}&url={dom}&version=2&icp=1', timeout=cls._timeout)
        if res is not None and res.json():
            model = cls.icp_model.copy()
            try:
                _t = res.json()
                data = _t['icp']
            except:
                return result
            if 'subject' not in data and 'website' not in data: return result
            if not data['website']['domain'].endswith(dom): return result
            model['domain'] = data['website']['domain']
            model['serviceLicence'] = data['website']['license']
            model['unitName'] = data['subject']['name']
            model['natureName'] = data['subject']['nature']
            model['mainLicence'] = data['subject']['license'].split('-')[0]
            model['updateRecordTime'] = data['subject']['updateTime']
            result.append(model)
        return result

    # 通过www.beianx.cn获取备案
    @classmethod
    def domain_icp_beianx(cls, dom: str):
        result = list()
        model = cls.icp_model.copy()
        header = {
            'Referer': 'https://www.beianx.cn/search/' + dom,
            "Cookie": '__51huid__JfwpT3IBSwA9n8PZ=ed1bfb7b-695b-56e0-8d15-eeeeb9fec52d; __51uvsct__JfvlrnUmvss1wiTZ=1; __51vcke__JfvlrnUmvss1wiTZ=312ab63d-ad97-5f40-a0b2-dd8a4f457d89; __51vuft__JfvlrnUmvss1wiTZ=1700638690690;'
        }
        res = r_get('https://www.beianx.cn/search/' + dom, header=header, timeout=cls._timeout)
        if res is None: return result
        if re.search('arg1=', res.text):
            try:
                header.update({"Cookie": header['Cookie'] + res.headers['Set-Cookie']})
            except:
                pass
        res = r_get('https://www.beianx.cn/search/' + dom, header=header, timeout=cls._timeout)
        if (res is None or res.status_code != 200 or re.search('--没有查询到记录--', res.text)
                or re.search('arg1=', res.text)): return result
        soup = Function.beautifulsoup(res.text, res.content, dict(res.headers))
        try:
            tr = soup.find('table', class_="table table-sm table-bordered table-hover").find_all('tr')[1]
            tds = tr.find_all('td')[1:-2]
            model.update({
                "unitName": tds[0].text.strip(),
                "natureName": tds[1].text.strip(),
                "serviceLicence": tds[2].text.strip(),
                "mainLicence": tds[2].text.strip().split('-')[0],
                "SiteName": tds[3].text.strip(),
                "SiteIndex": tds[4].text.strip(),
                "domain": Function.is_domain(tds[4].text.strip()),
                "updateRecordTime": tds[5].text.strip(),
            })
            result.append(model)
        except:
            pass
        return result

    # 通过icplishi.com获取备案
    @classmethod
    def domain_icp_icplishi(cls, domain: str):
        api = "https://icplishi.com"
        result = list()
        url = api + "/" + domain.strip('\\') + '/'
        model = cls.icp_model.copy()
        res = r_get(url=url, header={"Referer": api + "/" + domain, "Connection": "close"}, timeout=cls._timeout)
        if res is None or res.status_code != 200: return result
        text = res.text
        soup = Function.beautifulsoup(text, res.content, dict(res.headers))
        if soup is None or re.search('该域名禁止查询', text): return result
        if soup is None or re.search('对不起，该页面无法显示', text): return result
        try:
            now_icp = soup.find('div', class_='module mod-panel').find('div', class_='c-bd').find('tbody')
            if now_icp is None:
                now_icp = soup.find_all('div', class_='box')[1].find('div', class_='c-bd').find('tbody')
            tds = now_icp.find_all('td')
            while tds:
                title = tds.pop(0).text.strip('\n')
                if title == '网站首页': model.update({"SiteIndex": tds.pop(0).text.strip('\n')})
                if title == '备案类型': model.update({"natureName": tds.pop(0).text.strip('\n')})
                if title == '备案主体': model.update({"unitName": tds.pop(0).text.strip('\n')})
                if title == '备案号': model.update({"serviceLicence": tds.pop(0).text.strip('\n')})
                if title == '备案时间': model.update(
                    {"updateRecordTime": tds.pop(0).text.strip('\n').replace('\n', ' ')})
            model.update({"domain": Function.is_domain(model['SiteIndex'])})
            model.update({"mainLicence": model['serviceLicence'].split('-')[0]})
            result.append(model)
        except Exception as err:
            pass
        return result

    # 通过https://www.fzhan.com/ 接口获取备案
    @classmethod
    def domain_icp_fzhan(cls, dom: str):
        result = list()
        res = r_get(
            f'https://www.fzhan.com/tem/moban/niu/api/tools_domain_name_registration_query.php?domain={dom}',
            timeout=cls._timeout)
        if res is not None and res.status_code == 200 and res.json():
            try:
                r_json = res.json()
                if r_json['code'] != 200: return result
                data = r_json['data']
            except:
                return result
            model = cls.icp_model.copy()
            model['domain'] = dom
            model['serviceLicence'] = data['licenseKey'].split('-')[0]
            model['unitName'] = data['organizer']
            model['natureName'] = data['unitNature']
            model['mainLicence'] = data['licenseKey']
            model['updateRecordTime'] = data['auditTime']
            result.append(model)
        return result

    # 获取企业注册备案信息
    @classmethod
    async def unit_info_query(cls, keyword: str):
        res = await db.unit_info_query(keyword)
        if res: return res
        run = sorted([cls.unit_info_chinaz], key=lambda x: random.random())
        for fun in run:
            try:
                result = fun(keyword)
            except:
                result = None
            if result and result['Cname']:
                if Function.is_domain(keyword):
                    await db.unit_info_update(keyword, result, dom=True)
                elif not re.search(r'.', keyword):
                    await db.unit_info_update(keyword, result, Cname=True)
        return None

    # icp.chinaz.com 获取企业注册信息
    @classmethod
    def unit_info_chinaz(cls, keyword: str) -> dict:
        result = cls.unit_info_model.copy()
        res = r_get(url="https://icp.chinaz.com/" + keyword, timeout=cls._timeout)
        if res is None or res.status_code != 200: return result
        soup = Function.beautifulsoup(res.text, res.content, dict(res.headers))
        try:
            for tr in soup.find_all('tbody')[0].find_all('tr'):
                tds = tr.find_all('td')
                while tds:
                    title = tds.pop(0).text.strip('\n')
                    if title == '主办单位名称': result.update({"Cname": tds.pop(0).text.strip('\n')})
                    if title == '主办单位性质': result.update({"Ctype": tds.pop(0).text.strip('\n')})
                    if title == '网站名称': result.update({"SiteName": tds.pop(0).text.strip('\n')})
                    if title == '网站负责人': result.update({"SitePrincipal": tds.pop(0).text.strip('\n')})
                    if title == '网站首页网址': result.update({"SiteIndex": tds.pop(0).text.strip('\n')})
                    if title == '审核日期': result.update({"ReviewTime": tds.pop(0).text.strip('\n')})
            for tr in soup.find_all('tbody')[1].find_all('tr'):
                tds = tr.find_all('td')
                while tds:
                    title = tds.pop(0).text.strip('\n')
                    if title == '公司类型': result.update({"GsType": tds.pop(0).text.strip('\n')})
                    if title == '注册资本': result.update({"RegCapital": tds.pop(0).text.strip('\n')})
                    if title == '注册时间': result.update({"RegTimer": tds.pop(0).text.strip('\n')})
                    if title == '注册地址': result.update({"RegAddr": tds.pop(0).text.strip('\n')})
        except:
            pass
        return result


class Quake:
    @classmethod
    def get_icp(cls, domain: str):
        result = list()
        if not quake['token']: return result
        header = {"X-QuakeToken": quake['token'], "Content-Type": "application/json"}
        data = {"query": f'domain:"{domain}"', "start": 0, "size": 1, "ignore_cache": True, "latest": True}
        res = r_post(url=quake['api'] + '/api/v3/search/quake_service', header=header, json=data)
        if not res or res.status_code != 200: return result
        model = Engine.icp_model.copy()
        try:
            res = res.json()
            icp = res['data'][0]['service']['http']['icp']
            model['serviceLicence'] = icp['licence']
            model['updateRecordTime'] = icp['update_time'].replace('T', ' ').rstrip('Z')
            model['domain'] = icp['domain']
            model['mainLicence'] = icp['main_licence']['licence']
            model['natureName'] = icp['main_licence']['nature']
            model['unitName'] = icp['main_licence']['unit']
            result.append(model)
        except:
            pass
        return result
