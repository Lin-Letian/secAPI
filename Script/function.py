from Script import (
    BeautifulSoup, chardet, datetime,
    ipaddress, inet_aton, hashlib, load,
    os,
    re, random,
    urlparse, unpack
)


class Function:
    # 程序运行的绝对路径
    path = os.path.dirname(os.path.abspath(__file__)) + '/../'
    country, province, city, county = list(), list(), dict(), dict()
    fingers = None
    domSuffix = [
        '.ac.cn', '.ah.cn', '.bj.cn', '.com.cn', '.cq.cn', '.fj.cn', '.gd.cn', '.gov.cn', '.gs.cn', '.gx.cn', '.gz.cn',
        '.ha.cn',
        '.hb.cn', '.he.cn', '.hi.cn', '.hk.cn', '.hl.cn', '.hn.cn', '.jl.cn', '.js.cn', '.jx.cn', '.ln.cn', '.mo.cn',
        '.net.cn',
        '.nm.cn', '.nx.cn', '.org.cn', '.zj.cn', '.edu.cn', '.cn', '.com', '.edu', '.gov', '.net', '.org', '.biz',
        '.info', '.pro',
        '.name', '.museum', '.coop', '.aero', '.xxx', '.idv', '.xyz', '.asia', '.co', '.top', '.icu', '.site', '.cc',
        '.vip', '.tv',
        '.ltd', '.club', '.me', '.cfd', '.cloud', '.online', '.work', '.fun', '.cx', '.cm', '.pub', '.life', '.us',
        '.fr', '.games',
        '.link', '.in', '.tech', '.market', '.uk', '.live', '.tw', '.pw', '.ink', '.fit', '.shop', '.guru', '.store',
        '.website',
        '.wiki', '.cyou', '.pl', '.moe', '.mobi', '.hk', '.city', '.men', '.wang', '.bond', '.tokyo', '.one', '.hu',
        '.chat', '.host',
        '.so', '.space', '.cf', '.buzz', '.win', '.gq', '.bid', '.trade', '.loan', '.gdn', '.tel', '.date', '.vc',
        '.racing',
        '.science', '.ws', '.dev', '.la', '.nl', '.de', '.ne.jp', '.mil.jp', '.go.jp', '.ac.jp', '.or.jp', '.co.jp',
        '.jp', '.ga',
        '.ru', '.tk', '.bz', '.today', '.fi', '.co.cz', '.ml', '.ml', '.app', '.art', '.click', '.sbs'
    ]
    Province = [
        '北京', '天津', '河北', '山西', '内蒙古', '辽宁', '吉林', '黑龙江', '上海', '江苏', '浙江', '安徽', '福建',
        '江西', '山东', '河南', '湖北', '湖南', '广东', '广西', '海南', '重庆', '四川', '贵州', '云南', '西藏', '陕西',
        '甘肃', '青海', '宁夏', '新疆', '台湾', '香港', '澳门'
    ]

    # 获取header头
    @classmethod
    def header(cls, switch: str = '', types: str = '', api: str = '', yq: bool = False) -> dict:  # 获取请求头
        ip = f"101.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        _u = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
            'Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (HTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11',
            'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (HTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (HTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (HTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (HTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (HTML, like Gecko) Chrome/19.77.34.5 Safari/537.1',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (HTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (HTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5',
            'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (HTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (HTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (HTML, like Gecko) Chrome/19.0.1061.0 Safari/536.3',
        ]
        header = {
            'User-Agent': random.choice(_u),
            "CLIENT-IP": ip,
            "X-FORWARDED-FOR": ip,
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        }
        if switch == 'Bing': header.update({'Host': 'cn.bing.com', 'Referer': 'https://www.bing.com'})
        if types == "json": header.update({'Content-Type': 'application/json'})
        if api: header.update({"Host": api.split('://')[-1].split('/')[0], "Referer": api})
        if yq: header.update({
            "User-Agent": "Baiduspider+(+http://www.baidu.com/search/spider.htm);google|baiduspider|baidu|spider|sogou|bing|yahoo|soso|sosospider|360spider|youdao|jikeSpider;)",
        })
        return header

    # BeautifulSoup格式化
    @classmethod
    def beautifulsoup(cls, text: str, content: bytes, headers: dict) -> BeautifulSoup:
        _char = {
            "gb2312": "gbk", 'gbk': 'gbk',
            'utf-8': 'utf-8'
        }
        soup = BeautifulSoup(text, 'html.parser')
        charset = None
        content_type = headers.get('Content-Type')
        # 获取编码-1 => 响应头
        charset = content_type.split('charset=')[
            -1].lower() if content_type and 'charset=' in content_type else None
        charset = _char[charset] if charset is not None and charset in _char else None

        if charset is None:
            # 获取编码-2 => meta标签1 -> http-equiv="Content-Type"
            meta = soup.find('meta', attrs={'http-equiv': 'Content-Type'})
            _match = re.search(r'charset=([^;]+)', meta.get('content')) if meta and meta.get('content') else None
            charset = _match.group(1).lower() if _match else None
            charset = _char[charset] if charset is not None and charset in _char else None

        if charset is None:
            # 获取编码-3 => meta标签2 -> charset=""
            meta_tag = soup.find('meta', {'charset': True})
            charset = meta_tag[
                'charset'].lower() if charset is None and meta_tag and 'charset' in meta_tag.attrs else None
            charset = _char[charset] if charset is not None and charset in _char else None

        if charset is None:
            # 获取编码-4 => 通过chardet自动检测
            try:
                charset = chardet.detect(content)['encoding'].lower() if charset is None else charset
                charset = _char[charset] if charset is not None and charset in _char else None
            except:
                pass
            charset = _char[charset] if charset is not None and charset in _char else 'utf-8'

        try:
            return BeautifulSoup(content.decode(charset), 'html.parser')
        except:
            return soup

    # 获取格式化后时间
    @classmethod
    def timer(cls, date=None) -> str:  # 时间
        now = datetime.now()
        if date: now = datetime.fromtimestamp(date)
        year = f'{now.year:02}'
        month = f'{now.month:02}'
        day = f'{now.day:02}'
        hour = f'{now.hour:02}'
        minute = f'{now.minute:02}'
        second = f'{now.second:02}'
        return f"{year}-{month}-{day} {hour}:{minute}:{second}"

    # 功能性模块
    @classmethod
    # 获取str的MD5值
    def md5(cls, input_string: str) -> str:
        md5_hash = hashlib.md5()
        md5_hash.update(input_string.encode('utf-8'))
        return str(md5_hash.hexdigest())

    # 格式化地址信息
    @classmethod
    def extract_Addr(cls, addr: str) -> dict:
        result = dict()
        if not cls.country or not cls.province or not cls.city or not cls.county:
            if not cls.get_addr(): return result
        try:
            result["Country"] = list(item for item in cls.country if item in addr)[0]
        except:
            pass
        try:
            prov = list(item for item in cls.province if item['name'] in addr)[0]
            result["Province"] = prov['name']
            prov_code = prov['code']
            try:
                city = list(item for item in cls.city[prov_code] if item['name'] in addr)[0]
                result["City"] = city['name']
                city_code = city['code']
                try:
                    county = list(item for item in cls.county[city_code] if item['name'] in addr)[0]
                    result["County"] = county['name']
                except:
                    pass
            except:
                pass
        except:
            pass
        if 'Province' in result and result['Province'] and 'Country' not in result: result['Country'] = '中国'
        return result

    # 判断是否可能存在SSRF漏洞
    @classmethod
    def check_ssrf(cls, url: str) -> bool:
        try:
            hostname = urlparse(url).hostname
            hostname = hostname if hostname else url

            def ip2long(ip_addr):
                return unpack("!L", inet_aton(ip_addr))[0]

            def is_inner_ipaddress(ip):
                ip = ip2long(ip)
                return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
                    ip2long('10.0.0.0') >> 24 == ip >> 24 or \
                    ip2long('172.16.0.0') >> 20 == ip >> 20 or \
                    ip2long('192.168.0.0') >> 16 == ip >> 16 or \
                    ip2long('0.0.0.0') >> 24 == ip >> 24

            return is_inner_ipaddress(hostname)
        except:
            return False

    # 获取行政区域位置信息
    @classmethod
    def get_addr(cls) -> bool:
        try:
            with open(Function.path + "Config/addr_dict.json", 'rb') as f:
                f = load(f)
                cls.country, cls.province, cls.city, cls.county = f['country'], f['province'], f['city'], f['county']
                return True
        except:
            return False

    # 获取一个ip段内的ip列表
    @classmethod
    def ip_in_range(cls, start_ip, end_ip) -> list:
        start_int = int(ipaddress.IPv4Address(start_ip))
        end_int = int(ipaddress.IPv4Address(end_ip))
        ips = list()
        for ip_int in range(start_int, end_int + 1): ips.append(str(ipaddress.IPv4Address(ip_int)))
        return ips

    # 获取网站指纹
    @classmethod
    def get_finger(cls, html: str, header: str, title: str) -> list:
        file, result = cls.path + 'Config/finger.json', []
        if not os.path.isfile(file): return result
        if cls.fingers is None:
            with open(file, 'r') as f: cls.fingers = load(f)
        if cls.fingers:
            for finger in cls.fingers:
                if html and finger["location"] == "body":
                    if all([html.find(_keyword) != -1 for _keyword in finger["keyword"]]):
                        result.append(finger["cms"]) if finger["cms"] not in result else None
                elif header and finger["location"] == "header":
                    if all([header.find(_keyword) != -1 for _keyword in finger["keyword"]]):
                        result.append(finger["cms"]) if finger["cms"] not in result else None
                elif title and finger["location"] == "title":
                    if all([title.find(_keyword) != -1 for _keyword in finger["keyword"]]):
                        result.append(finger["cms"]) if finger["cms"] not in result else None
        return result

    # 判断是否为域名
    @classmethod
    def is_domain(cls, domain: str) -> str:
        if len(domain.split('.')) > 1:
            for i in cls.domSuffix:
                if domain.endswith(i):
                    domain = domain[:-len(i)].split('.')[-1] + i
                    return domain
        return ''

    # 判断是否为IPv4
    @classmethod
    def is_ipv4(cls, ip):
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
        match = re.match(pattern, ip)
        return bool(match)

    @classmethod
    def is_waf(cls, text: str) -> bool:
        waf_ = [
            "您的请求带有不合法参数，已被网站管理员设置拦截"
        ]
        for _ in waf_:
            if re.search(_, text): return True
        return False

    # whois信息获取str值
    @classmethod
    def whois_get_str(cls, string) -> str:
        st = type(string)
        if st is str: return string
        if st is list and string: return string[-1]
        return string

    # 格式化ipshudi格式
    @classmethod
    def format_ipshudi(cls, result: dict) -> dict:
        result['Country'] = "中国" if result['Country'] == '中華人民共和國' else result['Country']
        result['Country'] = "中国" if result['Country'].lower() == 'china' else result['Country']
        Province = [i for i in cls.Province if re.search(i, result['Province'])]
        result['Province'] = Province[0] if Province else result['Province']
        result['City'] = '湖州' if result['City'] == 'Huchow' else result['City']
        Operator = '移动' if result['Operator'].startswith("China Mobile") else result['Operator']
        Operator = "Akamai" if re.search('Akamai', Operator) else Operator
        Operator = "阿里云" if re.search('Alibaba Cloud', Operator) else Operator
        Operator = "亚马逊" if re.search('Amazon', Operator) else Operator
        Operator = "电信" if re.search('Telecom', Operator) else Operator
        Operator = "联通" if re.search('Unicom', Operator) else Operator
        Operator = Operator[2:] if Operator.startswith('中国') else Operator
        Operator = "中国宽带互联网" if re.search('chinanet', Operator.lower()) else Operator
        Operator = "中国互联网络信息中心" if re.search('cnc group china', Operator.lower()) else Operator
        Operator = "Cloudflare" if re.search('cloudflare', Operator.lower()) else Operator
        Operator = "百度云" if re.search('baidu', Operator.lower()) else Operator
        Operator = "腾讯云" if re.search('tencent', Operator.lower()) else Operator
        Operator = "微软云" if re.search('microsoft', Operator.lower()) else Operator
        Operator = "华为云" if re.search('huawei', Operator.lower()) else Operator
        Operator = "腾讯云" if Operator == "腾讯" else Operator
        Operator = "百度云" if Operator == "百度" else Operator
        Operator = "谷歌云" if Operator == "谷歌公司" else Operator
        Operator = "阿里巴巴广告公司" if re.search('alibaba advertising co', Operator.lower()) else Operator
        Operator = "阿里巴巴" if re.search('alibaba\.com llc', Operator.lower()) else Operator
        Operator = "阿里巴巴(美国)" if re.search('alibaba \(us\)', Operator.lower()) else Operator
        result['Operator'] = Operator

        return result
