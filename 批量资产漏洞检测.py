from secAPI import Exploit, secAPI
from urllib.parse import urlparse
from datetime import datetime
import openpyxl, os, sys
from log import log

e = Exploit()


# e.init()


def timer() -> str:  # 时间
    now = datetime.now()
    year = f'{now.year:02}'
    month = f'{now.month:02}'
    day = f'{now.day:02}'
    hour = f'{now.hour:02}'
    minute = f'{now.minute:02}'
    second = f'{now.second:02}'
    return f"{year}-{month}-{day} {hour}:{minute}:{second}"


def run(url: str, t: str, p: str, v: str):
    global e
    o_file = urlparse(url).netloc.split(':')[0] + timer().replace('.', '_').replace(':', '_')
    poc = e.get_poc(t, p, v)
    res = e.v_run(url, poc, o_file)[-1]
    return res


def main(t: str, p: str, v: str):
    w_csv = []
    with open('config/p_urls.txt', 'r') as f:
        urls = list(set([i for i in f.read().split('\n') if i]))

    for url in urls:
        log.info('[+] Run: {}'.format(url))
        if not secAPI.url_check_status(url): continue
        res = run(url, t, p, v)
        if res['isVul']:
            log.info('漏洞存在 {}'.format(res['vName']))
            ip = secAPI.site_get_ip(url)
            ip_info = secAPI.ip_get_info(ip)
            port = urlparse(url).netloc.split(':')[-1]
            port = port if port else '80' if urlparse(url).scheme == 'http' else '443'
            try:
                int(port)
            except:
                port = '80' if urlparse(url).scheme == 'http' else '443'
            w_csv.append([
                ip, port, urlparse(url).scheme, 'tcp', ip_info['Province'], ip_info['City'], ip_info['Operator'],
                timer(), res['vName'], res['vType'], res['level'], res['vDesc'],
                res['fix'][0] if len(res['fix']) else ''
            ])
    if w_csv:
        fname = '批量漏洞测试'
        # 创建一个新的Excel工作簿
        workbook = openpyxl.Workbook()
        # 选择默认的工作表
        worksheet = workbook.active
        worksheet.append(
            ['IP', '端口', '服务', '协议', '省份/直辖市', '城市', '运营商', '验证时间', 'PoC名称', '漏洞类型',
             '危险级别', '描述', '解决方案'])
        for row in w_csv: worksheet.append(row)
        workbook.save(fname + '.xlsx')


if __name__ == '__main__':
    if not os.path.exists('config/p_urls.txt'): sys.exit('The File “p_urls.txt” Not Fount')
    r = Exploit.run(True)
    main(r[0], r[1], r[2])
