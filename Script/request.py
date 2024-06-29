from aiohttp import ClientSession, ClientResponse, ClientTimeout, FormData
from urllib.parse import unquote, urlparse
from Script.function import Function
from requests_html import HTMLSession as session
from urllib3 import disable_warnings
from typing import Union, Dict
from loguru import logger
import re

disable_warnings()
Timeout = 12


def format_url(url: str):
    tmp = urlparse(url)
    url = tmp.scheme + "://" + tmp.netloc + unquote(tmp.path).replace('../', '.%2E/')
    if tmp.query: url += "?" + tmp.query
    if tmp.fragment: url += "#" + tmp.fragment
    return url


def g_headers(url: str, header: dict = None):
    _header = Function.header()
    try:
        ufo = urlparse(url)
        _header.update({"Host": ufo.netloc})
        _header.update({"Referer": ufo.scheme + '://' + ufo.netloc})
    except ValueError as err:
        print(f"Error parsing URL: {url}, Error: {err}")
    if header: _header.update(header)
    return _header


# 判断域名请求协议
async def get_url(text: str):
    if text.startswith('http') and re.search("://", text): return text
    domain = text.split('://')[-1]
    res = await async_get('http://' + domain)
    if res is not None and res.status == 200: return 'http://' + domain
    res1 = await async_get('https://' + domain)
    if res1 is not None and res1.status == 200: return 'https://' + domain
    if res1 is None and res is not None: return 'http://' + domain
    if res is None and res1 is not None: return 'https://' + domain
    return 'http://' + domain


def r_get(
        url: str,
        timeout: int = Timeout,
        allow_redirects: bool = False,
        verify: bool = False,
        header: dict = None,
        params=None,
        stream: bool = True,
        *args
):
    r"""
    <Response [200]>
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """
    url = format_url(url)
    header = g_headers(url=url, header=header)

    try:
        with session() as S:
            return S.request(method='get', url=url, allow_redirects=allow_redirects, timeout=timeout, verify=verify,
                             headers=header, params=params, stream=stream, *args)
    except Exception as e:
        logger.error(f"Error: {e},url:{url}")
        return None


async def async_get(
        url: str,
        timeout: int = Timeout,
        allow_redirects: bool = False,
        verify: bool = False,
        header: Dict[str, str] = None,
        params: dict = None
) -> Union[ClientResponse, None]:
    """
    发送异步HTTP GET请求

    :param url: 请求的URL
    :param timeout: 请求超时时间（秒）
    :param allow_redirects: 是否允许重定向
    :param verify: 是否验证SSL证书（默认为True）
    :param header: 请求头字典
    :param params: URL参数
    :return: aiohttp.ClientResponse对象或None（如果发生异常）
    """

    url = format_url(url)
    header = g_headers(url=url, header=header)
    try:
        async with ClientSession(trust_env=verify, timeout=ClientTimeout(total=timeout), headers=header) as S:
            async with S.get(url=url, allow_redirects=allow_redirects, params=params, ssl=verify) as _:
                # _.get_encoding()
                try:
                    await _.text()
                except:
                    await _.text('gbk')
                return _
    except Exception as e:
        logger.error(f"Error: {e},url:{url}")
        return None


def r_post(
        url: str,
        data=None,
        json: dict = None,
        files=None,
        timeout: int = Timeout,
        allow_redirects: bool = False,
        verify: bool = False,
        header: dict = None,
        params=None,
        stream: bool = True,
        *args
):
    """
    Sends a POST request.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """
    url = format_url(url)
    if header is not None and 'Content-Type' not in header and json is None and files is None:
        header.update({"Content-Type": "application/x-www-form-urlencoded"})
    header = g_headers(url=url, header=header)
    try:
        with session() as S:
            return S.request(method='post', url=url, files=files, data=data, json=json, allow_redirects=allow_redirects,
                             timeout=timeout, verify=verify, headers=header, params=params, stream=stream, *args)
    except Exception as e:
        logger.error(f"Error: {e},url:{url}")
        return None


async def async_post(
        url: str,
        data=None,
        json: dict = None,
        files=None,
        timeout: int = Timeout,
        allow_redirects: bool = False,
        verify: bool = False,
        header: dict = None,
        params=None
) -> Union[ClientResponse, None]:
    """
    发送异步HTTP POST请求

    :param url: 请求的URL
    :param data: 作为请求体的数据（仅当json和files为None时有效）
    :param json: 作为请求体的JSON数据（如果提供，将自动设置Content-Type为application/json）
    :param files: 要上传的文件
    :param timeout: 请求超时时间，默认为无限制（使用aiohttp.ClientTimeout类来定义）
    :param allow_redirects: 是否允许自动处理重定向，默认为False
    :param verify: 是否验证SSL证书，默认为True
    :param header: 请求头字典（建议将参数名改为headers以保持一致性）
    :param params: 附加到URL的查询参数
    :return: aiohttp.ClientResponse对象，如果发生异常则返回None
    """
    url = format_url(url)
    if header is not None and 'Content-Type' not in header and json is None and files is None:
        header.update({"Content-Type": "application/x-www-form-urlencoded"})
    header = g_headers(url=url, header=header)
    form = None
    if files is not None:
        form = FormData()
        for f in files:
            form.add_field(
                name=f,
                filename=files[f][0] if files[f] else '',
                value=files[f][1] if len(files[f]) > 1 else '',
                content_type=files[f][2] if len(files[f]) > 2 else ''
            )
        if data: [form.add_field(k, str(data[k])) for k in data]
    async with ClientSession(trust_env=verify, timeout=ClientTimeout(total=timeout), headers=header) as S:
        try:
            async with S.post(url=url, data=data if form is None else form, json=json,
                              allow_redirects=allow_redirects, params=params, ssl=verify) as _:
                await _.text()
                return _
        except Exception as e:
            logger.error(f"Error: {e},url:{url}")
            return None


def r_put(
        url: str,
        data=None,
        json: dict = None,
        files=None,
        timeout: int = Timeout,
        allow_redirects: bool = False,
        verify: bool = False,
        header: dict = None,
        params=None,
        stream: bool = True,
        *args
):
    """
    Sends a POST request.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """
    url = format_url(url)
    header = g_headers(url=url, header=header)
    try:
        with session() as S:
            return S.request(method='put', url=url, files=files, data=data, json=json, allow_redirects=allow_redirects,
                             timeout=timeout, verify=verify, headers=header, params=params, stream=stream, *args)
    except Exception as e:
        logger.error(f"Error: {e},url:{url}")
        return None


async def async_put(url: str, data=None, timeout: int = Timeout, allow_redirects: bool = False, verify: bool = False,
                    header: dict = None) -> Union[ClientResponse, None]:
    """
    发送异步HTTP PUT请求

    :param url: 要发送请求的 URL。
    :param data: 要在请求体中发送的数据。
    :param timeout: 请求的超时时间（秒）。
    :param allow_redirects: 是否允许跟随重定向。
    :param verify: 是否验证 SSL 证书。
    :param header: 与请求一起发送的 HTTP 头部字典。
    :return: 包含响应对象和布尔值的元组，表示请求是否成功。
    :rtype: tuple[aiohttp.ClientResponse, bool]
    """
    url = format_url(url)  # 假设你有一个 format_url 函数来格式化 URL
    header = g_headers(url=url, header=header)  # 假设你有一个 g_headers 函数来设置或合并头部

    try:
        async with ClientSession(timeout=ClientTimeout(total=timeout), trust_env=verify, headers=header) as S:
            async with S.put(url, data=data, allow_redirects=allow_redirects, ssl=verify) as _:
                await _.text()
                return _
    except Exception as e:
        logger.error(f"Error: {e},url:{url}")
        return None
