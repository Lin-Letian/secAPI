from Script import InvalidUsage, Unauthorized, Forbidden, NotFound, MethodNotAllowed, URLBuildError, ServerError, \
    ServiceUnavailable
from Script.api import API, Analysis, Query, Vul, Download
from Script.page import Page


class Router:
    def __init__(self, con):
        page = Page()
        _methods = ['GET', 'POST']
        _post = ['POST']
        _get = ['GET']

        # Error
        con.exception(InvalidUsage)(page.ignore_400s)
        con.exception(Unauthorized)(page.ignore_401s)
        con.exception(Forbidden)(page.ignore_403s)
        con.exception(NotFound)(page.ignore_404s)
        con.exception(MethodNotAllowed)(page.ignore_405s)
        con.exception(ServerError)(page.ignore_500s)
        con.exception(URLBuildError)(page.ignore_500_1s)
        con.exception(ServiceUnavailable)(page.ignore_503s)
        # Index
        con.add_route(page.index_, uri='/', methods=_methods)
        # auth
        con.add_route(API.check_login, uri='/auth/login', methods=_post)
        con.add_route(API.check_login_long_timer, uri='/auth/login/long_timer', methods=_post)
        con.add_route(API.check_token, uri='/auth/check_token', methods=_post)
        # Analysis
        con.add_route(Analysis.ip, uri="/api/analysis/ip", methods=_post)
        con.add_route(Analysis.site, uri="/api/analysis/site", methods=_post)
        con.add_route(Analysis.domain, uri="/api/analysis/domain", methods=_post)
        con.add_route(Query.icp, uri="/api/query/icp", methods=_post)
        con.add_route(Query.unit_info, uri="/api/query/unit_info", methods=_post)
        con.add_route(Vul.vul, uri="/api/vul", methods=_post)
        con.add_route(Download.down, uri="/down/download", methods=_get)