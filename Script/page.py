from Script import cinit, html

cinit()


class Page:
    say = '<title>🙅客官不可以</title>'
    Header = {"X-Powered-By-Birdy-Waf": 'Birdy', "WZWS-Ray": "WZWS", "Server": r"Birdy\-waf"}

    @classmethod
    async def index_(cls, request):
        return html('林乐天的协助平台', status=200, headers=cls.Header)

    @classmethod
    async def robots_say(cls, request):
        return html('😴晚安，玛卡巴卡', status=200, headers=cls.Header)

    @classmethod
    async def ignore_400s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)

    @classmethod
    async def ignore_401s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)

    @classmethod
    async def ignore_403s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)

    @classmethod
    async def ignore_404s(cls, request, exception):
        return html(cls.say, status=404, headers=cls.Header)

    @classmethod
    async def ignore_405s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)

    @classmethod
    async def ignore_500s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)

    @classmethod
    async def ignore_500_1s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)

    @classmethod
    async def ignore_503s(cls, request, exception):
        return html(cls.say, status=403, headers=cls.Header)
