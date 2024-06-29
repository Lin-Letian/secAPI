from Script.database import MySQL
from Script import jwt_decode, PAD_PKCS5, CBC, binascii, des, time, jwt_encode, datetime, re

db = MySQL()


class Action:
    SECRET_KEY = 'a675810674f1f0894a1d26e5ab421ad2e273c8aa'
    des_key = 'B4GO_4@0'

    # 创建JWT
    @classmethod
    def encipher_token(cls, timer: int, user_id: int, role: str):
        return cls.des_encrypt(
            jwt_encode({"time": timer, 'loginId': user_id, "role": role}, cls.SECRET_KEY, algorithm='HS256'))

    # 解析JWT
    @classmethod
    def decrypt_token(cls, token: str):
        try:
            return jwt_decode(cls.des_decrypt(token), cls.SECRET_KEY, algorithms=['HS256'])
        except:
            return False

    # DES 加密
    @classmethod
    def des_encrypt(cls, s) -> str:
        return binascii.b2a_hex(
            des(cls.des_key, CBC, cls.des_key, pad=None, padmode=PAD_PKCS5).encrypt(s, padmode=PAD_PKCS5)).decode()

    # DES 解密
    @classmethod
    def des_decrypt(cls, s) -> str:
        return des(cls.des_key, CBC, cls.des_key, pad=None, padmode=PAD_PKCS5).decrypt(binascii.a2b_hex(s),
                                                                                       padmode=PAD_PKCS5).decode()

    @classmethod
    async def is_exploit(cls, token: str) -> bool:
        if token is None: return False
        try:
            payload = cls.decrypt_token(token)
            if payload:
                user = await db.get_user(payload['loginId'], payload['time'])
                # 当前时间戳 - 登陆时间戳 <= 60 * 60 * 24 * 7 * 4 * 12 + 3 * 6 即为登陆未过期 -> 354天
                return True if re.search('s', user[-1]) else False
            return False
        except:
            return False

    # 验证JWT令牌的装饰器
    @classmethod
    async def authenticate(cls, token: str) -> str:
        if token is None: return "0"
        try:
            payload = cls.decrypt_token(token)
            if payload:
                user = await db.get_user(payload['loginId'], payload['time'])
                # 当前时间戳 - 登陆时间戳 <= 60 * 60 * 24 * 7 * 4 * 12 + 3 * 6 即为登陆未过期 -> 354天
                return "1" if user and int(time()) - payload['time'] <= 60 * 60 * 24 * 7 and token == user[0] else "0"
            return "0"
        except:
            return "0"

    @classmethod
    async def get_role(cls, token) -> str:
        if token is None: return "0"
        rdata = cls.decrypt_token(token=token)
        data = await db.get_user(rdata['loginId'], rdata['time'])
        if data: return str(data[-1]) if data[-1] else '0'
        return '0'

    @classmethod
    async def is_root(cls, token) -> bool:
        auth = await cls.authenticate(token=token)
        role = await cls.get_role(token=token)
        if auth == '1': return 'llt' == role

    @classmethod
    async def is_secWork(cls, token) -> bool:  # 判断是否拥有渗透测试模块权限
        auth = await cls.authenticate(token=token)
        role = await cls.get_role(token=token)
        if auth == '1': return '3' in role or 'llt' == role

    @classmethod
    async def is_basic(cls, token) -> bool:  # 判断是否为基本权限
        role = await cls.get_role(token=token)
        return '0' in role or 'llt' == role

    @classmethod
    async def is_AssetSorting(cls, token) -> bool:  # 判断是否拥有区域资产梳理模块权限
        auth = await cls.authenticate(token=token)
        role = await cls.get_role(token=token)
        if auth == '1': return '1' in role or 'llt' == role

    @classmethod
    async def is_AssetCollect(cls, token) -> bool:  # 判断是否拥有资产收集权限
        auth = await cls.authenticate(token=token)
        role = await cls.get_role(token=token)
        if auth == '1': return '2' in role or 'llt' == role

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
