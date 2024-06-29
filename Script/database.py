from Script.function import Function, re
from Config import mysql as ini
from json import loads, dumps
from Script import unquote
from loguru import logger
import aiomysql, asyncio


class MySQL:
    host, port, user, passwd, database, timer = ini['host'], ini['port'], ini['user'], ini['pass'], ini['db'], 10
    pool = None
    loop = asyncio.get_event_loop()

    # SQL Connect
    @classmethod
    async def init_pool(cls, minsize=10, maxsize=10):
        return await aiomysql.create_pool(
            host=cls.host, port=cls.port,
            user=cls.user, password=cls.passwd,
            db=cls.database, loop=cls.loop,
            minsize=minsize, maxsize=maxsize,
            charset='utf8mb4', autocommit=True
        )

    # 获取登陆信息
    @classmethod
    async def login_get_user(cls, uname: str, passwd: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            sql = '''select userID,email,englishName,phoneNumber,password,userRole from users where (email=%s or englishName=%s) and password=%s limit 0,1'''
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (uname, uname, passwd))
                    res = await cur.fetchone()
                    return res if res else ()
        except Exception as e:
            logger.error(e)
        return ()

    # 用户登陆后更新数据
    @classmethod
    async def user_login(cls, logtime: int, uid: int, token: str, ip: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            sql = '''UPDATE users SET lastLoginTime=%s,loginToken=%s,login_ip=%s where userID=%s'''
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (logtime, token, ip, uid))
                    await conn.coommit()
        except Exception as e:
            logger.error(e)

    # 验证token的时候返回信息
    @classmethod
    async def get_user(cls, uid: str, timer: int):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            sql = '''select loginToken,email,englishName,login_ip,lastLoginTime,userRole from users where userID=%s and lastLoginTime=%s limit 0,1'''
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql, (int(uid), timer))
                    res = await cur.fetchone()
                    return res if res else ()
        except Exception as e:
            logger.error(e)
        return ()

    # 获取IP归属信息
    @classmethod
    async def ip_get_shudi(cls, ip: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        'select country, province, city, county, operator, linetype from ipinfo_shudi where ip=%s limit 0,1',
                        (ip,)
                    )
                    res = await cur.fetchone()
                    if res: return {"Country": res[0], "Province": res[1], "City": res[2], "County": res[3],
                                    "Operator": res[4], "lineType": res[5]}
        except Exception as e:
            logger.error(e)
        return ()

    # ip数据插入到表中
    @classmethod
    async def ip_insert_shudi(cls, ip: str, d: dict):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select ip from ipinfo_shudi where ip=%s limit 0,1', (ip,))
                    if not await cur.fetchone():
                        sql = 'insert into ipinfo_shudi(ip, country, province, city, county, operator, linetype) values (%s,%s,%s,%s,%s,%s,%s)'
                        Province = [i for i in Function.Province if re.search(i, d['Province'])]
                        await cur.execute(sql, (
                            ip, d['Country'], Province[0] if Province else d['Province'], d['City'], d['County'],
                            d['Operator'], d['lineType']))
                        await conn.commit()
        except Exception as e:
            logger.error(e)
        return d

    # 获取IP Whois信息
    @classmethod
    async def ip_get_whois(cls, ip: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        'select inetnum, netname, status, descr, address, person, phone, e_mail, org_name, country, last_modified, source from ipinfo_whois where ip=%s limit 0,1',
                        (ip,)
                    )
                    res = await cur.fetchone()
                    if res:
                        result = {}
                        if res[0]: result.update({'inetnum': res[0]})
                        if res[1]: result.update({'netname': res[1]})
                        if res[2]: result.update({'status': res[2]})
                        if res[3]: result.update({'descr': res[3]})
                        if res[4]: result.update({'address': res[4]})
                        if res[5]: result.update({'person': res[5]})
                        if res[6]: result.update({'phone': res[6]})
                        if res[7]: result.update({'e_mail': res[7]})
                        if res[8]: result.update({'org_name': res[8]})
                        if res[9]: result.update({'country': res[9]})
                        if res[10]: result.update({'last_modified': res[10]})
                        if res[11]: result.update({'source': res[11]})
                        return result
        except Exception as e:
            logger.error(e)
        return {}

    # IP Whois插入到表中
    @classmethod
    async def ip_insert_whois(cls, ip: str, d: dict):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select ip from ipinfo_whois where ip=%s limit 0,1', (ip,))
                    if not await cur.fetchone():
                        sql = 'insert into ipinfo_whois(timer, ip, inetnum, netname, status, descr, address, person, phone, e_mail, org_name, country, last_modified,source) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                        await cur.execute(sql, (
                            Function.timer(), ip,
                            d['inetnum'] if "inetnum" in d else '',
                            d['netname'] if "netname" in d else '',
                            d['status'] if "status" in d else '',
                            d['descr'] if "descr" in d else '',
                            d['address'] if "address" in d else '',
                            d['person'] if "person" in d else '',
                            d['phone'] if "phone" in d else '',
                            d['e_mail'] if "e_mail" in d else '',
                            d['org_name'] if "org_name" in d else '',
                            d['country'] if "country" in d else '',
                            d['last_modified'] if "last_modified" in d else '',
                            d['source'] if "source" in d else '',
                        ))
                        await conn.commit()
        except Exception as e:
            logger.error(e)
        return d

    # 获取IP归属信息
    @classmethod
    async def ip_get_location(cls, ip: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select region, city, loc, org from ipinfo_location where ip=%s limit 0,1', (ip,))
                    res = await cur.fetchone()
                    if res: return {"region": res[0], "city": res[1], "loc": res[2], "org": res[3]}
        except Exception as e:
            logger.error(e)
        return ()

    #  ip数据插入到表中
    @classmethod
    async def ip_insert_location(cls, ip: str, d: dict):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select ip from ipinfo_location where ip=%s limit 0,1', (ip,))
                    if not await cur.fetchone():
                        sql = 'insert into ipinfo_location(timer, ip, region, city, loc, org) values (%s,%s,%s,%s,%s,%s)'
                        await cur.execute(sql, (Function.timer(), ip, d['region'], d['city'], d['loc'], d['org']))
                        await conn.commit()
        except Exception as e:
            logger.error(e)
        return d

    # 获取违法信息关键字
    @classmethod
    async def site_bad_keywords(cls):
        result = []
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select keyword from site_bad_keywords group by keyword')
                    res = await cur.fetchall()
                    if res: [result.append(i[0].lower()) for i in res if i and i[0].lower() not in result]
                    return sorted(result)
        except Exception as e:
            logger.error(e)
        return result

    # 获取IP归属信息
    @classmethod
    async def domain_get_whois(cls, domain: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        'select domain, registrar, registrant, whois_server, creation_date, expiration_date, last_updated, emails, ns_server, status, registrant_country from domain_whois where domain=%s limit 0,1',
                        (domain,))
                    res = await cur.fetchone()
                    if res:
                        try:
                            ns_server = loads(res[8])
                        except:
                            ns_server = None
                        return {
                            "domain": res[0],
                            'registrar': res[1],
                            'registrant': res[2],
                            'whois_server': res[3],
                            'creation_date': res[4],
                            'expiration_date': res[5],
                            'last_updated': res[6],
                            "emails": res[7],
                            'ns_server': ns_server,
                            'status': res[9] if res[9] else 'None',
                            'registrant_country': res[10]
                        }
        except Exception as e:
            logger.error(e)
        return {}

    #  ip数据插入到表中
    @classmethod
    async def domain_insert_whois(cls, domain: str, d: dict):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select domain from domain_whois where domain=%s limit 0,1', (domain,))
                    if not await cur.fetchone():
                        sql = 'insert into domain_whois(timer, domain, registrar, registrant, whois_server, creation_date, expiration_date, last_updated, emails, ns_server, status, registrant_country) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                        try:
                            ns_server = dumps(d['ns_server'])
                        except:
                            ns_server = dumps([])
                        await cur.execute(sql, (
                            Function.timer(), domain, d['registrar'], d['registrant'], d['whois_server'],
                            d['creation_date'], d['expiration_date'], d['last_updated'], d['emails'], ns_server,
                            d['status'], d['registrant_country'],
                        ))
                        await conn.commit()
        except Exception as e:
            logger.error(e)
        return d

    # 获取icp备案信息
    @classmethod
    async def domain_icp_query(cls, keyword: str):
        keyword = unquote(keyword)
        result = []
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        'select unitName, mainLicence, serviceLicence, natureName, updateRecordTime, SiteName, SiteIndex,domain from domain_icp where (domain=%s or unitName=%s or serviceLicence=%s or mainLicence=%s)',
                        (keyword, keyword, keyword, keyword))
                    res = await cur.fetchall()
                    if res:
                        for i in res:
                            if len(i) != 8: continue
                            result.append({
                                "SiteName": i[5],  # 网站名称
                                "SiteIndex": i[6],  # 网站首页
                                "natureName": i[3],  # 单位性质
                                "unitName": i[0],  # 主办单位
                                "mainLicence": i[1],  # ICP号
                                "serviceLicence": i[2],  # 许可证号
                                "updateRecordTime": i[4],  # 登记时间
                                "domain": i[7],  # 域名
                            })
                    return result
        except Exception as e:
            logger.error(e)
        return result

    # 新增ICP备案记录
    @classmethod
    async def domain_insert_icp(cls, o: list = None):
        if o is None: o = list()
        data = []
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    for i in o:
                        await cur.execute('select count(*) from domain_icp where domain=%s', (i['domain'],))
                        fetchone = await cur.fetchone()
                        if fetchone[0] > 0: continue
                        if i['natureName'] != "未备案" and i['mainLicence'] != "-": data.append([
                            i['unitName'], i['mainLicence'], i['serviceLicence'], i['natureName'],
                            i['updateRecordTime'], i['SiteName'], i['SiteIndex'], i['domain']
                        ])
                    while data:
                        sql = 'insert into domain_icp(unitName, mainLicence, serviceLicence, natureName, updateRecordTime, SiteName, SiteIndex,domain) values (%s,%s,%s,%s,%s,%s,%s,%s)'
                        await cur.execute(sql, data.pop())
                    await conn.commit()
                    return True if cur.rowcount > 0 else False
        except Exception as e:
            logger.error(e)
        return False

    # 获取网安备案信息
    @classmethod
    async def domain_wangan_query(cls, keyword: str):
        keyword = unquote(keyword)
        result = []
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        'select unitName, wanganid, domain, unitType, department, webName, time, webType from domain_wangan_id where (domain=%s or unitName=%s or wanganid=%s)',
                        (keyword, keyword, keyword))
                    res = await cur.fetchall()
                    if res:
                        for i in res:
                            if len(i) != 8: continue
                            result.append({
                                "webName": i[5],  # 网站名称
                                "time": i[6],  # 更新时间
                                "unitType": i[3],  # 单位性质
                                "unitName": i[0],  # 主办单位
                                "wanganId": i[1],  # 网安备案号
                                "domain": i[2],  # 域名
                                "department": i[4],  # 登记单位
                                "webType": i[7],  # 网站类型
                            })
                    return result
        except Exception as e:
            logger.error(e)
        return result

    # 新增ICP备案记录
    @classmethod
    async def domain_insert_wangan(cls, o: list = None):
        if o is None: o = list()
        data = []
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    for i in o:
                        await cur.execute('select count(*) from domain_wangan_id where domain=%s limit 0,1',
                                          (i['domain'],))
                        fetchone = await cur.fetchone()
                        if fetchone[0] > 0: continue
                        data.append([i['unitName'], i['wanganId'], i['domain'], i['unitType'], i['department'],
                                     i['webName'], i['time'], i['webType']])
                    while data:
                        sql = 'insert into domain_wangan_id(unitName, wanganid, domain, unitType, department, webName, time, webType) values (%s,%s,%s,%s,%s,%s,%s,%s)'
                        await cur.execute(sql, data.pop())
                    await conn.commit()
                    return True if cur.rowcount > 0 else False
        except Exception as e:
            logger.error(e)
        return False

    # 获取单位工商备案信息
    @classmethod
    async def unit_info_query(cls, keyword: str):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "select domain, SiteIndex, SiteName, SitePrincipal, Cname, Ctype, GsRegID, GsStatus, GsType, Industry, Operators, RegAddr, RegCapital, RegTimer, ReviewTime, VerifyTime, person, taxpayerID from domain_info_unit where isok='Y' and (Cname=%s or domain =%s) limit 0,1",
                        (keyword, keyword))
                    r = await cur.fetchone()
                    return {
                        "Cname": r[4], "Ctype": r[5], "SiteName": r[2], "SitePrincipal": r[3], "SiteIndex": r[1],
                        "ReviewTime": r[14], "person": r[16], "RegCapital": r[12], "RegTimer": r[13], "GsStatus": r[7],
                        "GsType": r[8], "GsRegID": r[6],
                        "Industry": r[9], "taxpayerID": r[17], "VerifyTime": r[15], "RegAddr": r[11], "Operators": r[10]
                    } if r else ()
        except Exception as e:
            logger.error(e)
        return ()

    # 更新单位工商备案信息
    @classmethod
    async def unit_info_update(cls, keyword: str, r, dom: bool = False, Cname: bool = False):
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('select count(*) from domain_info_unit where domain =%s', (keyword,))
                    res = await cur.fetchone()
                    if res and res[0] > 0:
                        await cur.execute(
                            "select count(*) from domain_info_unit where (domain='' or domain is null) and Cname=%s",
                            (r['Cname'],))
                        res = await cur.fetchone()
                        if res and res[0] > 0:
                            sql = f"UPDATE domain_info_unit SET domain=%s,isok=%s,SiteIndex=%s,SiteName=%s,SitePrincipal=%s,Cname=%s,Ctype=%s,GsRegID=%s,GsStatus=%s,GsType=%s,Industry=%s,Operators=%s,RegAddr=%s,RegCapital=%s,RegTimer=%s,ReviewTime=%s,VerifyTime=%s,person=%s,taxpayerID=%s where (domain='' or domain is null) and Cname=%s"
                            await cur.execute(sql, (
                                keyword, 'Y', r['SiteIndex'], r['SiteName'], r['SitePrincipal'], r['Cname'], r['Ctype'],
                                r['GsRegID'],
                                r['GsStatus'], r['GsType'], r['Industry'], r['Operators'], r['RegAddr'],
                                r['RegCapital'],
                                r['RegTimer'],
                                r['ReviewTime'], r['VerifyTime'], r['person'], r['taxpayerID'], r['Cname']))
                        else:
                            sql = 'insert into domain_info_unit(domain,isok,SiteIndex,SiteName,SitePrincipal,Cname,Ctype,GsRegID,GsStatus,GsType,Industry,Operators,RegAddr,RegCapital,RegTimer,ReviewTime,VerifyTime,person,taxpayerID) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                            await cur.execute(sql, (
                                keyword, 'Y', r['SiteIndex'], r['SiteName'], r['SitePrincipal'], r['Cname'], r['Ctype'],
                                r['GsRegID'],
                                r['GsStatus'], r['GsType'], r['Industry'], r['Operators'], r['RegAddr'],
                                r['RegCapital'],
                                r['RegTimer'],
                                r['ReviewTime'], r['VerifyTime'], r['person'], r['taxpayerID']))
                    elif Cname:
                        await cur.execute('select count(*) from domain_info_unit where Cname =%s', (keyword,))
                        res = await cur.fetchone()
                        if res and res[0] > 0:
                            sql = f"UPDATE domain_info_unit SET isok=%s,SiteIndex=%s,SiteName=%s,SitePrincipal=%s,Cname=%s,Ctype=%s,GsRegID=%s,GsStatus=%s,GsType=%s,Industry=%s,Operators=%s,RegAddr=%s,RegCapital=%s,RegTimer=%s,ReviewTime=%s,VerifyTime=%s,person=%s,taxpayerID=%s where Cname=%s"
                            await cur.execute(sql, (
                                'Y', r['SiteIndex'], r['SiteName'], r['SitePrincipal'], keyword, r['Ctype'],
                                r['GsRegID'],
                                r['GsStatus'],
                                r['GsType'], r['Industry'], r['Operators'], r['RegAddr'], r['RegCapital'],
                                r['RegTimer'],
                                r['ReviewTime'],
                                r['VerifyTime'], r['person'], r['taxpayerID'], keyword))
                        else:
                            sql = 'insert into domain_info_unit(domain,isok,SiteIndex,SiteName,SitePrincipal,Cname,Ctype,GsRegID,GsStatus,GsType,Industry,Operators,RegAddr,RegCapital,RegTimer,ReviewTime,VerifyTime,person,taxpayerID) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                            await cur.execute(sql, (
                                '', 'Y', r['SiteIndex'], r['SiteName'], r['SitePrincipal'], keyword, r['Ctype'],
                                r['GsRegID'],
                                r['GsStatus'],
                                r['GsType'], r['Industry'], r['Operators'], r['RegAddr'], r['RegCapital'],
                                r['RegTimer'],
                                r['ReviewTime'],
                                r['VerifyTime'], r['person'], r['taxpayerID']))
                    await conn.commit()
                    return True if cur.rowcount and cur.rowcount > 0 else False
        except Exception as e:
            logger.error(e)
        return False

    # 新增访问日志
    @classmethod
    async def insert_access_log(cls, timer: str, uid: str, model: str, typer: str, value: str) -> None:
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    sql = 'insert into log_access(time,uid,model,type,value) values (%s,%s,%s,%s,%s)'
                    await cur.execute(sql, (timer, uid, model, typer, value))
                    await conn.commit()
        except Exception as e:
            logger.error(e)

    # 新增登陆日志
    @classmethod
    async def insert_login_log(cls, uid: str, uname: str, role: str, timer: str, ip: str) -> None:
        try:
            if cls.pool is None: cls.pool = await cls.init_pool()
            async with cls.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    sql = 'insert into log_login(uid,uname,role,time,ip) values (%s,%s,%s,%s,%s)'
                    await cur.execute(sql, (uid, uname, role, timer, ip))
                    await conn.commit()
        except Exception as e:
            logger.error(e)
