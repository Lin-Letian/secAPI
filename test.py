from Vuls import get_list, get_poc
from Script.engine import Function
import asyncio

#  获取一个md5值
print(Function.md5('12312'))

vs = asyncio.run(get_list('all'))

pros = []
vuls = []
typ = []
for i in vs:
    pros.extend(list(vs[i].keys()))
    for o in vs[i]:
        vuls.extend(list(vs[i][o]))
        for v in list(vs[i][o]):
            ab = asyncio.run(get_poc([i, o, v]))
            if ab['type'] not in typ:
                typ.append(ab['type'])
            # if 'type' not in ab: print([i, o, v])

print('漏洞产品:', len(pros), "个")
print('漏洞:', len(vuls), "个")

# 目前的漏洞类型有哪些
# 为了帮助控制新增的漏洞的类型
print(typ)

types = ['SQL注入', '文件读取', '访问控制', '默认口令/弱口令', '解析漏洞', '代码执行', '信息泄漏', '文件上传',
         '命令执行', '命令注入',
         '反序列化', '文件下载', '外部实体注入', '目录遍历']
