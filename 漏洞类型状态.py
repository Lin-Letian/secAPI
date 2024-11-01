from Vuls import get_list, get_poc
from Script.engine import Function
import asyncio

#  获取一个md5值
print(Function.md5('fdafasf'))

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
