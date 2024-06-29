from Config import mysql as ini
from Script import function
import pymysql

host, port, user, passwd, database = ini['host'], ini['port'], ini['user'], ini['pass'], ini['db']
# 创建数据库连接
db = pymysql.connect(
    host=host,  # 数据库地址
    port=port,
    user=user,  # 数据库用户名
    password=passwd,  # 数据库密码
    database=database,  # 数据库名
    charset='utf8mb4',  # 字符集，根据需要选择
)

# userID 需要在数据库里看一下最后一个是多少，然后+1
# 权限 0 =>基本权限 3 => 漏洞查询权限 s => 漏洞利用权限
# NULL值不用管
sql = f'''INSERT INTO `secapi`.`users` (`userID`, `chineseName`, `englishName`, `email`, `password`, `loginToken`, `phoneNumber`, `userRole`, `lastLoginTime`, `login_ip`) VALUES ('10000000002', '管理员', 'Superman', 'super@birdy02.com', '{function.Function.md5(input("默认账户：Superman，请设置密码："))}', NULL, NULL, '03s', NULL, NULL);'''

try:
    with db.cursor() as cursor:
        cursor.execute(sql)
        db.commit()
finally:  # 关闭数据库连接
    db.close()
