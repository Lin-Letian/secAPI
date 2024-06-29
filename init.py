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
)  # 返回结果为字典格式

create_table = [
    '''
    CREATE TABLE IF NOT EXISTS `users`  (
      `userID` char(11) NOT NULL DEFAULT 10000000001,
      `chineseName` varchar(64) NOT NULL,
      `englishName` char(128) NOT NULL,
      `email` char(255) NOT NULL,
      `password` char(255) NOT NULL,
      `loginToken` text NULL,
      `phoneNumber` char(11) NULL,
      `userRole` char(16) NULL DEFAULT 0,
      `lastLoginTime` bigint(10) NULL,
      `login_ip` char(15) NULL,
      PRIMARY KEY (`userID`)
    );
    ''', '''
    DROP TABLE IF EXISTS `ipinfo_shudi`;
    ''',
    '''
    CREATE TABLE IF NOT EXISTS `ipinfo_shudi`  (
      `id` int NOT NULL AUTO_INCREMENT,
      `ip` char(15) NOT NULL COMMENT 'ip地址',
      `country` varchar(255) NULL COMMENT '国家',
      `province` varchar(255) NULL COMMENT '省',
      `city` varchar(255) NULL COMMENT '市',
      `county` varchar(255) NULL COMMENT '区县',
      `operator` varchar(255) NULL COMMENT '运营商',
      `linetype` varchar(255) NULL COMMENT '线路类型',
      PRIMARY KEY (`id`) USING BTREE,
      INDEX `index_ip`(`ip`) USING BTREE
    );
    ''', '''
    CREATE TABLE IF NOT EXISTS `domain_info_unit`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `isok` char(1) NOT NULL DEFAULT 'N',
  `domain` varchar(255) NOT NULL,
  `SiteIndex` varchar(255) NULL,
  `SiteName` varchar(255) NULL,
  `SitePrincipal` varchar(255) NULL,
  `Cname` varchar(255) NULL,
  `Ctype` varchar(255) NULL,
  `GsRegID` char(255) NULL,
  `GsStatus` varchar(255) NULL,
  `GsType` varchar(255) NULL,
  `Industry` varchar(255) NULL,
  `Operators` varchar(255) NULL,
  `RegAddr` varchar(255) NULL,
  `RegCapital` varchar(255) NULL,
  `RegTimer` char(255) NULL,
  `ReviewTime` char(255) NULL,
  `VerifyTime` char(255) NULL,
  `person` varchar(255) NULL,
  `taxpayerID` char(255) NULL,
  PRIMARY KEY (`id`)
);
''', '''
CREATE TABLE IF NOT EXISTS `site_bad_keywords`  (
  `keyword` varchar(255) NOT NULL
);
''', '''
CREATE TABLE IF NOT EXISTS `domain_icp`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `unitName` varchar(255) NOT NULL,
  `mainLicence` varchar(255) NOT NULL,
  `serviceLicence` varchar(255) NOT NULL,
  `natureName` varchar(255) NOT NULL,
  `updateRecordTime` char(255) NOT NULL,
  `SiteName` varchar(255) NULL,
  `SiteIndex` varchar(255) NULL,
  `domain` varchar(255) NULL,
  PRIMARY KEY (`id`)
);
''', '''
CREATE TABLE IF NOT EXISTS `log_access`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `time` char(19) NOT NULL,
  `uid` char(11) NOT NULL,
  `model` varchar(255) NOT NULL,
  `type` varchar(255) NULL,
  `value` text NULL,
  PRIMARY KEY (`id`)
);
''', '''
CREATE TABLE IF NOT EXISTS `log_login`  (
  `id` int AUTO_INCREMENT,
  `uid` char(11) NOT NULL,
  `uname` varchar(255) NOT NULL,
  `role` char(255) NOT NULL,
  `time` char(19) NOT NULL,
  `ip` char(15) NOT NULL,
  PRIMARY KEY (`id`)
);
''', '''
CREATE TABLE IF NOT EXISTS `domain_wangan_id`  (
  `id` int AUTO_INCREMENT,
  `unitName` varchar(255) NULL,
  `wanganId` varchar(255) NULL,
  `domain` varchar(255) NULL,
  `unitType` varchar(255) NULL,
  `department` varchar(255) NULL,
  `webName` varchar(255) NULL,
  `time` varchar(255) NULL,
  `webType` varchar(255) NULL,
  PRIMARY KEY (`id`)
);
''', '''
CREATE INDEX idx_ip ON ipinfo_shudi(ip);
''', '''
CREATE TABLE IF NOT EXISTS `secapi`.`ipinfo_whois`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `timer` char(19) NULL,
  `ip` char(15) NULL,
  `inetnum` varchar(255) NULL COMMENT '地址范围',
  `netname` varchar(255) NULL COMMENT '网络名称',
  `status` varchar(255) NULL COMMENT '网络类型',
  `descr` varchar(255) NULL COMMENT '描述',
  `address` varchar(255) NULL COMMENT '注册地址',
  `person` varchar(255) NULL COMMENT '注册人',
  `phone` varchar(255) NULL COMMENT '电话',
  `e_mail` varchar(255) NULL COMMENT '邮箱',
  `org_name` varchar(255) NULL COMMENT '组织名',
  `country` varchar(255) NULL COMMENT '国家',
  `last_modified` varchar(255) NULL COMMENT 'CNNIC上次更新',
  `source` varchar(255) NULL COMMENT '数据来源',
  PRIMARY KEY (`id`),
  INDEX `ipv4`(`ip`)
);
''', '''
CREATE TABLE IF NOT EXISTS `secapi`.`ipinfo_location`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `timer` char(19) NULL,
  `ip` char(15) NULL,
  `region` varchar(255) NULL,
  `city` varchar(255) NULL,
  `loc` varchar(255) NULL,
  `org` varchar(255) NULL,
  PRIMARY KEY (`id`),
  INDEX `ipv4`(`ip`)
);
''', '''
CREATE TABLE IF NOT EXISTS `secapi`.`domain_whois`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `timer` char(19) NULL,
  `domain` varchar(255) NULL,
  `registrar` varchar(255) NULL COMMENT '登记者',
  `registrant` varchar(255) NULL COMMENT '登记人',
  `whois_server` varchar(255) NULL,
  `creation_date` varchar(255) NULL COMMENT '创建时间',
  `expiration_date` varchar(255) NULL COMMENT '到期时间',
  `last_updated` varchar(255) NULL,
  `emails` varchar(255) NULL,
  `ns_server` text NULL,
  `status` varchar(255) NULL,
  `registrant_country` varchar(255) NULL,
  PRIMARY KEY (`id`),
  INDEX `index_domain`(`domain`)
);
''', '''
CREATE TABLE IF NOT EXISTS `secapi`.`ipinfo_bad`  (
  `ip` char(15) NOT NULL,
  `num` int NOT NULL DEFAULT 0,
  `timer` char(19) NOT NULL
);
''', '''
CREATE TABLE IF NOT EXISTS `secapi`.`domain_nslookup`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `timer` char(19) NULL,
  `domain` varchar(253) NOT NULL,
  `cname` varchar(255) NULL,
  `ns` text NULL,
  `a` text NULL,
  `aaaa` text NULL,
  `txt` text NULL,
  PRIMARY KEY (`id`, `domain`),
  INDEX `dex_domain`(`domain`) USING BTREE
);
''', f'''
INSERT INTO `secapi`.`users` (`userID`, `chineseName`, `englishName`, `email`, `password`, `loginToken`, `phoneNumber`, `userRole`, `lastLoginTime`, `login_ip`) VALUES ('10000000001', '管理员', 'Superman', 'super@birdy02.com', '{function.Function.md5(input("默认账户：Superman，请设置密码："))}', NULL, NULL, '03s', NULL, NULL);
'''
]

try:
    with db.cursor() as cursor:
        for sql in create_table:
            cursor.execute(sql)
            # 提交事务
            db.commit()
finally:
    # 关闭数据库连接
    db.close()
