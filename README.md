# 最新版请访问： https://tools.birdy02.com

# secAPI

    这是一个为个人工作开发的协助平台，有分析网页、分析ip、分析域名、ICP等查询的功能
    
    这是一个 v1.2 版本，在这之前还有 Python+Sqlite3的 版本
    目前已经将代码迁移到Golang语言中，Python版本的更新将变得缓慢
    程序在Linux下运行效果最佳、Windows中也可以正常使用

## 部署
    开发环境：Python 3.10.11 + MySQL 5.7
    
    1. 请在Config/__init__.py中配置好数据库配置信息
    2. 运行 python init.py 实现初始化
    3. 由于这只是个API，图形化界面调用暂定使用以下平台来使用
    4. 运行这个程序，你只需要复制 run.sh 文件中的代码来运行即可

林乐天的协助平台，[https://tools.birdy02.com](https://old-tools.birdy02.com/)，登录时更新api为本地搭建的api地址

## 文件说明
    Append_User.py 文件用来新增用户，用户信息需要在文件中修改
    test.py 可以看到平台中有的漏洞数量和漏洞类型有哪些


## 联系我
如果有好的建议或者一起更新，请联系我，备注 Github
https://www.birdy02.com
https://tools.birdy02.com

# 说明图
<img src="https://github.com/Lin-Letian/secAPI/blob/main/Config/secAPI.png">
