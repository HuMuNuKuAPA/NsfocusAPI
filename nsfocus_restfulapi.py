#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
# 日期：2023年5月9日
from pprint import pprint

import requests
import json
import hashlib
import urllib3
import re
import datetime
import os
import smtplib
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.utils import formataddr
from email.mime.image import MIMEImage
import pymysql
from jinja2 import Environment, FileSystemLoader
import time
from device_info import device_dict

urllib3.disable_warnings()


class NsfocusAPI:
    def __init__(self, usename, pwd, pagesize=1000, pageno=1):
        """
        :param usename: 用于登录IPS的用户名
        :param pwd: 用于登录IPS时的密码
        :param pagesize: 每页显示的记录数量，这个一般用在取IPS日志的，我们这里不太会出现大于1000条记录的情况
        :param pageno: 和pagesize搭配使用，用于取第几页记录的数据，由于pagesize固定为1000，一般不会有超出1000条记录的情况，所以页数固定为1
        """
        self.username = usename
        self.pwd = pwd
        self.pageSize = pagesize
        self.pageNo = pageno

        # 获取当前的时间戳，并转换为字符串格式，在后面用于计算13位时间戳用
        self.currunttime = str(time.time())
        # 以下参数用于发送邮件时候用
        self.mailServer = 'XXXX'
        self.mailAccount = 'XXXX'
        self.mailPWD = 'Systec123'  # 公司邮箱的发件人密码
        self.from_mail = 'XXXX'
        # 邮件格式这里一定要注意，中间可以用分号隔离开，但是最后一个用户那里不能用再有任何符号，否则会报错Falied recipients: {'': (550, b'Invalid User:')}
        self.to_mail = 'XXXX'


    def get_key(self, dev_ip):
        """
        在和API接口交互前必须先完成设备的登陆认证，设备登陆认证成功后，会返回三个字段，用于后续与API交互的时候提供验证
        返回‘security_key’，'api_key'和cookie
        """
        # 绿盟登录认证用的URL
        url = f'https://{dev_ip}:8081/api/system/account/login/login'
        # 登录认证用post方法，在body中需要传用户名和密码
        params = f'{{"username": "{self.username}","password": "{self.pwd}","vcode": "jrae","lang": "zh_CN"}}'
        # 通过post方法发送request请求
        resp = requests.post(url, params, verify=False)
        # 获取返回值，返回值的格式是json的，通过json.loads方法反序列为python的字典，然后通过字典中的'security_key'和'api_key'建获取值
        resp_dict = json.loads(resp.text)
        # 获取cookie，后续的交互都需要在头部中带上cookie
        cookie = resp.cookies
        return resp_dict['data']['security_key'], resp_dict['data']['api_key'], cookie

    def calculate_time(self):
        """
        计算时间，将1683527912.4615455这种格式的时间戳转换为13位格式，在后续的request请求中需要用到
        :return:
        """
        result = re.split(r'\.', self.currunttime)
        time_13 = result[0] + result[1][:3]  # time = '1640330445060'  时间是13位格式
        return time_13

    def send_get_request(self, ip, api_url, para=''):
        """
        绿盟所有的GET方式的API都是通过这个方法发送的
        :param ip: 设备IP
        :param api_url: api接口的URL
        :param para: get请求的api接口的参数是通过para来传给IPS的
        :return: get请求的结果
        """
        # 在与API接口交互之前，收先要与设备完成认证，并获取security_key、api_key和cookie用于后续的认证
        security_key, api_key, cookie = self.get_key(ip)
        # 计算13位时间戳
        time_13 = self.calculate_time()
        # api接口url
        request_api_row = api_url
        # url和api接口的参数
        request_api = api_url + para
        url = f'https://{ip}:8081{request_api}'
        # 将security-key api-key 13位时间戳 和api接口url（不带参数）合在一起做哈希
        jm = 'security-key:%s;api-key:%s;time:%s;rest-uri:%s' % (security_key, api_key, time_13, request_api_row)
        m1 = hashlib.sha256(jm.encode("utf-8"))
        sign = m1.hexdigest()
        # 绿盟的get请求需要在http头部中添加sign即哈希信息、apikey和13位时间戳
        header = {
            "sign": sign,
            "apikey": api_key,
            "time": time_13,
        }
        # 通过get方法发送request请求，需要带上之前构造的header和cookies
        req_get_policy = requests.get(url,
                                      headers=header,
                                      cookies=cookie,
                                      verify=False,
                                      timeout=2
                                      )
        # 通过json.loads反序列化获得结果
        rsp_get_content = json.loads(req_get_policy.content)
        return rsp_get_content

    def structure_post_url(self, ip, api_url):
        """
        绿盟的post方式的api接口都需要在url中包含sign=XX&apikey=XX&time=XX，这个方法是用来构造post请求的url
        :param ip: 设备的IP
        :param api_url: post请求的api接口地址
        :return: post请求的url
        """
        # 在与API接口交互之前，收先要与设备完成认证，并获取security_key、api_key和cookie用于后续的认证
        security_key, api_key, cookie = self.get_key(ip)
        # 计算13位时间戳
        time_13 = self.calculate_time()
        url = f'https://{ip}:8081{api_url}'
        jm = f'security-key:{security_key};api-key:{api_key};time:{time_13};rest-uri:{api_url}'
        m1 = hashlib.sha256(jm.encode("utf-8"))
        sign = m1.hexdigest()
        # 构造POST请求的URL
        url_request = f'{url}?sign={sign}&apikey={api_key}&time={time_13}'
        return url_request, cookie

    def post_blacklist(self, ip, blackip, days=30):
        # 加黑名单的API接口
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 获取当前时间，用于给黑名单的abstract属性设置时间，abstract属性在IPS页面中就是备注
        current_time = datetime.datetime.now()
        # end_time是黑名单的封禁时间默认加黑30天
        end_time = current_time + datetime.timedelta(days=days)
        data = {
            "action": "insert",
            "data": {'abstract': f'于{current_time}添加',  # 备注信息
                     'cate': 'ip',  # 通过IP的方式添加
                     'direction': '3',  # 不管是黑名单是以源地址还会目的地址，都禁止通信
                     'enabled': 'true',
                     'end_time': end_time.strftime("%Y.%m.%d"),
                     'name': blackip,
                     'start_time': '',  # 不写默认就是当前时间
                     'threat_type': '9'
                     }
        }
        # 发送请求
        try:
            request = requests.post(url=url_request, data=json.dumps(data), cookies=cookie, verify=False, timeout=2)
            return True, request.text
        except requests.exceptions.ConnectTimeout as e:
            # print('请求失败', e)
            return False, e

    def post_applyconfig(self, ip):
        """
        绿盟的设备在post配置后，必须要应用陪住，这个方法就是相当于页面上的应用配置
        :param ip: IPS的设备IP
        :return:
        """
        # 应用配置的API接口
        url = '/api/index/applyconfig'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 应用配置的post请求只要有了URL和cookie就可以了
        try:
            applyconfig_post = requests.post(url=url_request, cookies=cookie, verify=False, timeout=2)
            return True, applyconfig_post.text
        except requests.exceptions.ConnectTimeout as e:
            # print('请求失败', e)
            return False, e

    def get_ips_event(self, ip, time_range):
        """
        本方法用于获取IPS的网络入侵日志
        :param ip: IPS的设备ip
        :param time_range: 想要获取的IPS日志的时间范围，单位是小时，即获取当前时间往前time_range小时的IPS日志
        :return:返回网络入侵日志和当前时间
        """
        # 获得timedelta用于计算时间
        hour_step = datetime.timedelta(hours=time_range)
        # 当前时间，即IPS日志的结束时间 时间格式为2023-05-09 15:06:03.883005
        e_datetime = datetime.datetime.now()
        # IPS日志的起始时间 时间格式为2023-05-09 15:06:03.883005
        s_datetime = e_datetime - hour_step

        # 将2023-05-09 15:06:03.883005格式时间转换为时间戳，这个时间戳需要放在get请求中
        e_time = int(datetime.datetime.timestamp(e_datetime))
        s_time = int(datetime.datetime.timestamp(s_datetime))

        # 获取ips网络入侵日志的api接口
        api = '/api/log/security/ips/event'
        # 获取ips网络入侵日志的api接口的参数
        api_para = f'?pageSize={self.pageSize}&pageNo={self.pageNo}&s_time={s_time}&e_time={e_time}'
        # 通过self.send_get_request方法发送request请求，并获取结果
        result = self.send_get_request(ip, api, api_para)
        # return result["data"]['data']
        return result, e_datetime

    def get_ips_blacklist(self, ip):
        """
        本方法用于获取ips的黑名单信息
        :param ip: IPS地址
        :return: 返回黑名单信息
        """
        # 获取ips黑名单的api接口
        api = '/api/policy/globalList/black/manual'
        # 获取ips黑名单的api接口的参数
        api_para = f'?pageSize={self.pageSize}&pageNo={self.pageNo}'
        # 通过self.send_get_request方法发送request请求，并获取结果
        result = self.send_get_request(ip, api, api_para)
        # blackip = []
        # for i in result['data']['data']:
        #     # pprint(result['data']['data'])
        #     blackip.append(i['name'])
        return result['data']['data']

    def update_ips_blacklist(self, ip, blackip, days=90):
        # black_id用于存储黑名单列表中的id，在更新黑名单列表的时候，需要用id来标识需要更新的信息
        black_id = 0
        # 调用get_ips_blacklist()函数，用来获得所有的黑名单信息
        blacklist = self.get_ips_blacklist(ip)
        for dict_info in blacklist:
            for k, v in dict_info.items():
                # 通过blackip定位到具体的黑名单信息
                if v == blackip:
                    # 然后通过id键获得需要的id值
                    black_id = dict_info['id']
        # 更新黑名单的API接口
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 获取当前时间，用于给黑名单的abstract属性设置时间，abstract属性在IPS页面中就是备注
        current_time = datetime.datetime.now()
        # end_time是黑名单的封禁时间默认加黑30天
        end_time = current_time + datetime.timedelta(days=days)
        data = {
            "action": "update",
            "data": {
                'id': black_id,
                'abstract': f'于{current_time}更新',  # 备注信息
                'cate': 'ip',  # 通过IP的方式添加
                'end_time': end_time.strftime("%Y.%m.%d"),
                'name': blackip,
                'start_time': '',  # 不写默认就是当前时间
                'threat_type': '9'
            }
        }
        # 发送请求
        try:
            request = requests.post(url=url_request, data=json.dumps(data), cookies=cookie, verify=False, timeout=2)
            return True, request.text
        except requests.exceptions.ConnectTimeout as e:
            # print('请求失败', e)
            return False, e

    def send_mail(self, subj, main_body, files=None):  # 使用SSL加密SMTP发送邮件, 此函数发送的邮件有主题,有正文,还可以发送附件
        """
        本方法用于发送邮件用
        :param subj: 邮件的主题
        :param main_body: 邮件的内容
        :param files: 附件
        :return: 返回邮件发送的状态信息
        """
        tos = self.to_mail.split(';')  # 把多个邮件接受者通过';'分开
        date = email.utils.formatdate()  # 格式化邮件时间
        msg = MIMEMultipart()  # 产生MIME多部分的邮件信息
        msg["Subject"] = subj  # 主题
        msg["From"] = formataddr(["绿盟IPS自动化告警", self.from_mail])  # 发件人
        msg["To"] = self.to_mail  # 收件人
        msg["Date"] = date  # 发件日期

        # 指定图片为当前目录
        fp = open('30year.gif', 'rb')
        msgImage = MIMEImage(fp.read())
        fp.close()
        # 定义图片 ID，在 HTML 文本中引用
        msgImage.add_header('Content-ID', '<image>')
        msg.attach(msgImage)

        # 邮件正文为Text类型, 使用MIMEText添加
        # MIME类型介绍 https://docs.python.org/2/library/email.mime.html
        part = MIMEText(main_body, 'html')
        msg.attach(part)  # 添加正文

        if files:  # 如果存在附件文件
            for file in files:  # 逐个读取文件,并添加到附件
                # MIMEXXX决定了什么类型 MIMEApplication为二进制文件
                # 添加二进制文件
                part = MIMEApplication(open(file, 'rb').read())
                # 添加头部信息, 说明此文件为附件,并且添加文件名
                part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file))
                # 把这个部分内容添加到MIMEMultipart()中
                msg.attach(part)

        server = smtplib.SMTP_SSL(self.mailServer, 465)  # 连接邮件服务器
        server.login(self.mailAccount, self.mailPWD)  # 通过用户名和密码登录邮件服务器
        failed = server.sendmail(self.from_mail, tos, msg.as_string())  # 发送邮件
        server.quit()  # 退出会话
        if failed:
            print('Falied recipients:', failed)  # 如果出现故障，打印故障原因！
        else:
            print('邮件已经成功发出！')  # 如果没有故障发生，打印'邮件已经成功发出！'！

    def close_db(self):
        """
        之前关闭数据库连接都是写在write_to_database和analyse_database这两个方法里的，但是实际循环调用的时候会发现报错，循环第一个元素的时
        候正常，但是循环到第二个元素的时候就会数据库报错，查了一些资料可能是和关闭数据库连接有关，在循环到第二个元素的时候发现数据断开连接了，
        至于具体的原因，以我现在的能力无法解决，希望又有朝一日我能搞清楚2023年5月9日！！！！！！！！！！

        大概知道问题了，我把pymysql.connect（）这个数据库连接对象写到__init__里面了，我想复用代码，数据库连接对象在创建class对象的时候
        会一并生成但是一旦数据库连接被关闭，就没有数据库连接对象的连接了，后续再想连数据库就会报错2023年5月10日
        :return:
        """
        # self.mydb.close()
        pass

    def write_to_database(self, ips_ip, tb_name, time_step=1):
        """
        最重要的方法，前面的所有方法都是为这个方法服务的，处理逻辑：
        1.通过self.get_ips_event获取IPS日志
        2.如果有能获取到IPS日志，则提取里面的内容写入到数据库
        3.如果获取不到IPS日志：
            判断是否8:00 - 18:00,如果在这个范围内则发邮件提醒管理员近期没有收到IPS日志，需要登录设备检查

        :param ips_ip:IPS的地址
        :param tb_name:数据库标的名称，每个IPS对应一个数据库表名称
        :param time_step: 想要获取的IPS日志的时间范围，单位是小时，即获取当前时间往前time_range小时的IPS日志
        :return:
        """
        # 通过self.get_ips_event方法获取1小时内的IPS日志
        get_content, opt_time = self.get_ips_event(ips_ip, time_step)
        # 创建一个列表，用于存放从IPS哪里获取的威胁日志
        values = []
        # 数据库名
        table_name = tb_name
        # 用于获得当前时间的结构化数据
        mytime = time.localtime()
        # 获得当前时间的小时数，用于判断是否在当前时间在8:00 - 18:00之间
        myhour = mytime.tm_hour

        if get_content:
            # 如果能获取到日志，则提取里面需要的值写入数据库
            for i in get_content['data']['data']:
                sip = i['sip']
                count = i['count']  # 攻击次数
                dip = i['dip']
                dport = i['dport']
                threat_level = int(i['threat_level'])
                event = i['event']
                threat_type = i['threat_type']
                attack_type = i['attack_type']
                action = i['action'][0]
                country = i['scountry']
                event_time = i['time']
                items = (
                    sip, count, dip, dport, threat_level, event, threat_type, attack_type, action, country, event_time,
                    opt_time)
                values.append(items)
            try:
                # 创建数据库连接对象
                mydb = pymysql.connect(
                    host="10.168.51.237",
                    user="wuzp",
                    password="Systec#278",
                    database="config_backup",
                    port=3306,
                    charset="utf8"
                )
                # 创建游标对象
                mycursor = mydb.cursor()
                # 定义插入多条数据的SQL语句
                sql = "INSERT INTO {} (sip, attack_number,dip,dport,threat_level,event,threat_type,attack_type," \
                      "action,scountry,event_time,opt_time) " \
                      "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)".format(table_name)

                # 执行插入多条数据的SQL语句
                mycursor.executemany(sql, values)

                # 提交事务
                mydb.commit()
                print('数据写入成功')
            except pymysql.Error as error:
                print("Failed to execute query: {}".format(error))
            # 关闭数据库连接
            mydb.close()

        else:
            # 如果没有获取到IPS日志，则根据判断 是否需要发邮件提醒
            if 8 <= myhour <= 18:
                self.send_mail(
                    f'{ips_ip}无日志',
                    f'经查{ips_ip}无日志，请管理员尽快确认设备状态！',
                )

    def analyse_database(self, ips_ip, tb_name, attack_number, location, time_step=24):
        """
        分析数据库，目前是分析24小时内，如果被IPS拦截次数大于3次的，会统计出来并发邮件告警
        :param ips_ip: IPS的地址
        :param tb_name: 每个IPS都对应一个数据库的表名
        :param attack_number:对应IPS中的拦截模式，如果是阻断则attack_number为2，如果是旁路阻断则attack_number为16
        :param location:用于发邮件的时候表示IPS是属于哪个区域的
        :param time_step: 分析多少小时间内的数据，默认值是24小时
        :return:
        """
        # 调用get_ips_blacklist方法获取黑名单信息的字典
        blackip_dict = self.get_ips_blacklist(ips_ip)
        # 从字典中提取所有的黑名单IP
        blackip_list = [i['name'] for i in blackip_dict]
        # 模板的位置；这里用到jinja2的模板，这个模板主要是为发送的邮件内容提供模板
        env = Environment(loader=FileSystemLoader('.'))
        # 加载模板
        template = env.get_template("mail_notice.j2")
        # 获取当前时间由于发邮件用
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            # 创建数据库连接对象
            mydb = pymysql.connect(
                host="10.168.51.237",
                user="wuzp",
                password="Systec#278",
                database="config_backup",
                port=3306,
                charset="utf8"
            )
            # 创建游标对象
            mycursor = mydb.cursor()
            # 执行SQL语句，查询orders表中customer_id为1的记录
            sql = "select sip, count(*) from {} where event_time  BETWEEN NOW() - INTERVAL %s HOUR AND NOW()".format(
                tb_name)
            # sql = "select * from ips_event where event_time  BETWEEN NOW() - INTERVAL %s HOUR AND NOW()"
            # sql += " AND threat_level = 3"
            sql += f" AND action = {attack_number}"
            sql += " GROUP BY sip"
            sql += " having count(*) > 3"

            mycursor.execute(sql,
                             time_step
                             )
            # 获取结果结果的格式是（'地址'：'攻击次数'）
            myresult = mycursor.fetchall()

            # 创建一个字典用于存放数据库的返回结果，这个结果后面还会被jinja2用于生成邮件内容用
            event_dict = {}
            # 输出结果
            for x in myresult:
                # x的值是（'地址'：'攻击次数'），x[0]代表攻击源地址，x[1]代表攻击次数
                attack_event_sql = "select sip,event from {} where sip= \"{}\"".format(
                    tb_name, x[0])
                mycursor.execute(attack_event_sql)
                # 返回结果的格式是(('162.243.145.16', 'Zgrab 扫描攻击探测'), ('162.243.145.16', 'Zgrab 扫描攻击探测'))
                attack_event_result = mycursor.fetchall()
                # 得到的结果是去重后的攻击事件的集合{'Apache Log4j2 远程代码执行漏洞(CVE-2021-44228)'}
                result = {i[1] for i in attack_event_result}
                # 将集合转换为有序的列表后面方便遍历
                final = list(result)
                # 将攻击次数放在列表头，方便后面jinja2获取
                final.insert(0, x[1])
                # 最终得到{'ip':[攻击次数，告警事件1...n]}的字典
                event_dict[attack_event_result[0][0]] = final

        except pymysql.Error as error:
            print("Failed to execute query: {}".format(error))
            # 异常抛出
            # print(myresult)
            raise error

        # 关闭连接
        mydb.close()

        # 以下三个时间参数都是为了发送邮件时候用的
        hour_step = datetime.timedelta(hours=time_step)
        e_datetime = datetime.datetime.now()
        s_datetime = e_datetime - hour_step
        # 通过jinja2生成的模板生成邮件的内容
        result = template.render(policy=event_dict, s_time=s_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                                 e_time=e_datetime.strftime("%Y-%m-%d %H:%M:%S"), time_interval=time_step,
                                 blackip_list=blackip_list)
        # print(result)

        # 发送告警邮件
        if myresult:
            self.send_mail(
                f'{current_time}_{location}IPS {ips_ip}_拦截情况',
                result
            )
        else:
            self.send_mail(
                f'{current_time}_{location}IPS {ips_ip}_拦截情况',
                f'{current_time}_{location}IPS {ips_ip} 无威胁拦截的告警日志！'
            )


if __name__ == '__main__':
    login_account = 'wuzp'
    loging_password = '6dd3cda8f68bc2b6701ba3e4e83800991ad02be83419af8cc500e20d93432e5c14f345139d273' \
                      '08b9f6ffb5c2d17ebc2f578d4798ba066e9970038a3f055a8b504538696491a6bffce9f1330698974d7' \
                      'd417eeb85f6fd21c86e663e4ea8eae91f0387dc4b2de19edb1c4979b1b31a61c3fe82c9546efb1a50f2956b' \
                      '8bd10fc39074dda3a7b6cd0902f4c5db4fa18a17d11d6cfe7f8a4524dfa78f5cc8c3a19972010a06bf1995c076' \
                      'ab0b01856aed8e189286f19447aab53b1dd4103296e249d74b9d21f27e043045757fcf56bb67a57c343435a2f374' \
                      'd265477634f704feeb744e2c7ea77c28dd35bebe0fb156910ef6519c15513644bc92f495fe5541f4077'

    myobj = NsfocusAPI(login_account, loging_password)
    myobj.analyse_database('10.192.4.61', 'kjw_ips_event', 2, '科技网')
