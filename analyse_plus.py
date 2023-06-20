#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
import datetime
import pymysql
from jinja2 import Environment, FileSystemLoader
from nsfocus_restfulapi import NsfocusAPI
from pprint import pprint


class NewNsfocusAPI(NsfocusAPI):
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
            # sql = "select sip, count(*) from {} where event_time  BETWEEN NOW() - INTERVAL %s HOUR AND NOW()".format(
            #     tb_name)
            sql = "select sip, scountry,count(*) from {} where event_time  BETWEEN NOW() - INTERVAL %s HOUR AND NOW()".format(
                tb_name)
            # sql = "select * from ips_event where event_time  BETWEEN NOW() - INTERVAL %s HOUR AND NOW()"
            sql += " AND threat_level > 1"
            sql += " AND scountry != “中国”"
            sql += " AND scountry != “--”"
            sql += ' AND and event not LIKE " % {} % "'.format('扫描')
            sql += " GROUP BY sip, scountry"
            sql += " having count(*) > 0"

            mycursor.execute(sql,
                             time_step
                             )
            # 获取结果
            myresult = mycursor.fetchall()

            # 创建一个字典用于存放数据库的返回结果，这个结果后面还会被jinja2用于生成邮件内容用
            result_dict = {}
            # 输出结果
            for x in myresult:
                result_dict[x[0]] = x[1]
                print(x)
            pprint(result_dict)

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
        # result = template.render(policy=result_dict, s_time=s_datetime.strftime("%Y-%m-%d %H:%M:%S"),
        #                          e_time=e_datetime.strftime("%Y-%m-%d %H:%M:%S"), time_interval=time_step)
        #
        # pprint(result)

        # # 发送告警邮件
        # if myresult:
        #     self.send_mail(
        #         f'{current_time}_{location}IPS {ips_ip}_拦截情况',
        #         result
        #     )
        # else:
        #     self.send_mail(
        #         f'{current_time}_{location}IPS {ips_ip}_拦截情况',
        #         f'{current_time}_{location}IPS {ips_ip} 无威胁拦截的告警日志！'
        #     )


if __name__ == '__main__':
    login_account = 'wuzp'
    loging_password = '6dd3cda8f68bc2b6701ba3e4e83800991ad02be83419af8cc500e20d93432e5c14f345139d273' \
                      '08b9f6ffb5c2d17ebc2f578d4798ba066e9970038a3f055a8b504538696491a6bffce9f1330698974d7' \
                      'd417eeb85f6fd21c86e663e4ea8eae91f0387dc4b2de19edb1c4979b1b31a61c3fe82c9546efb1a50f2956b' \
                      '8bd10fc39074dda3a7b6cd0902f4c5db4fa18a17d11d6cfe7f8a4524dfa78f5cc8c3a19972010a06bf1995c076' \
                      'ab0b01856aed8e189286f19447aab53b1dd4103296e249d74b9d21f27e043045757fcf56bb67a57c343435a2f374' \
                      'd265477634f704feeb744e2c7ea77c28dd35bebe0fb156910ef6519c15513644bc92f495fe5541f4077'

    myobj = NewNsfocusAPI(login_account, loging_password)

    arg_dict = {
        # '10.167.68.9': ['qc_ips_event', 16, '金桥全创'],
        # '10.168.46.33': ['zq_ips_event', 2, '金桥网上交易'],
        # '10.168.224.241': ['oa_ips_event', 2, '金桥OA区'],
        '10.192.4.61': ['kjw_ips_event', 2, '科技网'],
        # '10.190.204.66': ['wp_ips_event', 16, '宛平南路'],
    }

    # def analyse_database(self, ips_ip, tb_name, attack_number, location, time_step=24):
    for k, v in arg_dict.items():
        myobj.analyse_database(k, v[0], v[1], v[2])
