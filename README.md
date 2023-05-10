# NsfocusAPI
NsfocusAPI
用来收集绿盟IPS威胁入侵的日志，并做一些基础的判断，比如
1.如果在24小时内，被IPS拦截了3次以上，则提取该攻击IP，并通过邮件发送给管理员。
2.每小时将IPS的威胁日志写入数据库，并根据是否有IPS威胁日志，判断IPS的工作状态，如果没有日志则发邮件提醒管理员去登录设备核查设备信息。

如果想要更多的判断维度可以在analyse_database()方法中修改相应的sql查询。
脚本还提供加黑名单的功能，通post_blacklist.py可以将需要加黑的IP加入黑名单。
