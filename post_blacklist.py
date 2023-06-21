#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
from pprint import pprint
from nsfocus_restfulapi import NsfocusAPI
from device_info import device_dict

login_account = 'wuzp'
loging_password = '6dd3cda8f68bc2b6701ba3e4e83800991ad02be83419af8cc500e20d93432e5c14f345139d273' \
                  '08b9f6ffb5c2d17ebc2f578d4798ba066e9970038a3f055a8b504538696491a6bffce9f1330698974d7' \
                  'd417eeb85f6fd21c86e663e4ea8eae91f0387dc4b2de19edb1c4979b1b31a61c3fe82c9546efb1a50f2956b' \
                  '8bd10fc39074dda3a7b6cd0902f4c5db4fa18a17d11d6cfe7f8a4524dfa78f5cc8c3a19972010a06bf1995c076' \
                  'ab0b01856aed8e189286f19447aab53b1dd4103296e249d74b9d21f27e043045757fcf56bb67a57c343435a2f374' \
                  'd265477634f704feeb744e2c7ea77c28dd35bebe0fb156910ef6519c15513644bc92f495fe5541f4077'

"""
183.15.176.216
121.37.182.135
"""

myobj = NsfocusAPI(login_account, loging_password)
for k, v in device_dict.items():
    post_result, post_content = myobj.post_blacklist(k, '42.192.79.197')
    pprint(post_content)
    apply_result, apply_content = myobj.post_applyconfig(k)
    pprint(apply_content)
