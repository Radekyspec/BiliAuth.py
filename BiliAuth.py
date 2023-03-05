import asyncio
import base64
import hashlib
import json
import time
import urllib.parse
from copy import deepcopy
from typing import Optional

import aiohttp
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


class BiliAuth:
    def __init__(self):
        self.username = None
        self.password = None
        self.region = None
        self.buvid = "XZ686A469231BE4F88E7CB07AE269E3BF4792"
        self.headers = {
            "env": "prod",
            "app-key": "android64",
            "Buvid": self.buvid,
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "zh-cn",
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 BiliDroid/7.16.0 (bbcallen@gmail.com) os/android model/ASUS_Z01QD "
                          "mobi_app/android build/7160300 channel/bili innerVer/7160310 osVer/6.0.1 network/2",
        }

    def set(self, username, password, region):
        self.username = username
        self.password = password
        self.region = region

    async def post(self, url: str, headers: Optional[dict] = None, payload: Optional[dict] = None):
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.post(url, data=payload) as resp:
                resp = await resp.text()
                resp = json.loads(resp)
        await session.close()
        return resp

    async def get(self, url: str, headers: Optional[dict] = None, payload: Optional[dict] = None):
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, params=payload) as resp:
                resp = await resp.text()
                resp = json.loads(resp)
        await session.close()
        return resp

    async def get_public_key(self):
        url = "https://passport.bilibili.com/x/passport-login/web/key"
        raw = await self.get(url)
        hash_value = raw["data"]["hash"]
        public_key = raw["data"]["key"]
        return hash_value, public_key

    async def password_encryption(self):
        hash_value, public_key = await self.get_public_key()
        public_key = RSA.importKey(public_key)
        raw_pass = hash_value + self.password
        cipher = PKCS1_v1_5.new(public_key)
        enc_pass = str(base64.b64encode(cipher.encrypt(raw_pass.encode("utf-8"))), "utf-8")
        return enc_pass

    @staticmethod
    def payload_sign(payload):
        """Create and return a new payload dict with default params.
        """
        default = {
            "access_key": "",
            "appkey": "783bbb7264451d82",
            "build": "7160300",
            "channel": "bili",
            "device": "phone",
            "mobi_app": "android",
            "platform": "android",
            "c_locale": "zh_CN",
            "s_locale": "zh_CN",
            "statistics": '{"appId":1,"platform":3,"version":"7.16.0","abtest":""}',
            "disable_rcmd": "0",
            "ts": int(time.time()),
        }
        r_payload = {**payload, **default}
        payload_keys = sorted(r_payload)
        payload = {}
        [payload.update({i: r_payload[i]}) for i in payload_keys]
        return payload

    @staticmethod
    def app_sign(payload) -> None:
        # app_secret = str(base64.b64decode("MjY1MzU4M2M4ODczZGVhMjY4YWI5Mzg2OTE4YjFkNjU=".encode("utf-8")), "utf-8")
        app_secret = "2653583c8873dea268ab9386918b1d65"
        query = urllib.parse.urlencode(payload)
        md5 = hashlib.md5()
        md5.update((query + app_secret).encode())
        sign = md5.hexdigest()
        payload.update({"sign": sign})

    async def account_login(self):
        url = "https://passport.bilibili.com/x/passport-login/oauth2/login"
        payload = {
            "captcha": "",
            "challenge": "",
            "cookies": "",
            "password": await self.password_encryption(),
            "permission": "ALL",
            "seccode": "",
            "subid": "1",
            "username": self.username,
            "validate": ""
        }
        payload = self.payload_sign(payload)
        self.app_sign(payload)
        resp = await self.post(url, self.headers, payload)
        return resp

    @staticmethod
    def reformat_keys(after_login):
        default = {
            "code": -404,
            "message": after_login
        }
        if "data" not in after_login or not isinstance(after_login["data"], dict):
            return default
        if (status := after_login["data"].get("status", None)) == 0:
            cookie_info = after_login["data"]["cookie_info"]["cookies"]
            cookies = ""
            for cookie in cookie_info:
                cookies += cookie["name"] + "=" + cookie["value"] + "; "
            cookies = cookies[:-2]
            keys_lib = {
                "code": 0,
                "message": "",
                "access_token": after_login["data"]["token_info"]["access_token"],
                "refresh_token": after_login["data"]["token_info"]["refresh_token"],
                "cookies": cookies
            }
            return keys_lib
        elif status == 2:
            # 需要验证手机
            keys_lib = {
                "code": 2,
                "message": after_login["data"]["message"],
                "url": after_login["data"]["url"]
            }
            return keys_lib
        elif after_login["code"] == -629:
            # 用户名或密码错误
            keys_lib = {
                "code": -629,
                "message": after_login["message"]
            }
            return keys_lib
        return default

    def is_ready(self) -> bool:
        return self.username is not None and self.password is not None and self.region is not None

    async def acquire(self, is_print=False, fallback_sms=False) -> dict:
        if not self.is_ready():
            print("未设置手机号/密码/国家代码")
            return {}
        after_login = await self.account_login()
        keys_lib = self.reformat_keys(after_login)
        if keys_lib["code"] != 0:
            print("账密登录失败, {}".format(keys_lib["message"]))
            if fallback_sms:
                print("尝试短信验证码登录...")
                keys_lib = self.reformat_keys(await self.login_sms())
        elif is_print:
            print("access_token:", keys_lib["access_token"])
            print("refresh_token:", keys_lib["refresh_token"])
            print("cookies:", keys_lib["cookies"])
        return keys_lib

    async def acquire_by_sms(self, is_print=False) -> dict:
        if not self.is_ready():
            print("未设置手机号/密码/国家代码")
            return {}
        after_login = await self.login_sms()
        keys_lib = self.reformat_keys(after_login)
        if is_print:
            print("access_token:", keys_lib["access_token"])
            print("refresh_token:", keys_lib["refresh_token"])
            print("cookies:", keys_lib["cookies"])
        return keys_lib

    async def login_sms(self, is_print=False):
        raw_payload = await self.send_sms()
        url = "https://passport.bilibili.com/x/passport-login/login/sms"
        payload = {
            "captcha_key": raw_payload["captcha_key"],
            "cid": raw_payload["cid"],
            "tel": raw_payload["tel"],
            "statistics": raw_payload["statistics"],
            "code": input("请输入收到的短信验证码: "),
        }
        payload = self.payload_sign(payload)
        self.app_sign(payload)
        resp = await self.post(url, self.headers, payload)
        if is_print:
            print(resp)
        return resp

    async def send_sms(self):
        url = "https://passport.bilibili.com/x/passport-login/sms/send"
        payload = {
            "cid": "86",
            "tel": self.username,
        }
        t_payload = self.payload_sign(payload)
        self.app_sign(t_payload)
        resp = await self.post(url, self.headers, t_payload)
        while not resp["data"]["captcha_key"]:
            t_payload = deepcopy(payload)
            recaptcha = (list(filter(lambda x: x.startswith("recaptcha_token"),
                                     resp["data"]["recaptcha_url"].split("&")))[0]).split("=")[1]
            gt = (list(filter(lambda x: x.startswith("gee_gt"),
                              resp["data"]["recaptcha_url"].split("&")))[0]).split("=")[1]
            challenge = (list(filter(lambda x: x.startswith("gee_challenge"),
                              resp["data"]["recaptcha_url"].split("&")))[0]).split("=")[1]
            t_payload["recaptcha_token"] = recaptcha
            challenge, validate = await self.pass_captcha(gt, challenge)
            t_payload["gee_challenge"] = challenge
            t_payload["gee_validate"] = validate
            t_payload["gee_seccode"] = t_payload["gee_validate"] + "|jordan"
            t_payload = self.payload_sign(t_payload)
            self.app_sign(t_payload)
            resp = await self.post(url, self.headers, t_payload)
            print(resp)
        payload["captcha_key"] = resp["data"]["captcha_key"]
        return payload

    async def pass_captcha(self, gt, challenge):
        resp = await self.post("http://www.damagou.top/apiv1/jiyanRecognize.html",
                               self.headers,
                               {
                                   "userkey": "b39d890ef3e1da0d52a5453d3465cf84",
                                   "gt": gt,
                                   "challenge": challenge,
                                   "isJson": "2"
                               })
        c_and_v = resp["data"].split("|")
        if len(c_and_v) != 2:
            return await self.pass_captcha(gt, challenge)
        return tuple(c_and_v)


if __name__ == '__main__':
    u = 15078863008
    p = "HELLOaaa20031227"
    r = "86"
    auth = BiliAuth()
    auth.set(u, p, r)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(auth.acquire(is_print=True))
    input("按任意键退出...")
