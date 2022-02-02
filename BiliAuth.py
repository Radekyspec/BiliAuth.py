import aiohttp
import base64
import hashlib
import json
import random
import time
import urllib.parse
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from typing import Optional


class BiliAuth:
    @classmethod
    def set(cls, username, password):
        cls.username = username
        cls.password = password

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

    def fake_buvid(self):
        mac_list = []
        for i in range(1, 7):
            rand_str = "".join(random.sample("0123456789abcdef", 2))
            mac_list.append(rand_str)
        rand_mac = ":".join(mac_list)
        md5 = hashlib.md5()
        md5.update(rand_mac.encode())
        md5_mac_str = md5.hexdigest()
        md5_mac = list(md5_mac_str)
        fake_mac = ("XY" + md5_mac[2] + md5_mac[12] + md5_mac[22] + md5_mac_str).upper()
        return fake_mac

    def payload_sign(self, payload):
        default = {
            "access_key": "",
            "actionKey": "appkey",
            "appkey": "783bbb7264451d82",
            "build": "6550400",
            "channel": "bili",
            "device": "phone",
            "mobi_app": "android",
            "platform": "android",
            "ts": str(time.time()).split(".")[0],
        }
        raw_payload = {**payload, **default}
        raw_payload_keys = sorted(raw_payload.keys())
        payload = {}
        for i in raw_payload_keys:
            payload.update({i: raw_payload[i]})
        return payload

    def app_sign(self, payload):
        # app_secret = str(base64.b64decode("MjY1MzU4M2M4ODczZGVhMjY4YWI5Mzg2OTE4YjFkNjU=".encode("utf-8")), "utf-8")
        app_secret = "2653583c8873dea268ab9386918b1d65"
        query = urllib.parse.urlencode(payload)
        md5 = hashlib.md5()
        md5.update((query + app_secret).encode())
        sign = md5.hexdigest()
        return sign

    async def account_login(self):
        url = "https://passport.bilibili.com/x/passport-login/oauth2/login"
        headers = {
            "env": "prod",
            "APP-KEY": "android",
            "Buvid": self.fake_buvid(),
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "zh-cn",
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 BiliDroid/6.55.0 (bbcalllen@gmail.com) os/android model/MuMu mobi_app/android build/6550400 channel/bili innerVer/6550400 osVer/7.1.2 network/2",
        }
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
        sign = self.app_sign(payload)
        payload.update({"sign": sign})
        resp = await self.post(url, headers, payload)
        return resp

    def reformat_keys(self, after_login):
        if after_login["data"] and after_login["data"]["status"] == 0:
            cookie_info = after_login["data"]["cookie_info"]["cookies"]
            cookies = ""
            for cookie in cookie_info:
                cookies += cookie["name"] + "=" + cookie["value"] + "; "
            cookies = cookies[:-2]
            keys_lib = {
                "code": 0,
                "message": "",
                "access_key": after_login["data"]["token_info"]["access_token"],
                "refresh_key": after_login["data"]["token_info"]["refresh_token"],
                "cookies": cookies
            }
            return keys_lib
        elif after_login["data"] and after_login["data"]["status"] == 2:
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
                "code": after_login["code"],
                "message": after_login["message"]
            }
            return keys_lib

    async def acquire(self, is_print=True):
        after_login = await self.account_login()
        keys_lib = self.reformat_keys(after_login)
        if is_print:
            print(keys_lib)
            return keys_lib
        else:
            return keys_lib
