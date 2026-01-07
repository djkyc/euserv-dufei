import os
import sys
import io
import re
import json
import time
import threading
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from PIL import Image
import ddddocr
import requests
from bs4 import BeautifulSoup
from imap_tools import MailBox, AND

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 兼容新版 Pillow
if not hasattr(Image, 'ANTIALIAS'):
    Image.ANTIALIAS = Image.Resampling.LANCZOS

# 全局 OCR 实例（线程安全）
ocr = ddddocr.DdddOcr()
ocr_lock = threading.Lock()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"

# ============== 配置数据类 ==============
class AccountConfig:
    """单个账号配置"""
    def __init__(self, email, password, imap_server='imap.gmail.com', email_password=''):
        self.email = email
        self.password = password
        self.imap_server = imap_server
        self.email_password = email_password if email_password else password


class GlobalConfig:
    """全局配置"""
    def __init__(self, telegram_bot_token="", telegram_chat_id="", max_workers=3, max_login_retries=3):
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.max_workers = max_workers
        self.max_login_retries = max_login_retries


# ============== 配置区 ==============
# 全局配置
GLOBAL_CONFIG = GlobalConfig(
    telegram_bot_token=os.getenv("TG_BOT_TOKEN"),
    telegram_chat_id=os.getenv("TG_CHAT_ID"),
    max_workers=3,  # 建议不超过5，避免触发频率限制
    max_login_retries=5
)


# 账号列表配置
ACCOUNTS = [
    AccountConfig(
        email=os.getenv("EUSERV_EMAIL"),
        password=os.getenv("EUSERV_PASSWORD"),
        imap_server="imap.gmail.com",
        email_password=os.getenv("EMAIL_PASS")  # Gmail 应用专用密码
    ),
]

# ====================================


def recognize_and_calculate(captcha_image_url: str, session: requests.Session) -> Optional[str]:
    """识别并计算验证码（线程安全）"""
    logger.info("正在处理验证码...")
    try:
        logger.debug("尝试自动识别验证码...")
        response = session.get(captcha_image_url)
        img = Image.open(io.BytesIO(response.content)).convert('RGB')
        
        # 颜色过滤（保留橙色文字，噪点变白）
        pixels = img.load()
        width, height = img.size
        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                if not (r > 200 and 100 < g < 220 and b < 80):
                    pixels[x, y] = (255, 255, 255)
        
        # 转灰度 + 二值化
        img = img.convert('L')
        threshold = 200
        img = img.point(lambda x: 0 if x < threshold else 255, '1')
        
        # 去边框
        border = 10
        pixels = img.load()
        for x in range(width):
            for y in range(height):
                if x < border or x >= width - border or y < border or y >= height - border:
                    pixels[x, y] = 255
        
        output = io.BytesIO()
        img.save(output, format='PNG')
        processed_bytes = output.getvalue()
        
        # OCR 识别（加锁保证线程安全）
        with ocr_lock:
            text = ocr.classification(processed_bytes).strip()
        
        logger.debug(f"OCR 识别文本: {text}")

        # 预处理：去除空格、大小写统一（右边字母转大写）
        raw_text = text.strip()
        text = raw_text.replace(' ', '').upper()  # 上面的正则要用大写匹配

        # 情况1：纯字母数字组合（没有运算符），直接返回原始识别文本（保留大小写）
        if re.fullmatch(r'[A-Z0-9]+', text):
            logger.info(f"检测到纯字母数字验证码: {raw_text}")
            return raw_text.strip()  # 保留原始大小写返回

        # 情况2：尝试解析四则运算
        # 支持的运算符：+ - * × x X / ÷
        pattern = r'^(\d+)([+\-*/×xX÷/])(\d+|[A-Z])$'
        match = re.match(pattern, text)

        if not match:
            logger.warning(f"无法解析验证码格式（非纯字母数字也非运算式）: {raw_text}")
            return raw_text.strip()  # 还是返回原始文本，交给上层处理或重试

        left_str, op, right_str = match.groups()
        left = int(left_str)

        # 处理右边：数字或字母（A=10 ... Z=35）
        if right_str.isdigit():
            right = int(right_str)
        else:  # 一定是单个大写字母（因为正则限制了）
            if 'A' <= right_str <= 'Z':
                right = ord(right_str) - ord('A') + 10
            else:
                logger.warning(f"右边字符无效: {right_str}")
                return raw_text.strip()

        # 根据运算符计算
        if op in {'*', '×', 'X', 'x'}:
            result = left * right
            op_name = '乘'
        elif op == '+':
            result = left + right
            op_name = '加'
        elif op == '-':
            result = left - right
            op_name = '减'
        elif op in {'/', '÷'}:
            if right == 0:
                logger.warning("除数为0，无法计算")
                return raw_text.strip()
            if left % right != 0:  # 如果不是整除，很多网站会拒绝非整数答案
                logger.warning(f"除法非整除: {left} ÷ {right} = {left / right}")
                return raw_text.strip()
            result = left // right
            op_name = '除'
        else:
            logger.warning(f"未知运算符: {op}")
            return raw_text.strip()

        logger.info(f"验证码计算: {left} {op_name} {right_str} = {result}")
        return str(result)
    except Exception as e:
        logger.error(f"验证码识别错误发生错误: {e}", exc_info=True)
        return None


def get_euserv_pin(email: str, email_password: str, imap_server: str) -> Optional[str]:
    """从邮箱获取 EUserv PIN 码"""
    try:
        logger.info(f"正在从邮箱 {email} 获取 PIN 码...")
        with MailBox(imap_server).login(email, email_password) as mailbox:
            for msg in mailbox.fetch(AND(from_='no-reply@euserv.com', body='PIN'), limit=1, reverse=True):
                logger.debug(f"找到邮件: {msg.subject}, 收件时间: {msg.date_str}")
                
                match = re.search(r'PIN:\s*\n?(\d{6})', msg.text)
                if match:
                    pin = match.group(1)
                    logger.info(f"✅ 提取到 PIN 码: {pin}")
                    return pin
                else:
                    match_fallback = re.search(r'(\d{6})', msg.text)
                    if match_fallback:
                        pin = match_fallback.group(1)
                        logger.warning(f"⚠️ 备选匹配 PIN 码: {pin}")
                        return pin
                    
            logger.warning("❌ 未找到符合条件的 EUserv 邮件")
            return None

    except Exception as e:
        logger.error(f"获取 PIN 码时发生错误: {e}", exc_info=True)
        return None


class EUserv:
    """EUserv 操作类"""
    
    def __init__(self, config: AccountConfig):
        self.config = config
        self.session = requests.Session()
        self.sess_id = None
        self.c_id = None
        
    def login(self) -> bool:
        """登录 EUserv（支持验证码和 PIN）"""
        logger.info(f"正在登录账号: {self.config.email}")
        
        headers = {
            'user-agent': USER_AGENT,
            'origin': 'https://www.euserv.com'
        }
        url = "https://support.euserv.com/index.iphp"
        captcha_url = "https://support.euserv.com/securimage_show.php"
        
        try:
            # 获取 sess_id
            sess = self.session.get(url, headers=headers)
            sess_id_match = re.search(r'sess_id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{30,100})["\']?', sess.text)
            if not sess_id_match:
                sess_id_match = re.search(r'sess_id=([a-zA-Z0-9]{30,100})', sess.text)
            
            if not sess_id_match:
                logger.error("❌ 无法获取 sess_id")
                return False
            
            sess_id = sess_id_match.group(1)
            logger.debug(f"获取到 sess_id: {sess_id[:20]}...")
            
            # 访问 logo
            logo_png_url = "https://support.euserv.com/pic/logo_small.png"
            self.session.get(logo_png_url, headers=headers)
            
            # 提交登录表单
            login_data = {
                'email': self.config.email,
                'password': self.config.password,
                'form_selected_language': 'en',
                'Submit': 'Login',
                'subaction': 'login',
                'sess_id': sess_id
            }
            
            logger.debug("提交登录表单...")
            response = self.session.post(url, headers=headers, data=login_data)
            response.raise_for_status()

            #解析返回页面
            soup = BeautifulSoup(response.text, "html.parser")

            # 检查登录错误
            if 'Please check email address/customer ID and password' in response.text:
                logger.error("❌ 用户名或密码错误")
                return False
            if 'kc2_login_iplock_cdown' in response.text:
                logger.error("❌ 密码错误次数过多，账号被锁定，请5分钟后重试")
                return False
            
            # 处理验证码
            if 'captcha' in response.text.lower():
                logger.info("⚠️ 需要验证码，正在识别...")
                captcha_code = recognize_and_calculate(captcha_url, self.session)
                
                if not captcha_code:
                    logger.error("❌ 验证码识别失败")
                    return False
                
                captcha_data = {
                    'subaction': 'login',
                    'sess_id': sess_id,
                    'captcha_code': captcha_code
                }
                
                response = self.session.post(url, headers=headers, data=captcha_data)
                response.raise_for_status()
                
                if 'captcha' in response.text.lower():
                    logger.error("❌ 验证码错误")
                    return False
            
            # 处理 PIN 验证
            if 'PIN that you receive via email' in response.text:
                self.c_id = soup.find("input", {"name": "c_id"})["value"]
                logger.info("⚠️ 需要 PIN 验证")
                
                # 延时60秒等待邮箱
                time.sleep(60)
                
                pin = get_euserv_pin(
                    self.config.email,
                    self.config.email_password,
                    self.config.imap_server
                )
                
                if not pin:
                    logger.error("❌ 获取 PIN 码失败")
                    return False
                
                login_confirm_data = {
                    'pin': pin,
                    'sess_id': sess_id,
                    'Submit': 'Confirm',
                    'subaction': 'login',
                    'c_id': self.c_id,
                }
                response = self.session.post(url, headers=headers, data=login_confirm_data)
                response.raise_for_status()


            # 检查登录成功
            success_checks = [
                'Hello' in response.text,
                'Confirm or change your customer data here' in response.text,
                'logout' in response.text.lower() and 'customer' in response.text.lower()
            ]
            
            if any(success_checks):
                logger.info(f"✅ 账号 {self.config.email} 登录成功")
                self.sess_id = sess_id
                return True
            else:
                logger.error(f"❌ 账号 {self.config.email} 登录失败")
                return False
                
        except Exception as e:
            logger.error(f"❌ 登录过程出现异常: {e}", exc_info=True)
            return False


# 执行脚本部分保持不变
