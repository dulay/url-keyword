import requests
from bs4 import BeautifulSoup
import re
import string
from urllib.parse import urljoin

def clean_and_split_keywords(keyword_str):
    s = re.sub(r"[\s、;；，,|/\\\n\r]+", ",", str(keyword_str))
    s = s.translate(str.maketrans('', '', string.punctuation))
    keywords = [kw.strip() for kw in s.split(",") if kw.strip()]
    return keywords

def clean_text(text):
    text = text.lower()
    text = re.sub(r'[' + string.punctuation + r'\s]+', ' ', text)
    return text

def detect_redirect_type(resp, html):
    if resp.is_redirect or resp.is_permanent_redirect:
        return "http_redirect"
    meta = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*(\d+)\s*;\s*url=([^"\'> ]+)',
        html, re.IGNORECASE)
    if meta:
        delay = int(meta.group(1))
        return "meta_immediate" if delay == 0 else "meta_delayed"
    js = re.search(r'window\.location(?:\.href)?\s*=\s*[\'"]([^\'"]+)[\'"]', html)
    if js:
        before = html[:js.start()]
        if re.search(r'setTimeout\s*\(', before):
            return "js_delayed"
        else:
            return "js_immediate"
    js2 = re.search(r'location\.(?:replace|assign)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', html)
    if js2:
        before = html[:js2.start()]
        if re.search(r'setTimeout\s*\(', before):
            return "js_delayed"
        else:
            return "js_immediate"
    js3 = re.search(r'setTimeout\s*\([^,]+,\s*(\d+)\s*\)\s*;?\s*window\.location(?:\.href)?\s*=\s*[\'"]([^\'"]+)[\'"]', html)
    if js3:
        return "js_delayed"
    return "none"

def get_final_url_content(url, max_depth=5, timeout=10, headers=None, redirect_chain=None):
    if redirect_chain is None:
        redirect_chain = []
    if max_depth <= 0:
        return "", url, 599, redirect_chain, "too_many_redirects", 0

    if headers is None:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
        html = resp.text
        final_url = resp.url
        status_code = resp.status_code
        page_size = len(html.encode(resp.encoding or "utf-8"))
        redirect_type = detect_redirect_type(resp, html)
        redirect_chain.append({"url": final_url, "type": redirect_type, "size": page_size})

        # Meta Refresh 跳转
        meta = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*(\d+)\s*;\s*url=([^"\'> ]+)',
            html, re.IGNORECASE)
        if meta:
            next_url = meta.group(2).strip()
            next_url = urljoin(final_url, next_url)
            return get_final_url_content(next_url, max_depth-1, timeout, headers, redirect_chain)

        # JS 跳转
        js_patterns = [
            r'window\.location(?:\.href)?\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'location\.(?:replace|assign)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
        ]
        for pattern in js_patterns:
            js = re.search(pattern, html, re.IGNORECASE)
            if js:
                next_url = js.group(1).strip()
                next_url = urljoin(final_url, next_url)
                return get_final_url_content(next_url, max_depth-1, timeout, headers, redirect_chain)

        return html, final_url, status_code, redirect_chain, redirect_type, page_size
    except Exception as e:
        return "", url, 598, redirect_chain, "request_error", 0

def format_page_size(size_bytes):
    if size_bytes >= 1024*1024:
        return f"{size_bytes//1024//1024}M"
    elif size_bytes >= 1024:
        return f"{size_bytes//1024}K"
    else:
        return f"{size_bytes}B"

def show_redirect_type(type_str):
    if type_str in ['meta_immediate','js_immediate','http_redirect']:
        return "立即跳转"
    elif type_str in ['meta_delayed','js_delayed']:
        return "延迟跳转"
    elif type_str == 'none':
        return "无跳转"
    else:
        return type_str

def keyword_match_result(text, keyword_str):
    keywords = clean_and_split_keywords(keyword_str)
    total = len(keywords)
    if total == 0:
        return {"match": False, "ratio": 0, "matched": [], "match_info": ""}
    text_clean = clean_text(text)
    matched = [kw for kw in keywords if kw and clean_text(kw) in text_clean]
    matched_num = len(matched)
    ratio = matched_num / total if total else 0
    if ratio > 0.7:
        logic = True
    elif ratio < 0.5:
        logic = False
    else:
        # 50%-70%之间，整体比对
        logic = clean_text(keyword_str) in text_clean
    match_info = f"{matched_num}/{total} ({int(ratio*100)}%)，匹配：{'，'.join(matched)}"
    return {"match": logic, "ratio": int(ratio*100), "matched": matched, "match_info": match_info}

def check_keyword_in_url(url, keyword_str):
    """
    先对原始URL比对，再对跳转最终页面比对。任一命中则视为命中，提升可信度。
    返回dict，含两次比对详情、最终可信判断、跳转等信息。
    """
    try:
        # 原始页面抓取与比对
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        resp = requests.get(url, timeout=10, allow_redirects=True, headers=headers)
        html = resp.text
        http_code = resp.status_code
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(separator=' ', strip=True)
        title1 = soup.title.string.strip() if soup.title and soup.title.string else ""
        size1 = len(html.encode(resp.encoding or "utf-8"))
        match1 = keyword_match_result(text, keyword_str)

        # 跳转后页面抓取与比对
        html2, final_url, http_code2, redirect_chain, final_redirect_type, page_size2 = get_final_url_content(
            url, timeout=10)
        if html2:
            soup2 = BeautifulSoup(html2, "html.parser")
            text2 = soup2.get_text(separator=' ', strip=True)
            title2 = soup2.title.string.strip() if soup2.title and soup2.title.string else ""
            match2 = keyword_match_result(text2, keyword_str)
        else:
            title2 = ""
            match2 = {"match": False, "ratio": 0, "matched": [], "match_info": ""}

        # 可信度提升逻辑：只要有一次命中即判为“仍存在”，都未命中为“已删除”
        if match1["match"] or match2["match"]:
            result = "仍存在"
            ratio = max(match1["ratio"], match2["ratio"])
            match_info = f"原始:{match1['match_info']}；跳转:{match2['match_info']}"
        else:
            result = "已删除"
            ratio = 0
            match_info = f"原始:{match1['match_info']}；跳转:{match2['match_info']}"

        # 若两次请求都失败
        if not html and not html2:
            result = "核查失败"

        return {
            "result": result,
            "url": url,
            "title": title1 or title2,
            "http_code": http_code2 if http_code2 != 0 else http_code,
            "ratio": ratio,
            "match_info": match_info,
            "final_redirect_type": show_redirect_type(final_redirect_type),
            "page_size": format_page_size(page_size2),
            "redirect_chain": [
                {
                    "url": step["url"],
                    "type": show_redirect_type(step["type"]),
                    "size": format_page_size(step["size"])
                } for step in redirect_chain
            ],
            "detail": {
                "origin": {
                    "title": title1,
                    "http_code": http_code,
                    "match": match1["match"],
                    "ratio": match1["ratio"],
                    "match_info": match1["match_info"],
                    "page_size": format_page_size(size1)
                },
                "final": {
                    "url": final_url,
                    "title": title2,
                    "http_code": http_code2,
                    "match": match2["match"],
                    "ratio": match2["ratio"],
                    "match_info": match2["match_info"],
                    "page_size": format_page_size(page_size2),
                    "redirect_chain": [
                        {
                            "url": step["url"],
                            "type": show_redirect_type(step["type"]),
                            "size": format_page_size(step["size"])
                        } for step in redirect_chain
                    ],
                    "final_redirect_type": show_redirect_type(final_redirect_type)
                }
            }
        }
    except Exception as e:
        http_code = getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0
        return {
            "result": "核查失败",
            "url": url,
            "title": "",
            "http_code": http_code,
            "ratio": 0,
            "match_info": "",
            "final_redirect_type": "请求错误",
            "page_size": "0B",
            "redirect_chain": [],
            "detail": {}
        }