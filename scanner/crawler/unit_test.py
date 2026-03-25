from urllib.parse import urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup
import requests
from playwright.async_api import async_playwright

def normalize_url(url:str):
    parsed = urlparse(url)
    return parsed , urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))

def get_params(url:str):
    return list(parse_qs(urlparse(url).query).keys())

def check_same_domain(base_url:str, url):
    return urlparse(url).netloc == base_url

def extract_links(url:str, base_url:str):
    html = requests.get(url).text
    soup = BeautifulSoup(html, 'lxml')
    links = set()

    for tag in soup.find_all('a', href=True):
        href = tag['href']

        if check_same_domain(base_url, href):
            links.add(href)
    
    return links

async def main(url:str):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        new_page = await context.new_page()

        await new_page.goto(url)

if __name__ == "__main__":
    url = "https://earndot.online/login?email=LamaJack#checkin"
    parsed, unparsed = normalize_url(url)
    # print(f"Parsed: {parsed}")
    # print(f"Unparsed: {unparsed}")

    # for i in get_params(url):
    #     print(i)
    links = extract_links("https://earndot.online/", base_url="https://earndot.online/")
    print(len(links))