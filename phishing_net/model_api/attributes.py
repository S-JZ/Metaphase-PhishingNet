import xgboost as xgb
import os
import environ
import requests
from subprocess import *
from bs4 import BeautifulSoup
import json
from nltk.stem.porter import PorterStemmer
import base64
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import tldextract
import favicon
import datetime
from dateutil.relativedelta import relativedelta
import whois
import pandas as pd
import string
from datetime import date
import xgboost as xgb
import pickle
import nltk
nltk.download('stopwords')
from nltk.corpus import stopwords
import string
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
# !pip install python-whois
# !pip install tldextract
# !apt-get install whois
# !pip install python-whois
# !pip install favicon


# Check for IP Address and Hexa Code
env = environ.Env(
    # set casting, default value
    DEBUG=(bool, False)
)
# reading .env file
environ.Env.read_env()





def having_ip_add(url):
    import string
    index = url.find("://")
    split_url = url[index+3:]
    # print(split_url)
    index = split_url.find("/")
    split_url = split_url[:index]
    # print(split_url)
    split_url = split_url.replace(".", "")
    # print(split_url)
    counter_hex = 0
    for i in split_url:
        if i in string.hexdigits:
            counter_hex += 1

    total_len = len(split_url)
    having_Address = 1
    if counter_hex >= total_len:
        having_Address = -1

    return having_Address


# Check for URL Length

def find_url_len(url):
    URL_Length = 1
    if len(url) >= 75:
        URL_Length = -1
    elif len(url) >= 54 and len(url) <= 74:
        URL_length = 0

    return URL_Length


# Check for url shortner

def shortened_url(url):
    famous_short_urls = ["bit.ly", "tinyurl.com", "goo.gl",
                         "rebrand.ly", "t.co", "youtu.be",
                         "ow.ly", "w.wiki", "is.gd"]

    url_domain = url.split("://")[1]
    url_domain = url_domain.split("/")[0]
    check = 1
    if url_domain in famous_short_urls:
        check = -1

    return (check)


# check for url in url

def find_at(url):
    atrate = 1
    index = url.find("@")
    if index != -1:
        atrate = -1

    return (atrate)


# Redirecting URL check

def find_redirect(url):
    index = url.find("://")
    split_url = url[index+3:]
    check = 1
    index = split_url.find("//")
    if index != -1:
        check = -1

    return (check)


# - in domain check

def find_prefix(url):
    index = url.find("://")
    split_url = url[index+3:]
    # print(split_url)
    index = split_url.find("/")
    split_url = split_url[:index]
    # print(split_url)
    check = 1
    index = split_url.find("-")
    # print(index)
    if index != -1:
        check = -1

    return (check)


# Presence of multiple domains

def find_multi_domains(url):
    url = url.split("://")[1]
    url = url.split("/")[0]
    index = url.find("www.")
    split_url = url
    if index != -1:
        split_url = url[index+4:]
    # print(split_url)
    index = split_url.rfind(".")
    # print(index)
    if index != -1:
        split_url = split_url[:index]
    # print(split_url)
    check = 0
    for i in split_url:
        if i == ".":
            check += 1

    find = 1
    if check == 2:
        find = 0
    elif check >= 3:
        find = -1

    return (find)


# Certification and authority check

def find_authority(url):
    index_https = url.find("https://")
    valid_auth = ["GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign", "LinkedIn", "Sectigo",
                  "Symantec", "DigiCert", "Network Solutions", "RapidSSLonline", "SSL.com", "Entrust Datacard", "Google", "Facebook"]
    cmd = "curl -vvI "+ url
    #print()
    output = Popen(cmd, shell=True, stderr=PIPE).stderr
    output = output.read()
    std_out = output.decode('UTF-8')
    index = std_out.find("O=")

    split = std_out[index+2:]
    index_sp = split.find(" ")
    cur = split[:index_sp]

    index_sp = cur.find(",")
    if index_sp != -1:
        cur = cur[:index_sp]

    check = -1
    if cur in valid_auth and index_https != -1:
        check = 1

    return check


# send email check

def check_submit_to_email(url):
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    # Check if no form tag
    form_opt = str(soup.form)
    idx = form_opt.find("mail()")
    if idx == -1:
        idx = form_opt.find("mailto:")

    if idx == -1:
        return 1
    return -1


# check if https is part of domain

def existence_token(url):
    # Assumption - pagename cannot start with this token
    iul = url.find("//https")
    if(iul == -1):
        return 1
    else:
        return -1


# domain registration length

def register_len(url):
    extract = tldextract.extract(url)
    ul = extract.domain + "." + extract.suffix
    try:
        wres = whois.whois(url)
        f = wres["Creation Date"][0]
        s = wres["Registry Expiry Date"][0]
        if(s > f + relativedelta(months=+12)):
            return 1
        else:
            return -1
    except:
        return -1


# sfh check

def sfh_check(url):
    program_html = requests.get(url).text
    s = BeautifulSoup(program_html, "lxml")
    try:
        fin = str(s.form)
        ac = fin.find("action")
        if(ac != -1):
            i1 = fin[ac:].find(">")
            u1 = fin[ac+8:i1-1]
            if(u1 == "" or u1 == "about:blank"):
                return -1
            el1 = tldextract.extract(url)
            u_page = el1.domain
            el2 = tldextract.extract(u1)
            u_sfh = el2.domain
            if u_page in u_sfh:
                return 1
            return 0
        else:
            # Check this point
            return 1
    except:
        # Check this point
        return 1


# check %age of tags in url

def tags(url):
    program_html = requests.get(url).text
    s = BeautifulSoup(program_html, "lxml")
    mtags = s.find_all('Meta')
    ud = tldextract.extract(url)
    u_page = ud.domain
    mcount = 0
    for i in mtags:
        u1 = i['href']
        currpage = tldextract.extract(u1)
        u1_page = currpage.domain
        if currpage not in u1_page:
            mcount += 1
    scount = 0
    stags = s.find_all('Script')
    for j in stags:
        u1 = j['href']
        currpage = tldextract.extract(u1)
        u1_page = currpage.domain
        if currpage not in u1_page:
            scount += 1
    count = 0
    tags = s.find_all('Link')
    for k in tags:
        u1 = k['href']
        currpage = tldextract.extract(u1)
        u1_page = currpage.domain
        if currpage not in u1_page:
            count += 1
    percm_tag = 0
    percs_tag = 0
    percl_tag = 0

    if len(mtags) != 0:
        percm_tag = (mcount*100)//len(mtags)
    if len(stags) != 0:
        percs_tag = (scount*100)//len(stags)
    if len(tags) != 0:
        percl_tag = (count*100)//len(tags)

    if(percm_tag+percs_tag+percl_tag < 17):
        return 1
    elif(percm_tag+percs_tag+percl_tag <= 81):
        return 0
    return -1


# redirect url check

def url_valid(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except:
        return False




# statistical report

def statistical_report(url):

    headers = {
        'format': 'json',
    }

    def get_url_with_ip(URI):
        """Returns url with added URI for request"""
        url = "http://checkurl.phishtank.com/checkurl/"
        new_check_bytes = URI.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        url += base64_new_check
        return url

    def send_the_request_to_phish_tank(url, headers):
        """This function sends a request."""
        response = requests.request("POST", url=url, headers=headers)
        return response

    url = get_url_with_ip(url)
    r = send_the_request_to_phish_tank(url, headers)

    def parseXML(xmlfile):

        root = ET.fromstring(xmlfile)
        verified = False
        for item in root.iter('verified'):
            if item.text == "true":
                verified = True
                break

        phishing = False
        if verified:
            for item in root.iter('valid'):
                if item.text == "true":
                    phishing = True
                    break

        return phishing

    inph_Tank = parseXML(r.text)
    # print(r.text)

    if inph_Tank:
        return -1
    return 1


# check page rank

def page_rank(url):
    page_Rank_Api = os.getenv('API_KEY')
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    headers = {'API-OPR': page_Rank_Api}
    domain = url_ref
    req_url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    request = requests.get(req_url, headers=headers)
    result = request.json()
    print(result)
    stats = result['response'][0]['page_rank_decimal']
    if type(stats) == str:
        stats = 0

    if stats < 2:
        return -1
    return 1


# check page traffic

def web_traffic(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    html_content = requests.get(
        "https://www.alexa.com/siteinfo/" + url_ref).text
    soup = BeautifulSoup(html_content, "lxml")
    stat = str(soup.find('div', {'class': "rankmini-rank"})
               )[42:].split("\n")[0].replace(",", "")

    if not stat.isdigit():
        return -1

    stat = int(stat)
    if stat < 100000:
        return 1
    return 0


# dns record check

def dns_record(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
        whois_res = whois.whois(url)
        return 1
    except:
        return -1


# Age of domain function

def age_domain(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
        whois_res = whois.whois(url)
        if datetime.datetime.now() > whois_res["creation_date"][0] + relativedelta(months=+6):
            return 1
        else:
            return -1
    except:
        return -1


# check for iframe

def iframe(url):
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup.iframe).lower().find("frameborder") == -1:
        return 1
    return -1


# check if right click is disabled

def right_click_disabled(url):
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup).lower().find("preventdefault()") != -1:
        return -1
    elif str(soup).lower().find("event.button==2") != -1:
        return -1
    elif str(soup).lower().find("event.button == 2") != -1:
        return -1
    return 1


#  On mouse check

def on_mouse(url):
    try:
        html_content = requests.get(url).text
    except:
        return -1
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup).lower().find('onmouseover="window.status') != -1:
        return -1
    return 1


# favicon path check

def favicon_path(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain

    favs = favicon.get(url)
    # print(favs)
    match = 0
    for favi in favs:
        url_2 = favi.url
        extract_res = tldextract.extract(url_2)
        url_ref_2 = extract_res.domain

        if url_ref in url_ref_2:
            match += 1

    if match >= len(favs)/2:
        return 1
    return -1


# check request url

def request_URL(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain

    command = Popen(['curl', 'https://api.hackertarget.com/pagelinks/?q=' +
                    url], stdout=PIPE).communicate()[0]
    links_url = command.decode('utf-8').split("\n")

    count = 0

    for link in links_url:
        extract_res = tldextract.extract(link)
        url_ref2 = extract_res.domain

        if url_ref not in url_ref2:
            count += 1

    count /= len(links_url)

    if count < 0.22:
        return 1
    elif count < 0.61:
        return 0
    else:
        return -1


# url of anchor tags

def check_URL_of_anchor(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    a_tags = soup.find_all('a')

    if len(a_tags) == 0:
        return 1

    invalid = ['#', '#content', '#skip', 'JavaScript::void(0)']
    bad_count = 0
    for t in a_tags:
        try:
            link = t['href']
        except KeyError:
            continue

        if link in invalid:
            bad_count += 1

        if url_valid(link):
            extract_res = tldextract.extract(link)
            url_ref2 = extract_res.domain

            if url_ref not in url_ref2:
                bad_count += 1

    bad_count /= len(a_tags)

    if bad_count < 0.31:
        return 1
    elif bad_count <= 0.67:
        return 0
    return -1


# array of attribute results
def features_result(url):
    features_status = [0] * 24
    features_status[0] = having_ip_add(url)
    features_status[1] = find_url_len(url)
    features_status[2] = shortened_url(url)
    features_status[3] = find_at(url)
    features_status[4] = find_redirect(url)
    features_status[5] = find_prefix(url)
    features_status[6] = find_multi_domains(url)
    features_status[7] = find_authority(url)
    features_status[8] = register_len(url)
    features_status[9] = favicon_path(url)
    features_status[10] = existence_token(url)
    features_status[11] = request_URL(url)
    features_status[12] = check_URL_of_anchor(url)
    features_status[13] = tags(url)
    features_status[14] = sfh_check(url)
    features_status[15] = check_submit_to_email(url)
    #features_status[16] = redirect_check(url)
    features_status[16] = on_mouse(url)
    features_status[17] = right_click_disabled(url)
    features_status[18] = iframe(url)
    features_status[19] = age_domain(url)
    features_status[20] = dns_record(url)
    features_status[21] = web_traffic(url)
    features_status[22] = page_rank(url)
    features_status[23] = statistical_report(url)
    return features_status

#model


class SpamText:
    def transform_text(self, text):
        text = text.lower()
        ps = PorterStemmer()
        text = nltk.wordpunct_tokenize(text)
        y = []
        for i in text:
            if i.isalnum():
                y.append(i)       
        text = y[:]
        y.clear()
        for i in text:
            if i not in stopwords.words('english') and i not in string.punctuation:
                y.append(i)       
        text = y[:]
        y.clear()
        for i in text:
            y.append(ps.stem(i))
        print(y)
        return " ".join(y)

    def is_not_text_spam(self, text):
        tfidf = TfidfVectorizer()
        text = self.transform_text(text)
        x = pd.DataFrame([text])
        txt = tfidf.fit_transform(x[0]).toarray()
        print(txt)
        txt = np.pad(txt[0], (0, 7206 - len(txt[0])), 'constant')
        print("hey")
        return txt



    

