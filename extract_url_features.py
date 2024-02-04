import os
import sqlite3
import re
from urllib.parse import urlparse
import requests
import idna
from datetime import datetime
import whois
import json
from tqdm import tqdm
from multiprocessing import Pool

def extract_whois_features(domain):
    feature = {}
    try:
        whois_info = whois.whois(domain)
        if whois_info.expiration_date is not None and whois_info.creation_date is not None:
            feature['is_domain_valid'] = True
            expiration_date = (
                whois_info.expiration_date[0] if isinstance(whois_info.expiration_date, list) else whois_info.expiration_date
            )
            creation_date = (
                whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
            ) 

            if isinstance(creation_date, str):
                if 'before' in creation_date:
                    # If the date is given as 'before Aug-1996', set it to the start of that month
                    date_components = creation_date.split('-')
                    year = int(date_components[1])
                    month = datetime.strptime(date_components[0].split()[1], '%b').month
                    creation_date = datetime(year, month, 1)
                else:
                    # If it's a specific date, parse it
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')

            feature['days_until_expiration'] = (expiration_date - datetime.now()).days
            feature['registration_length'] = (expiration_date - creation_date).days
        else:
            feature['is_domain_valid'] = False
            feature['days_until_expiration'] = -1
            feature['registration_length'] = -1

    except Exception as e:
        feature['is_domain_valid'] = False
        feature['days_until_expiration'] = -1
        feature['registration_length'] = -1
    return feature

def is_punycode(domain):
    try:
        decoded_domain = idna.decode(domain)
        return decoded_domain != domain
    except idna.IDNAError:
        # This exception occurs if the domain is not valid Punycode
        return False

def compute_url_depth(parsed_url):
    path_components = [component for component in parsed_url.path.split('/') if component is not None]
    # Compute the depth (number of path components)
    return len(path_components)

def has_phishing_keywords(url):
    phishing_keywords = ['login', 'password', 'bank', 'secure', 'account']
    return any(keyword in url.lower() for keyword in phishing_keywords)

def is_shortened_url(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

    search = re.search(shortening_services, url)
    return search is not None

def has_redirection(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        if final_url != url:
            return True
        else:
            return False
    except Exception as e:
        return False

def extract_url_feature(row):
    row_id, url, html, label, timestamp = row
    parsed_url = urlparse(url)

    feature = {}
    feature['label'] = label

    feature['url_length'] = len(url)   
    feature['num_subdomains'] = len(parsed_url.netloc.split('.'))    
    feature['uses_https'] = parsed_url.scheme == 'https'    
    feature['contains_ip'] = bool(re.search(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))    
    feature['contains_phishing_keywords'] = has_phishing_keywords(url)
    feature['contains_at_symbol'] = '@' in url
    feature['url_depth'] = compute_url_depth(parsed_url)
    feature['is_shortened_url'] = is_shortened_url(url)
    feature['is_punycode'] = is_punycode(parsed_url.netloc)
    feature['has_redirection'] = has_redirection(url)

    feature.update(extract_whois_features(parsed_url.netloc))

    return row_id, feature

if __name__ == "__main__":
    data_basepath = './n96ncsr5g4-1'
    db_path = './phishing_index_db'
    url_features_path = './url_features.json'

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM `index`;')
    rows = cursor.fetchall()

    with Pool(16) as p:
        outputs = list(tqdm(p.imap(extract_url_feature, rows), total=len(rows)))

    features = dict(outputs)

    with open(url_features_path, 'w') as json_file:
        json.dump(features, json_file, indent=2)
    print(f"Features have been written to {url_features_path}")

    conn.close()