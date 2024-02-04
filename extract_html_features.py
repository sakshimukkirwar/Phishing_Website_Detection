import os
import sqlite3
import re
import json
from tqdm import tqdm
from multiprocessing import Pool
from bs4 import BeautifulSoup


def extract_html_feature(row):
    row_id, url, html, label, timestamp = row

    feature = {}
    feature['label'] = label

    with open(html, 'r', encoding='utf-8') as file:
        html_content = file.read()

    soup = BeautifulSoup(html_content, 'html.parser')

    forms = soup.find_all('form')
    feature['num_forms'] = len(forms)

    for form in forms:
        # Check for username and password fields
        username_fields = form.find_all('input', {'type': 'text', 'name': re.compile(r'user(?:name)?|login', re.IGNORECASE)})
        password_fields = form.find_all('input', {'type': 'password', 'name': re.compile(r'pass(?:word)?', re.IGNORECASE)})

        feature['num_username_fields'] = len(username_fields)
        feature['num_password_fields'] = len(password_fields)

        # Check for hidden fields
        hidden_fields = form.find_all('input', {'type': 'hidden'})
        feature['num_hidden_fields'] = len(hidden_fields)

        action_attribute = form.get('action', '')
        #  Convert form action to numerical feature
        if not action_attribute:
            form_action_numeric = 0  # No action
        elif action_attribute.startswith(('http://', 'https://')):
            form_action_numeric = 1  # Absolute URL
        elif action_attribute.startswith('/'):
            form_action_numeric = 2  # Relative URL
        else:
            form_action_numeric = 3  # Other (may include javascript, mailto, etc.)
        feature['form_action'] = form_action_numeric

        # Check for autocomplete attribute
        autocomplete_attribute = 'autocomplete' in form.attrs
        feature['form_autocomplete'] = 1 if autocomplete_attribute else 0

    if len(forms) == 0:
        feature['num_username_fields'] = 0
        feature['num_password_fields'] = 0
        feature['num_hidden_fields'] = 0
        feature['form_action'] = 0
        feature['form_autocomplete'] = 0


    external_links = soup.find_all('a', href=re.compile(r'^https?://'))
    feature['external_links_count'] = len(external_links)

    login_forms = soup.find_all('form', {'action': re.compile(r'login|signin|authenticate', re.IGNORECASE)})
    feature['login_form_present'] = True if login_forms else False

    javascript_redirects = soup.find_all('script', {'src': re.compile(r'window\.location')})
    feature['javascript_redirects_present'] = True if javascript_redirects else False

    iframes = soup.find_all('iframe')
    feature['iframes_count'] = len(iframes)

    scripts = soup.find_all('script')
    feature['num_obfuscated_scripts'] = sum(
        'eval(' in script.get_text() or 'document.write(' in script.get_text() for script in scripts
    )
    feature['external_js_inclusion'] = bool(soup.find('script', {'src': re.compile(r'^https?://')}))

    inline_styles = soup.find_all(style=True)
    feature['num_inline_styles'] = len(inline_styles)
    feature['num_script_tags'] = len(soup.find_all('script'))
    feature['num_iframe_tags'] = len(soup.find_all('iframe'))
    feature['num_img_tags'] = len(soup.find_all('img'))
    feature['num_a_tags'] = len(soup.find_all('a'))

    return row_id, feature

def get_html_paths(directory):
    html_paths = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.html'):
                assert file not in html_paths
                html_paths[file] = os.path.join(root, file)
    return html_paths

if __name__ == "__main__":
    data_basepath = './n96ncsr5g4-1'
    db_path = './phishing_index_db'
    html_features_path = './html_features.json'

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM `index`;')
    rows = cursor.fetchall()

    html_paths = get_html_paths(data_basepath)

    for i in range(len(rows)):
        row_i = rows[i]
        row_id, url, html, label, timestamp = row_i
        full_html_path = html_paths[html]

        # Replace with the full path
        rows[i] = (row_id, url, full_html_path, label, timestamp)

    with Pool(16) as p:
        outputs = list(tqdm(p.imap(extract_html_feature, rows), total=len(rows)))

    features = dict(outputs)

    with open(html_features_path, 'w') as json_file:
        json.dump(features, json_file, indent=2)
    print(f"Features have been written to {html_features_path}")

    conn.close()