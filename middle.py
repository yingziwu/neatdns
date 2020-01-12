import json
import os

import tldextract

import env

def merge_lines(mzdns0,mzdns1):
    with open(mzdns0, 'r') as f:
        mzdns0_lines = f.readlines()
    with open(mzdns1, 'r') as f:
        mzdns1_lines = f.readlines()
    lines = []
    lines.extend(mzdns0_lines)
    lines.extend(mzdns1_lines)
    return lines

def clean_zdns_output(lines, domains_file_path):
    '''清洗zdns输出文件，并将其与原域名列表合并'''
    domains = []
    for line in lines:
        result = json.loads(line)
        if result['status'] == 'NOERROR':
            answers = result["data"]["answers"]
            for answer in answers:
                if answer["type"] == "A" or answer["type"] == "AAAA":
                    ext = tldextract.extract(result["name"])
                    domain = ext.registered_domain
                    domains.append(domain + '.')
                    break

    with open(os.path.join(env.TMP_FOLDER, 'new_poisoning_domains.json'), 'w') as f:
        json.dump(domains, f)

    with open(domains_file_path, 'r') as f:
        domains_old = json.load(f)

    domains_new = []
    domains_new.extend(domains_old)
    domains_new.extend(domains)
    domains = list(set(domains_new))
    for domain in domains:
        if domain in env.TLD_LIST or domain == '' or not domain.endswith('.'):
            domains.remove(domain)
    domains.sort()
    with open(domains_file_path, 'w') as f:
        json.dump(domains, f, indent=4, sort_keys=True)


def test():
    print(env.TMP_FOLDER)
