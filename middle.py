import json
import os
import subprocess
import re

import tldextract

import env


def zdns_scan(in_fname, out_fnames, alexa=False):
    '''执行扫描命令'''
    base_cmd = ['zdns', 'DS', '-conf-file', env.RESOLVE_CONF_FNAME, '-timeout', '10', '-retries', '2']
    out1, out2 = out_fnames
    if alexa:
        base_cmd.append('-alexa')
    base_cmd.extend(['-input-file', in_fname])

    cmd1, cmd2 = base_cmd.copy(), base_cmd.copy()
    cmd1.extend(['-output-file', out1])
    cmd2.extend(['-prefix', 'www.', '-output-file', out2])
    cmds = [cmd1, cmd2]
    for cmd in cmds:
        print(' '.join(cmd))
        subprocess.call(cmd)


def merge_lines(mzdns0, mzdns1):
    '''合并两文本文件'''
    with open(mzdns0, 'r') as f:
        mzdns0_lines = f.readlines()
    with open(mzdns1, 'r') as f:
        mzdns1_lines = f.readlines()
    lines = []
    lines.extend(mzdns0_lines)
    lines.extend(mzdns1_lines)
    return lines


def zdns_detect(domain):
    '''探测域名是否被污染'''
    in_fname = os.path.join(env.TMP_FOLDER, 'zdns_tmp.txt')
    with open(in_fname, 'w') as f:
        f.write(domain + '\n')
    out1 = os.path.join(env.TMP_FOLDER, 'zdns_%s_0.json' % domain)
    out2 = os.path.join(env.TMP_FOLDER, 'zdns_%s_1.json' % domain)
    out_fnames = [out1, out2]
    zdns_scan(in_fname, out_fnames)
    lines = merge_lines(out1, out2)
    for line in lines:
        result = json.loads(line)
        if result['status'] == 'NOERROR':
            return True

    return False


def recursion_test(registered_domain, test_domain, pre_test_domain, old_domains):
    '''返回最短未被污染域名
    :param old_domains:
    '''
    q = zdns_detect(test_domain)
    if test_domain == registered_domain:
        if q is True:
            domain = test_domain
        else:
            domain = pre_test_domain
    else:
        if q is True:
            pre_test_domain = test_domain
            test_domain = re.sub('^([\w\-]+\.)', '', test_domain)
            if test_domain in old_domains:
                return test_domain
            else:
                return recursion_test(registered_domain, test_domain, pre_test_domain, old_domains)
        else:
            domain = test_domain

    return domain


def reduce_domain(raw_domain, old_domains):
    '''精简域名'''
    ext = tldextract.extract(raw_domain)
    registered_domain = ext.registered_domain

    pre_test_domain = None
    if raw_domain == registered_domain:
        return raw_domain
    elif raw_domain in old_domains:
        return
    elif registered_domain in old_domains:
        return
    elif registered_domain == '':
        return
    else:
        test_domain = re.sub('^([\w\-]+\.)', '', raw_domain)
        p, q = None, None
        domain = recursion_test(registered_domain, test_domain, pre_test_domain, old_domains)
        return domain


def clean_zdns_output(lines, domains_file_path):
    '''清洗zdns输出文件，并将其与原域名列表合并'''
    try:
        with open(domains_file_path, 'r') as f:
            old_domains = json.load(f)
    except FileNotFoundError as e:
        old_domains = []

    domains = []
    for line in lines:
        result = json.loads(line)
        if result['status'] == 'NOERROR':
            answers = result["data"]["answers"]
            for answer in answers:
                if answer["type"] == "A" or answer["type"] == "AAAA":
                    domain = reduce_domain(result["name"], old_domains)
                    if domain:
                        domain = domain.lower()
                        domains.append(domain)
                        break

    with open(os.path.join(env.TMP_FOLDER, 'new_poisoning_domains.json'), 'w') as f:
        json.dump(domains, f)

    if domains_file_path == env.POISONING_DOMAINS_LIST:
        domains_new = []
        with open(domains_file_path, 'r') as f:
            domains_old = json.load(f)
        domains_new.extend(domains_old)
        domains_new.extend(domains)
        domains = list(set(domains_new))
    else:
        domains = list(set(domains))

    for domain in domains:
        if domain in env.TLD_LIST or domain == '' or domain is None or domain.lower() != domain:
            domains.remove(domain)
    domains.sort()

    # Add Negative trust anchor
    if domains_file_path == env.POISONING_DOMAINS_LIST and env.ADD_NTA:
        new_domains = list(set(domains).difference(set(old_domains)))
        for new_domain in new_domains:
            cmd = ['rndc', 'nta', '-lifetime', '604800', new_domain]
            subprocess.call(cmd)

    print('Output file is: ' + domains_file_path)
    with open(domains_file_path, 'w') as f:
        json.dump(domains, f, indent=4, sort_keys=True)


def tail(f, lines=1, _buffer=4098):
    """Tail a file and get X lines from the end"""
    # place holder for the lines found
    lines_found = []

    # block counter will be multiplied by buffer
    # to get the block size from the end
    block_counter = -1

    # loop until we find X lines
    while len(lines_found) < lines:
        try:
            f.seek(block_counter * _buffer, os.SEEK_END)
        except IOError:  # either file is too small, or too many lines requested
            f.seek(0)
            lines_found = f.readlines()
            break

        lines_found = f.readlines()

        # we found enough lines, get out
        # Removed this line because it was redundant the while will catch
        # it, I left it for history
        # if len(lines_found) > lines:
        #    break

        # decrement the block counter to get the
        # next X bytes
        block_counter -= 1

    return lines_found[-lines:]


def test():
    print(env.TMP_FOLDER)
