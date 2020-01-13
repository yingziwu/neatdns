import json
import os
import subprocess

import tldextract

import env


def zdns_scan(in_fname, out_fnames, alexa=False):
    '''执行扫描命令'''
    base_cmd = ['zdns', 'AAAA', '-conf-file', env.RESOLVE_CONF_FNAME, '-timeout', '1']
    out1, out2 = out_fnames
    if alexa:
        base_cmd.append('-alexa')
    base_cmd.extend(['-input-file', in_fname])

    cmd1, cmd2 = base_cmd.copy(), base_cmd.copy()
    cmd1.extend(['-output-file', out1])
    cmd2.extend(['-prefix', 'www', '-output-file', out2])
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
                    domains.append(domain)
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
        if domain in env.TLD_LIST or domain == '':
            domains.remove(domain)
    domains.sort()
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
