import os
import re
import subprocess
import time

import env
import middle


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

# 读取日志
zdns_domains = []
with open(env.BIND_QUEEY_LOG_PATH,'r') as f:
    query_log_lines = tail(f, 10000)
for query_log_line in query_log_lines:
    m = re.search('\((.*)\):', query_log_line)
    if m:
        zdns_domain = m.groups()[0]
        zdns_domains.append(zdns_domain)
    else:
        print(query_log_line)

# 扫描
env.TMP_FOLDER = os.path.join(env.TMP_FOLDER, time.strftime('%m-%d_%H-%M-%S'))
if not os.path.exists(env.TMP_FOLDER):
    os.mkdir(env.TMP_FOLDER)

zdns_domains = list(set(zdns_domains))
zdns_fname = os.path.join(env.TMP_FOLDER, 'zdns_domains.txt')
mzdns0 = os.path.join(env.TMP_FOLDER, 'zdns0.json')
mzdns1 = os.path.join(env.TMP_FOLDER, 'zdns1.json')
with open(zdns_fname, 'w') as f:
    f.write('\n'.join(zdns_domains))
subprocess.call(
    ['zdns', 'AAAA', '-conf-file', env.RESOLVE_CONF_FNAME, '-timeout', '1', '-input-file', zdns_fname,
     '-output-file', mzdns0])
subprocess.call(
    ['zdns', 'AAAA', '-conf-file', env.RESOLVE_CONF_FNAME, '-timeout', '1', '-prefix', 'www', '-input-file', zdns_fname,
     '-output-file', mzdns1])

# 整理扫描结果
lines = middle.merge_lines(mzdns0, mzdns1)
middle.clean_zdns_output(lines, env.POISONING_DOMAINS_LIST)
print('Update complex!')
