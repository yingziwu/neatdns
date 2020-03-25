import os
import re
import time

import env
import middle

# 读取日志
zdns_domains = []

with open(env.BIND_QUEEY_LOG_PATH, 'r') as f:
    query_log_lines = middle.tail(f, 50000)
for query_log_line in query_log_lines:
    m = re.search('\((.*)\):', query_log_line)
    if m:
        zdns_domain = m.groups()[0]
        zdns_domains.append(zdns_domain)
    else:
        print(query_log_line)

with open(env.BIND_RESOLVE_LOG_PATH, 'r') as f:
    resolve_log_lines = middle.tail(f, 100000)
for resolve_log_line in resolve_log_lines:
    m = re.search('resolving (.*)\/', resolve_log_line)
    if m:
        zdns_domain = m.groups()[0]
        zdns_domains.append(zdns_domain)
    else:
        print(resolve_log_line)

# 扫描
env.TMP_FOLDER = os.path.join(env.TMP_FOLDER, 'update' + time.strftime('%m-%d_%H-%M-%S'))
if not os.path.exists(env.TMP_FOLDER):
    os.mkdir(env.TMP_FOLDER)

zdns_domains = list(set(zdns_domains))
zdns_fname = os.path.join(env.TMP_FOLDER, 'zdns_domains.txt')
out1 = os.path.join(env.TMP_FOLDER, 'zdns0.json')
out2 = os.path.join(env.TMP_FOLDER, 'zdns1.json')
out_fnames = [out1, out2]
with open(zdns_fname, 'w') as f:
    f.write('\n'.join(zdns_domains))
middle.zdns_scan(zdns_fname, out_fnames)

# 整理扫描结果
lines = middle.merge_lines(out1, out2)
middle.clean_zdns_output(lines, env.POISONING_DOMAINS_LIST)
print('Update complex!')
