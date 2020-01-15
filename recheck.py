import middle
import env
import os
import time
import json

env.TMP_FOLDER = os.path.join(env.TMP_FOLDER, 'recheck' + time.strftime('%m-%d_%H-%M-%S'))
if not os.path.exists(env.TMP_FOLDER):
    os.mkdir(env.TMP_FOLDER)

with open(env.POISONING_DOMAINS_LIST, 'r') as f:
    pds = json.load(f)
    zdns_domains = os.path.join(env.TMP_FOLDER, 'zdns_domains.txt')
    with open(zdns_domains, 'w') as f1:
        f1.write('\n'.join(pds))

out1 = os.path.join(env.TMP_FOLDER, 'zdns0.json')
out2 = os.path.join(env.TMP_FOLDER, 'zdns1.json')
out_fnames = [out1, out2]
middle.zdns_scan(zdns_domains, out_fnames)

lines = middle.merge_lines(out1, out2)
result_fname = os.path.join(env.TMP_FOLDER, 'recheck_domain_list_poisoning.json')
middle.clean_zdns_output(lines, result_fname)

