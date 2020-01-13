import os
from zipfile import ZipFile

import requests

import env
import middle

# 下载及解压 Alexa top 1m
resp = requests.get(env.ALEXA_TOP_1M_URL, timeout=5)
top_1m_zip = os.path.join(env.TMP_FOLDER, 'top-1m.csv.zip')
top_1m = os.path.join(env.TMP_FOLDER, 'top-1m.csv')
with open(top_1m_zip, 'wb') as f:
    f.write(resp.content)
with ZipFile(top_1m_zip) as zipObj:
    zipObj.extract('top-1m.csv', env.TMP_FOLDER)

# 扫描 Alexa top 1m
env.TMP_FOLDER = os.path.join(env.TMP_FOLDER, 'init')
if not os.path.exists(env.TMP_FOLDER):
    os.mkdir(env.TMP_FOLDER)

out1 = os.path.join(env.TMP_FOLDER, 'zdns0.json')
out2 = os.path.join(env.TMP_FOLDER, 'zdns1.json')
out_fnames = [out1, out2]
middle.zdns_scan(top_1m, out_fnames, True)

# 整理扫描结果
lines = middle.merge_lines(out1, out2)
middle.clean_zdns_output(lines, env.POISONING_DOMAINS_LIST)
print('Init Finish!')
