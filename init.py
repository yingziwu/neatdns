import os
import subprocess
from zipfile import ZipFile

import requests

import env
import middle

# 下载及解压 Alexa top 1m
resp = requests.get(env.ALEXA_TOP_1M_URL)
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

mzdns0 = os.path.join(env.TMP_FOLDER, 'zdns0.json')
mzdns1 = os.path.join(env.TMP_FOLDER, 'zdns1.json')
print('开始扫描 Alexa top 1m 域名……')
subprocess.call(['zdns', 'AAAA', '-alexa', '-conf-file', env.RESOLVE_CONF_FNAME, '-timeout', '1', '-input-file', top_1m,
                 '-output-file', mzdns0])
print('开始扫描 Alexa top 1m 域名（加 www.前缀）……')
subprocess.call(
    ['zdns', 'AAAA', '-alexa', '-conf-file', env.RESOLVE_CONF_FNAME, '-timeout', '1', '-prefix', 'www',
     '-input-file', top_1m, '-output-file', mzdns1])

# 整理扫描结果
lines = middle.merge_lines(mzdns0,mzdns1)
middle.clean_zdns_output(lines, env.POISONING_DOMAINS_LIST)
print('init scan Finish!')