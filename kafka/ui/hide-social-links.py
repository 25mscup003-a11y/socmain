"""Apply the local header customization and the Kafbat v1.5.0 topic ACL guard."""

from pathlib import Path
import re
import sys
from zipfile import ZipFile


STYLE = """
    <style id="ajnat-header-customization">
      nav[aria-label="Page Header"] a[href="https://github.com/kafbat/kafka-ui"],
      nav[aria-label="Page Header"] a[href="https://discord.com/invite/4DWzD7pGE5"],
      nav[aria-label="Page Header"] a[href="https://producthunt.com/products/ui-for-apache-kafka"] {
        display: none !important;
      }
    </style>
"""

with ZipFile(sys.argv[1]) as source:
    pages = [entry for entry in source.namelist() if entry.endswith('/static/index.html')]
    if len(pages) != 1:
        raise SystemExit('Expected one Kafbat static index.html; check the upstream image layout.')
    page = pages[0]
    html = source.read(page).decode('utf-8')
    if html.count('</head>') != 1:
        raise SystemExit('Expected one HTML head; refusing to modify an unexpected template.')
    html = html.replace('</head>', STYLE + '  </head>')

    topic_pages = [entry for entry in source.namelist()
                   if re.search(r'/static/assets/Topic-[\w-]+\.js$', entry)]
    if len(topic_pages) != 1:
        raise SystemExit('Expected one Kafbat Topic bundle; review the UI patch for this version.')
    topic_page = topic_pages[0]
    topic_js = source.read(topic_page).decode('utf-8')
    original_acls = ('()=>{const{topicName:e,clusterName:t}=Xe(),r=Yt(),'
                     '{data:n=sv}=zc({clusterName:t,topicName:e}),'
                     'a=Me.useMemo(()=>[hu(),pu(),mu(),yu()],[r]);'
                     'return j.jsx(gu,{acls:n,columns:a})}')
    if topic_js.count('ov=' + original_acls) != 1:
        raise SystemExit('Topic ACL component changed; review the patch before upgrading Kafbat.')
    replacement = Path(__file__).with_name('topic-acls.js').read_text().strip()
    topic_js = topic_js.replace('ov=' + original_acls,
                               replacement.replace('__ORIGINAL_TOPIC_ACLS__', original_acls))
    updates = {page: html.encode('utf-8'), topic_page: topic_js.encode('utf-8')}
    with ZipFile(sys.argv[2], 'w') as target:
        # Preserve each entry's metadata and compression, especially the stored
        # nested JARs required by Spring Boot. Leave upstream notices intact.
        for entry in source.infolist():
            target.writestr(entry, updates[entry.filename] if entry.filename in updates else source.read(entry))
