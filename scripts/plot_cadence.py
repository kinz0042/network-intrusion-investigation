#!/usr/bin/env python3
"""Optional report graphic. Requires matplotlib in addition to core requirements."""
import json
from pathlib import Path
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

root=Path(__file__).resolve().parents[1]
r=json.loads((root/'evidence/analysis.json').read_text())
rows=[x for x in r['http_requests'] if x['classification']=='review_remote_support']
times=[datetime.fromisoformat(x['time_utc'].replace('Z','+00:00')) for x in rows]
gaps=[(b-a).total_seconds() for a,b in zip(times,times[1:])]
fig,(top,bottom)=plt.subplots(2,1,figsize=(10,5.8),layout='constrained',gridspec_kw={'height_ratios':[1,2]})
top.eventplot(mdates.date2num(times),colors='#145e99',linewidths=1.3)
top.xaxis.set_major_locator(mdates.MinuteLocator(byminute=[0,30]))
top.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
top.set_yticks([]);top.set_xlabel('10 November 2026 · UTC');top.set_title('125 matching NetSupport HTTP request starts',loc='left',fontweight='bold')
bottom.plot(range(1,len(gaps)+1),gaps,'.',color='#145e99',markersize=4)
bottom.axhline(60.134689,color='#af4d13',linestyle='--',label='Median: 60.134689 seconds')
bottom.set_xlabel('Consecutive request interval');bottom.set_ylabel('Seconds');bottom.set_ylim(bottom=0);bottom.legend(frameon=False,loc='lower right')
fig.suptitle('Repeated communication is evidence to investigate, not proof of C2',fontsize=12)
fig.savefig(root/'evidence/request_cadence.svg',metadata={'Date':None})
fig.savefig(root/'evidence/request_cadence.png',dpi=140)
