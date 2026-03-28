"""get DigitalOcean droplet CPU stats and analyze them

Copied verbatim from louking/apache-access-summarizer/app/src/dometrics.py
"""

# pypi
from flask import logging
from requests import get
import numpy as np
from csv import DictWriter
from io import StringIO

from loutilities.timeu import epoch2dt


def get_droplet_cpu_metrics(token, droplet_id, start_window, end_window):
    """get CPU metrics for a droplet from DigitalOcean API

    Args:
        token (str): DigitalOcean API token
        droplet_id (int): droplet ID
        start_window (epoch): start of time window for metrics
        end_window (epoch): end of time window for metrics

    Returns:
        dict: dictionary of CPU metrics
    """
    url = f'https://api.digitalocean.com/v2/monitoring/metrics/droplet/cpu?host_id={droplet_id}&start={start_window}&end={end_window}'
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    resp = get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()


def metrics2csv(metrics):
    """convert DigitalOcean metrics to CSV format

    Args:
        metrics (dict): digital ocean metrics

    Returns:
        str: CSV formatted string of CPU metrics
    """
    timestamps = {m['metric']['mode']: np.array([int(v[0]) for v in m['values']]) for m in metrics['data']['result']}
    cpumetrics = {m['metric']['mode']: np.array([float(v[1]) for v in m['values']]) for m in metrics['data']['result']}

    ctimes_set = None
    for mode in timestamps:
        if not ctimes_set:
            ctimes_set = True
            ctimes = timestamps[mode]
            continue
        if not np.array_equal(ctimes, timestamps[mode]):
            raise ValueError('mismatched timestamps in cpu metrics')

    idle  = cpumetrics['idle']
    total = sum([cpumetrics[m] for m in cpumetrics])
    used  = total - idle

    dtimes = [epoch2dt(t).isoformat() for t in ctimes]

    with StringIO() as body:
        cpu_csv = DictWriter(body, fieldnames=['Time', '%CPU', 'Used (cum msec)', 'Total (cum msec)'])
        cpu_csv.writeheader()
        last_used = None
        for i in range(len(total)):
            # cpu time is cumulative in msec; round %CPU to 1/10th of a percent
            if last_used:
                cpu_p = round(100.0 * (used[i] - last_used) / (total[i] - last_total), 1)
                from math import isnan
                import logging
                log = logging.getLogger(__name__)
                if isnan(float(cpu_p)):
                    log.warning(f"NaN CPU% at {dtimes[i]} i={i}, used[{i}]={used[i]}, last_used={last_used}, total[{i}]={total[i]}, last_total={last_total}; skipping")
                    continue
            else:
                cpu_p = ''
            # https://www.digitalocean.com/community/questions/get_droplet_cpu_metrics-response-format?comment=212508
            cpu_csv.writerow({
                'Time': dtimes[i],
                '%CPU': cpu_p,
                'Used (cum msec)': round(used[i]),
                'Total (cum msec)': round(total[i]),
            })
            last_used  = used[i]
            last_total = total[i]

        contents = body.getvalue()

    return contents
