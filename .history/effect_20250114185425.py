import redis
import sys
import os
import argparse

r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()



def check_hfn:
