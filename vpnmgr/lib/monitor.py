import json
from .core import run
from .system import systemctl

def ensure_vnstat(osinfo,ensure_packages):
  ensure_packages(osinfo,["vnstat"])
  systemctl("enable","--now","vnstat",check=False)

def vnstat_summary():
  p=run(["vnstat","--json"],check=False,capture=True)
  if p.returncode!=0:
    return None
  try:
    return json.loads(p.stdout or "{}")
  except Exception:
    return None
