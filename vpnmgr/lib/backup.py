import datetime,tarfile,shutil
from pathlib import Path
from .core import BACKUP_DIR,STATE_PATH,SYSTEMD_DIR,load_state
from .system import have_systemd,systemctl

def create_backup():
  ts=datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
  out=Path(BACKUP_DIR)/f"vpnmgr-backup-{ts}.tar.gz"
  out.parent.mkdir(parents=True,exist_ok=True)
  st=load_state()
  paths=[]
  if Path(STATE_PATH).exists():
    paths.append(STATE_PATH)
  for p in Path(SYSTEMD_DIR).glob("vpnmgr-ssh-*.service"):
    paths.append(str(p))
  tls=st.get("tls",{})
  for k in ("cert_path","key_path"):
    v=tls.get(k,"")
    if v and Path(v).exists():
      paths.append(v)
  paths=list(dict.fromkeys(paths))
  with tarfile.open(str(out),"w:gz") as t:
    for p in paths:
      try:
        t.add(p,arcname=p.lstrip("/"))
      except Exception:
        pass
  return str(out)

def restore_backup(path):
  p=Path(path)
  if not p.exists():
    raise RuntimeError("backup not found")
  with tarfile.open(str(p),"r:gz") as t:
    t.extractall("/")
  if have_systemd():
    systemctl("daemon-reload",check=False)
    for u in Path(SYSTEMD_DIR).glob("vpnmgr-ssh-*.service"):
      systemctl("enable","--now",u.name,check=False)

def remove_state():
  try:
    shutil.rmtree("/var/lib/vpnmgr",ignore_errors=True)
  except Exception:
    pass
