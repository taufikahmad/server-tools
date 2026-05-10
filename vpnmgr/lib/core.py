import datetime,json,os,platform,random,re,shlex,shutil,string,subprocess
from pathlib import Path

LOG_PATH="/var/log/vpnmgr.log"
STATE_DIR="/var/lib/vpnmgr"
STATE_PATH=f"{STATE_DIR}/state.json"
BACKUP_DIR="/var/backups/vpnmgr"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
WEBSOCAT_PATH=f"{BIN_DIR}/websocat"

def now_iso():
  return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def log_line(level,msg,extra=None):
  try:
    Path(LOG_PATH).parent.mkdir(parents=True,exist_ok=True)
    o={"ts":now_iso(),"level":level,"msg":msg}
    if extra is not None:
      o["extra"]=extra
    with open(LOG_PATH,"a",encoding="utf-8") as f:
      f.write(json.dumps(o,ensure_ascii=False)+"\n")
  except Exception:
    pass

def die(msg,code=1):
  log_line("error",msg)
  raise SystemExit(code)

def run(cmd,check=True,capture=True,env=None):
  args=shlex.split(cmd) if isinstance(cmd,str) else list(cmd)
  log_line("cmd"," ".join(shlex.quote(x) for x in args))
  p=subprocess.run(args,check=False,stdout=subprocess.PIPE if capture else None,stderr=subprocess.PIPE if capture else None,text=True,env=env)
  if check and p.returncode!=0:
    out=(p.stdout or "").strip()
    err=(p.stderr or "").strip()
    raise RuntimeError(f"command failed rc={p.returncode} cmd={' '.join(args)} out={out} err={err}")
  return p

def is_root():
  try:
    return os.geteuid()==0
  except Exception:
    return False

def read_text(path,default=""):
  try:
    return Path(path).read_text(encoding="utf-8",errors="ignore")
  except Exception:
    return default

def write_text(path,content,mode=0o644):
  p=Path(path)
  p.parent.mkdir(parents=True,exist_ok=True)
  tmp=str(p)+".tmp"
  Path(tmp).write_text(content,encoding="utf-8")
  os.chmod(tmp,mode)
  os.replace(tmp,str(p))

def file_backup(path):
  p=Path(path)
  if not p.exists():
    return None
  bdir=Path(BACKUP_DIR)
  bdir.mkdir(parents=True,exist_ok=True)
  ts=datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
  dst=bdir/(p.name+"."+ts+".bak")
  shutil.copy2(str(p),str(dst))
  return str(dst)

def load_state():
  try:
    Path(STATE_DIR).mkdir(parents=True,exist_ok=True)
    if not Path(STATE_PATH).exists():
      return {}
    return json.loads(read_text(STATE_PATH,"{}") or "{}")
  except Exception:
    return {}

def save_state(s):
  Path(STATE_DIR).mkdir(parents=True,exist_ok=True)
  write_text(STATE_PATH,json.dumps(s,indent=2,ensure_ascii=False)+"\n",0o600)

def detect_os():
  osr={}
  for ln in read_text("/etc/os-release","").splitlines():
    if "=" in ln:
      k,v=ln.split("=",1)
      osr[k.strip()]=v.strip().strip('"')
  i=(osr.get("ID") or "").lower()
  like=(osr.get("ID_LIKE") or "").lower()
  if i in ("ubuntu","debian") or "debian" in like or "ubuntu" in like:
    return {"family":"debian","id":i or "debian"}
  if i in ("centos","rhel","rocky","almalinux","fedora") or any(x in like for x in ("rhel","fedora","centos")):
    return {"family":"rhel","id":i or "rhel"}
  return {"family":"unknown","id":i or "unknown"}

def pkg_mgr(osinfo):
  if osinfo["family"]=="debian":
    return "apt"
  if osinfo["family"]=="rhel":
    return "dnf" if shutil.which("dnf") else "yum"
  return None

def disable_apt_suite(suite):
  suite=(suite or "").strip()
  if not suite:
    return False
  changed=False
  paths=[]
  p=Path("/etc/apt/sources.list")
  if p.exists():
    paths.append(p)
  d=Path("/etc/apt/sources.list.d")
  if d.exists():
    paths+=sorted(d.glob("*.list"))
  for p in paths:
    txt=read_text(str(p),"")
    if not txt:
      continue
    out=[]
    touched=False
    for ln in txt.splitlines():
      s=ln.strip()
      if s and not s.startswith("#") and suite in ln:
        out.append("# "+ln)
        touched=True
      else:
        out.append(ln)
    if touched:
      file_backup(str(p))
      write_text(str(p),"\n".join(out).rstrip()+"\n",0o644)
      changed=True
  return changed

def ensure_packages(osinfo,pkgs):
  pm=pkg_mgr(osinfo)
  if not pm:
    raise RuntimeError("unsupported distro")
  if pm=="apt":
    p=run([pm,"update"],check=False,capture=True)
    if p.returncode!=0 and ("bullseye-backports" in (p.stdout or "") or "bullseye-backports" in (p.stderr or "")):
      if disable_apt_suite("bullseye-backports"):
        p=run([pm,"update"],check=False,capture=True)
    if p.returncode!=0:
      out=(p.stdout or "").strip()
      err=(p.stderr or "").strip()
      raise RuntimeError(f"apt update failed rc={p.returncode} out={out} err={err}")
    run([pm,"install","-y"]+list(pkgs),check=True,capture=False)
    return
  run([pm,"install","-y"]+list(pkgs),check=True,capture=False)

def random_password(n=16):
  a=string.ascii_letters+string.digits
  return "".join(random.choice(a) for _ in range(n))

def prompt(msg,default=None,secret=False):
  p=f"{msg} [{default}]: " if default is not None else f"{msg}: "
  if secret:
    import getpass
    v=getpass.getpass(p)
  else:
    v=input(p)
  v=v.strip()
  if not v and default is not None:
    return str(default)
  return v

def yn(msg,default=False):
  d="y" if default else "n"
  v=prompt(f"{msg} (y/n)",d).lower().strip()
  return v in ("y","yes","1","true","t")

def detect_arch():
  m=platform.machine().lower()
  if m in ("x86_64","amd64"):
    return "amd64"
  if m in ("aarch64","arm64"):
    return "arm64"
  if m.startswith("armv7") or m=="armv7l":
    return "armv7"
  return m

def download(url,dst,mode=0o755):
  import urllib.request
  Path(dst).parent.mkdir(parents=True,exist_ok=True)
  with urllib.request.urlopen(url,timeout=60) as r:
    data=r.read()
  Path(dst).write_bytes(data)
  os.chmod(dst,mode)

def install_websocat():
  if Path(WEBSOCAT_PATH).exists():
    return
  arch=detect_arch()
  if arch=="amd64":
    a="x86_64-unknown-linux-musl"
  elif arch=="arm64":
    a="aarch64-unknown-linux-musl"
  elif arch=="armv7":
    a="armv7-unknown-linux-musleabihf"
  else:
    raise RuntimeError(f"unsupported arch: {arch}")
  v="1.14.0"
  url=f"https://github.com/vi/websocat/releases/download/v{v}/websocat_{v}_{a}"
  download(url,WEBSOCAT_PATH,0o755)
  run([WEBSOCAT_PATH,"--version"],check=True,capture=True)

def validate_username(u):
  return bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}",u or ""))
