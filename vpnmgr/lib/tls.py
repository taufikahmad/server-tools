import shutil
from pathlib import Path
from .core import load_state,save_state,run

def have_systemd():
  return Path("/run/systemd/system").exists() and shutil.which("systemctl")

def active_units(units):
  out=[]
  for u in units:
    p=run(["systemctl","is-active",u],check=False,capture=True)
    if (p.stdout or "").strip()=="active":
      out.append(u)
  return out

def gen_self_signed(domain,days=825):
  out_dir=Path("/var/lib/vpnmgr/tls")
  out_dir.mkdir(parents=True,exist_ok=True)
  cert=str(out_dir/"fullchain.pem")
  key=str(out_dir/"privkey.pem")
  subj=f"/CN={domain}"
  run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-days",str(days),"-subj",subj],check=True,capture=True)
  try:
    Path(key).chmod(0o600)
  except Exception:
    pass
  st=load_state()
  st.setdefault("tls",{})
  st["tls"]["mode"]="self-signed"
  st["tls"]["domain"]=domain
  st["tls"]["cert_path"]=cert
  st["tls"]["key_path"]=key
  save_state(st)
  return {"cert":cert,"key":key}

def gen_letsencrypt(osinfo,domain,email,ensure_packages):
  ensure_packages(osinfo,["certbot"])
  restart=[]
  if have_systemd():
    restart+=active_units(["nginx.service","apache2.service"])
    u=run(["bash","-lc","systemctl list-units --type=service --all --no-legend 'vpnmgr-ssh-*.service' | awk '{print $1}'"],check=False,capture=True).stdout or ""
    units=[x.strip() for x in u.splitlines() if x.strip().endswith(".service")]
    restart+=active_units(units)
    for svc in set(restart):
      run(["systemctl","stop",svc],check=False,capture=True)
  try:
    args=["certbot","certonly","--standalone","-d",domain,"--agree-tos","--non-interactive"]
    if email and email.strip():
      args+=["-m",email.strip()]
    else:
      args+=["--register-unsafely-without-email"]
    run(args,check=True,capture=False)
  finally:
    if have_systemd():
      for svc in set(restart):
        run(["systemctl","start",svc],check=False,capture=True)
  cert=f"/etc/letsencrypt/live/{domain}/fullchain.pem"
  key=f"/etc/letsencrypt/live/{domain}/privkey.pem"
  if not Path(cert).exists() or not Path(key).exists():
    raise RuntimeError("letsencrypt cert not found")
  st=load_state()
  st.setdefault("tls",{})
  st["tls"]["mode"]="letsencrypt"
  st["tls"]["domain"]=domain
  st["tls"]["cert_path"]=cert
  st["tls"]["key_path"]=key
  save_state(st)
  return {"cert":cert,"key":key}

def tls_paths_required():
  st=load_state()
  t=st.get("tls",{})
  cert=t.get("cert_path","")
  key=t.get("key_path","")
  if not cert or not key:
    raise RuntimeError("TLS cert/key not configured")
  if not Path(cert).exists() or not Path(key).exists():
    raise RuntimeError("TLS cert/key missing on disk")
  return cert,key
