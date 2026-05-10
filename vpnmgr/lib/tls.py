from pathlib import Path
from .core import load_state,save_state,run

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
  run(["systemctl","stop","nginx"],check=False,capture=True)
  run(["systemctl","stop","apache2"],check=False,capture=True)
  args=["certbot","certonly","--standalone","-d",domain,"--agree-tos","--non-interactive"]
  if email and email.strip():
    args+=["-m",email.strip()]
  else:
    args+=["--register-unsafely-without-email"]
  run(args,check=True,capture=False)
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
