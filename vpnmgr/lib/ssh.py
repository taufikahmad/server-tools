import datetime
from .core import run,validate_username

def ssh_add_user(username,password,days=None):
  if not validate_username(username):
    raise RuntimeError("invalid username")
  if run(["id",username],check=False,capture=True).returncode==0:
    raise RuntimeError("user already exists")
  run(["useradd","-m","-s","/bin/bash",username],check=True,capture=True)
  p=run(["bash","-lc",f"printf %s {username}:{password} | chpasswd"],check=False,capture=True)
  if p.returncode!=0:
    raise RuntimeError("chpasswd failed")
  if days is not None and int(days)>0:
    exp=(datetime.date.today()+datetime.timedelta(days=int(days))).isoformat()
    run(["chage","-E",exp,username],check=True,capture=True)

def ssh_del_user(username,remove_home=True):
  if run(["id",username],check=False,capture=True).returncode!=0:
    raise RuntimeError("user not found")
  args=["userdel"]
  if remove_home:
    args.append("-r")
  args.append(username)
  run(args,check=True,capture=True)

def ssh_list_users():
  out=[]
  p=run(["bash","-lc","getent passwd"],check=False,capture=True)
  for ln in (p.stdout or "").splitlines():
    parts=ln.split(":")
    if len(parts)<7:
      continue
    u=parts[0]
    try:
      uid=int(parts[2])
    except Exception:
      continue
    sh=parts[6]
    if uid>=1000 and sh not in ("/usr/sbin/nologin","/bin/false"):
      out.append(u)
  return out

def ssh_enable_2fa(osinfo,ensure_packages,file_backup,read_text,write_text):
  if osinfo["family"]=="debian":
    ensure_packages(osinfo,["libpam-google-authenticator"])
  else:
    ensure_packages(osinfo,["google-authenticator"])
  sshd="/etc/ssh/sshd_config"
  pam="/etc/pam.d/sshd"
  file_backup(sshd)
  file_backup(pam)
  s=read_text(sshd,"")
  def set_line(k,v):
    nonlocal s
    import re
    r=re.compile(rf"^\s*{re.escape(k)}\s+.*$",re.M)
    if r.search(s):
      s=r.sub(f"{k} {v}",s)
    else:
      s=s.rstrip()+"\n"+f"{k} {v}"+"\n"
  set_line("ChallengeResponseAuthentication","yes")
  set_line("KbdInteractiveAuthentication","yes")
  set_line("AuthenticationMethods","publickey,password publickey,keyboard-interactive password,keyboard-interactive")
  write_text(sshd,s,0o600)
  p=read_text(pam,"")
  if "pam_google_authenticator.so" not in p:
    lines=p.splitlines()
    o=[]
    ins=False
    for ln in lines:
      o.append(ln)
      if not ins and ln.strip().startswith("@include"):
        o.append("auth required pam_google_authenticator.so nullok")
        ins=True
    if not ins:
      o.append("auth required pam_google_authenticator.so nullok")
    write_text(pam,"\n".join(o).rstrip()+"\n",0o644)
  run(["systemctl","restart","ssh"],check=False,capture=True)
  run(["systemctl","restart","sshd"],check=False,capture=True)

def ssh_disable_2fa(read_text,write_text):
  import re
  sshd="/etc/ssh/sshd_config"
  pam="/etc/pam.d/sshd"
  s=read_text(sshd,"")
  s=re.sub(r"^\s*AuthenticationMethods\s+.*$","",s,flags=re.M)
  s=re.sub(r"^\s*ChallengeResponseAuthentication\s+.*$","ChallengeResponseAuthentication no",s,flags=re.M)
  s=re.sub(r"^\s*KbdInteractiveAuthentication\s+.*$","KbdInteractiveAuthentication no",s,flags=re.M)
  s=re.sub(r"\n{3,}","\n\n",s).rstrip()+"\n"
  write_text(sshd,s,0o600)
  p=read_text(pam,"")
  p=re.sub(r"^\s*auth\s+required\s+pam_google_authenticator\.so.*$","",p,flags=re.M)
  p=re.sub(r"\n{3,}","\n\n",p).rstrip()+"\n"
  write_text(pam,p,0o644)
  run(["systemctl","restart","ssh"],check=False,capture=True)
  run(["systemctl","restart","sshd"],check=False,capture=True)
