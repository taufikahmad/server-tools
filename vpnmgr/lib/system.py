import os,shutil,re
from pathlib import Path
from .core import SYSTEMD_DIR,run,read_text,write_text,file_backup,log_line

def have_systemd():
  return Path("/run/systemd/system").exists() and shutil.which("systemctl")

def systemctl(*args,check=True):
  return run(["systemctl"]+list(args),check=check,capture=True)

def systemd_unit(name,content):
  if not have_systemd():
    raise RuntimeError("systemd not detected")
  path=f"{SYSTEMD_DIR}/{name}.service"
  file_backup(path)
  write_text(path,content,0o644)
  systemctl("daemon-reload",check=True)

def stop_disable_unit(name):
  if not have_systemd():
    return
  systemctl("stop",f"{name}.service",check=False)
  systemctl("disable",f"{name}.service",check=False)
  p=Path(f"{SYSTEMD_DIR}/{name}.service")
  if p.exists():
    try:
      p.unlink()
    except Exception:
      pass

def enable_ip_forward():
  txt=read_text("/etc/sysctl.conf","")
  lines=txt.splitlines()
  def set_kv(k,v):
    nonlocal lines
    out=[]
    found=False
    for ln in lines:
      if re.match(rf"^\s*{re.escape(k)}\s*=",ln):
        out.append(f"{k}={v}")
        found=True
      else:
        out.append(ln)
    if not found:
      out.append(f"{k}={v}")
    lines=out
  set_kv("net.ipv4.ip_forward","1")
  set_kv("net.ipv6.conf.all.forwarding","1")
  file_backup("/etc/sysctl.conf")
  write_text("/etc/sysctl.conf","\n".join(lines).rstrip()+"\n",0o644)
  run(["sysctl","-p"],check=True,capture=False)

def firewall_detect():
  if shutil.which("ufw"):
    return "ufw"
  if shutil.which("firewall-cmd"):
    return "firewalld"
  if shutil.which("iptables"):
    return "iptables"
  return None

def firewall_open_ports(ports,tcp=True,udp=False):
  fw=firewall_detect()
  if not fw:
    return
  ps=sorted(set(int(p) for p in ports if int(p)>0 and int(p)<65536))
  if fw=="ufw":
    for p in ps:
      if tcp:
        run(["ufw","allow",f"{p}/tcp"],check=False,capture=True)
      if udp:
        run(["ufw","allow",f"{p}/udp"],check=False,capture=True)
    run(["ufw","reload"],check=False,capture=True)
    return
  if fw=="firewalld":
    run(["systemctl","enable","--now","firewalld"],check=False,capture=True)
    for p in ps:
      if tcp:
        run(["firewall-cmd","--permanent","--add-port",f"{p}/tcp"],check=False,capture=True)
      if udp:
        run(["firewall-cmd","--permanent","--add-port",f"{p}/udp"],check=False,capture=True)
    run(["firewall-cmd","--reload"],check=False,capture=True)
    return
  if fw=="iptables":
    for p in ps:
      if tcp:
        if run(["iptables","-C","INPUT","-p","tcp","--dport",str(p),"-j","ACCEPT"],check=False,capture=True).returncode!=0:
          run(["iptables","-I","INPUT","-p","tcp","--dport",str(p),"-j","ACCEPT"],check=False,capture=True)
      if udp:
        if run(["iptables","-C","INPUT","-p","udp","--dport",str(p),"-j","ACCEPT"],check=False,capture=True).returncode!=0:
          run(["iptables","-I","INPUT","-p","udp","--dport",str(p),"-j","ACCEPT"],check=False,capture=True)

def journal_tail(service,lines=80):
  if not shutil.which("journalctl"):
    return ""
  p=run(["journalctl","-u",service,"-n",str(lines),"--no-pager"],check=False,capture=True)
  return (p.stdout or "").strip()

def status_tcp_ports(ports):
  out={}
  if not shutil.which("ss"):
    for p in ports:
      out[int(p)]=None
    return out
  q=run(["ss","-lntp"],check=False,capture=True).stdout or ""
  for p in ports:
    out[int(p)]=(":"+str(int(p)) in q)
  return out
