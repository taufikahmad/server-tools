import json,os,shlex,socket,sys
from pathlib import Path
from lib.core import is_root,detect_os,ensure_packages,prompt,yn,random_password,run,read_text,write_text,file_backup,load_state
from lib.system import enable_ip_forward,firewall_open_ports,have_systemd,systemctl,journal_tail,status_tcp_ports
from lib.tls import gen_self_signed,gen_letsencrypt
from lib.ws import configure,restart_all,stop_all,remove_all,DEFAULT_WS_PORTS,DEFAULT_WS_PATH,DEFAULT_SSH_TARGET,DEFAULT_WSS_PORT
from lib.ssh import ssh_add_user,ssh_del_user,ssh_list_users,ssh_enable_2fa,ssh_disable_2fa
from lib.monitor import ensure_vnstat,vnstat_summary
from lib.backup import create_backup,restore_backup,remove_state

def parse_ports(s,default):
  out=[]
  for x in (s or "").split(","):
    x=x.strip()
    if not x:
      continue
    try:
      p=int(x)
    except Exception:
      continue
    if 1<=p<=65535:
      out.append(p)
  return out or list(default)

def env_bool(k,default=False):
  v=os.getenv(k,"").strip().lower()
  if not v:
    return bool(default)
  return v in ("1","y","yes","true","t","on")

def install_menu_command():
  src=str(Path(__file__).resolve())
  dst="/usr/local/bin/menu"
  if Path(dst).exists():
    file_backup(dst)
  s="#!/usr/bin/env bash\nexec /usr/bin/env python3 "+shlex.quote(src)+" \"$@\"\n"
  write_text(dst,s,0o755)
  print("OK")

def show_client_export():
  st=load_state()
  cfg=st.get("ssh_ws",{})
  if not cfg:
    print("not configured")
    return
  ws_path=cfg.get("ws_path",DEFAULT_WS_PATH)
  ports=cfg.get("ws_ports",DEFAULT_WS_PORTS)
  wss=cfg.get("wss_enabled",False)
  wss_port=cfg.get("wss_port",DEFAULT_WSS_PORT)
  domain=st.get("tls",{}).get("domain","")
  ip=""
  try:
    ip=run(["bash","-lc","curl -fsS https://api.ipify.org || true"],check=False,capture=True).stdout.strip()
  except Exception:
    pass
  o={"type":"ssh-over-websocket","ws":{"host":domain or ip or "<host>","ports":ports,"path":ws_path,"tls":False},"wss":{"enabled":bool(wss),"host":domain or ip or "<host>","port":wss_port,"path":ws_path,"tls":True},"ssh_target":cfg.get("target",DEFAULT_SSH_TARGET)}
  print(json.dumps(o,indent=2))

def services_status():
  if not have_systemd():
    print("systemd not detected")
    return
  units=[u.name for u in Path("/etc/systemd/system").glob("vpnmgr-ssh-*.service")]
  out=[]
  for u in sorted(units):
    s=systemctl("is-active",u,check=False).stdout.strip()
    out.append({"unit":u,"active":s})
  print(json.dumps(out,indent=2))

def show_logs():
  if not have_systemd():
    print(read_text("/var/log/vpnmgr.log",""))
    return
  units=[u.name for u in Path("/etc/systemd/system").glob("vpnmgr-ssh-*.service")]
  for u in sorted(units):
    print(f"== {u} ==")
    print(journal_tail(u,80))
    print("")

def diagnostics():
  st=load_state()
  cfg=st.get("ssh_ws",{})
  ports=list(cfg.get("ws_ports",[]))
  if cfg.get("wss_enabled",False):
    ports.append(cfg.get("wss_port",DEFAULT_WSS_PORT))
  if not ports:
    ports=DEFAULT_WS_PORTS[:]
  print(json.dumps({"ports":status_tcp_ports(ports)},indent=2))

def uninstall_all(osinfo):
  if yn("Remove websocket services",True):
    remove_all()
  if yn("Disable SSH 2FA changes",False):
    ssh_disable_2fa(read_text,write_text)
  if yn("Remove websocat binary",False):
    try:
      Path("/usr/local/bin/websocat").unlink()
    except Exception:
      pass
  if yn("Remove state",False):
    remove_state()
  print("OK")

def menu():
  osinfo=detect_os()
  if not is_root():
    print("run as root",file=sys.stderr)
    return 1
  items=[
    ("Install 'menu' command",install_menu_command),
    ("Install/Configure SSH WebSocket (auto defaults)",lambda:configure_ws_auto(osinfo)),
    ("Install/Configure SSH WebSocket (manual)",lambda:configure_ws_manual(osinfo)),
    ("Restart WebSocket services",lambda:(restart_all(),print("OK"))),
    ("Stop WebSocket services",lambda:(stop_all(),print("OK"))),
    ("Remove WebSocket services",lambda:(remove_all(),print("OK"))),
    ("SSH: add user",lambda:add_user()),
    ("SSH: delete user",lambda:del_user()),
    ("SSH: list users",lambda:print("\n".join(ssh_list_users()) or "none")),
    ("SSH: enable 2FA (Google Authenticator PAM)",lambda:(ssh_enable_2fa(osinfo,ensure_packages,file_backup,read_text,write_text),print("OK"))),
    ("SSH: disable 2FA",lambda:(ssh_disable_2fa(read_text,write_text),print("OK"))),
    ("TLS: generate self-signed cert",lambda:(ensure_packages(osinfo,["openssl"]),gen_self_signed(prompt("domain/CN","localhost")),print("OK"))),
    ("TLS: get Let's Encrypt cert",lambda:(gen_letsencrypt(osinfo,prompt("domain"),prompt("email(optional)",""),ensure_packages),print("OK"))),
    ("Firewall: open WS/WSS ports from current config",lambda:open_ports_from_state()),
    ("Enable IPv4/IPv6 forwarding",lambda:(enable_ip_forward(),print("OK"))),
    ("Monitoring: vnstat summary",lambda:(ensure_vnstat(osinfo,ensure_packages),print(json.dumps(vnstat_summary() or {},indent=2)[:20000]))),
    ("Services: status",services_status),
    ("Logs: show",show_logs),
    ("Export client config (JSON)",show_client_export),
    ("Backup config",lambda:print(create_backup())),
    ("Restore from backup",lambda:(restore_backup(prompt("backup path")),print("OK"))),
    ("Run diagnostics",diagnostics),
    ("Uninstall all",lambda:uninstall_all(osinfo)),
    ("Exit",lambda:sys.exit(0)),
  ]
  while True:
    print("\nVPNMgr")
    print(f"os={osinfo['id']} family={osinfo['family']}")
    for i,(t,_) in enumerate(items,1):
      print(f"{i}. {t}")
    sel=prompt("Select",str(len(items)))
    if not sel.isdigit():
      continue
    idx=int(sel)
    if idx<1 or idx>len(items):
      continue
    try:
      items[idx-1][1]()
    except KeyboardInterrupt:
      print("cancelled")
    except SystemExit:
      raise
    except Exception as e:
      print(f"error: {e}")
  return 0

def configure_ws_auto(osinfo):
  ws_path=os.getenv("VPNMGR_WS_PATH",DEFAULT_WS_PATH).strip() or DEFAULT_WS_PATH
  target=os.getenv("VPNMGR_TARGET",DEFAULT_SSH_TARGET).strip() or DEFAULT_SSH_TARGET
  ports=parse_ports(os.getenv("VPNMGR_WS_PORTS",""),DEFAULT_WS_PORTS)
  wss=env_bool("VPNMGR_WSS",True)
  passwd=os.getenv("VPNMGR_WS_PASS","").strip()
  if not passwd:
    passwd=random_password(20)
  tls_mode=os.getenv("VPNMGR_TLS_MODE","").strip().lower()
  domain=os.getenv("VPNMGR_DOMAIN","").strip()
  email=os.getenv("VPNMGR_EMAIL","").strip()
  if wss:
    if tls_mode.startswith("let") or (not tls_mode and domain):
      if domain:
        gen_letsencrypt(osinfo,domain,email,ensure_packages)
      else:
        ensure_packages(osinfo,["openssl"])
        gen_self_signed(socket.getfqdn() or "localhost")
    else:
      ensure_packages(osinfo,["openssl"])
      gen_self_signed(domain or socket.getfqdn() or "localhost")
  configure(ws_path,ports,wss,target,passwd)
  print(json.dumps({"ws_path":ws_path,"target":target,"ws_ports":ports,"wss":bool(wss),"password":passwd},indent=2))

def configure_ws_manual(osinfo):
  ws_path=prompt("WebSocket path",DEFAULT_WS_PATH)
  target=prompt("SSH target host:port",DEFAULT_SSH_TARGET)
  passwd=prompt("WebSocket password (X-Pass optional)","")
  raw=prompt("WS ports (comma separated)",",".join(str(x) for x in DEFAULT_WS_PORTS))
  ports=parse_ports(raw,DEFAULT_WS_PORTS)
  wss=yn("Enable TLS WebSocket on 443 (wss)",True)
  if wss:
    mode=prompt("TLS mode (letsencrypt/self)","letsencrypt").strip().lower()
    if mode.startswith("let"):
      domain=prompt("Domain for TLS cert")
      email=prompt("Email for Let's Encrypt (optional)","")
      gen_letsencrypt(osinfo,domain,email,ensure_packages)
    else:
      ensure_packages(osinfo,["openssl"])
      gen_self_signed(prompt("Domain/CN for self-signed cert","localhost"))
  configure(ws_path,ports,wss,target,passwd)
  print("OK")

def open_ports_from_state():
  st=load_state()
  cfg=st.get("ssh_ws",{})
  ports=list(cfg.get("ws_ports",DEFAULT_WS_PORTS))
  if cfg.get("wss_enabled",False):
    ports.append(cfg.get("wss_port",DEFAULT_WSS_PORT))
  firewall_open_ports(ports,tcp=True,udp=False)
  print("OK")

def add_user():
  u=prompt("username")
  pw=prompt("password (leave empty to auto-generate)","")
  if not pw:
    pw=random_password()
    print(pw)
  days=int(prompt("expire days (0=never)","0") or "0")
  ssh_add_user(u,pw,days if days>0 else None)
  print("OK")

def del_user():
  u=prompt("username")
  ssh_del_user(u,yn("remove home",True))
  print("OK")

if __name__=="__main__":
  raise SystemExit(menu())
