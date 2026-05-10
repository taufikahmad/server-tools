from pathlib import Path
from .core import load_state,save_state,write_text,file_backup
from .system import systemd_unit,systemctl,stop_disable_unit,have_systemd,firewall_open_ports
from .tls import tls_paths_required

DEFAULT_WS_PORTS=[80,8080,2082]
DEFAULT_WSS_PORT=443
DEFAULT_WS_PATH="/ws"
DEFAULT_SSH_TARGET="127.0.0.1:22"
WS_SERVER_PATH="/usr/local/bin/vpnmgr_ws_server.py"

def unit_name(port,secure):
  p="wss" if secure else "ws"
  return f"vpnmgr-ssh-{p}-{int(port)}"

def ensure_ws_server_script():
  if Path(WS_SERVER_PATH).exists():
    file_backup(WS_SERVER_PATH)
  script="""#!/usr/bin/env python3
import argparse,select,socket,ssl,sys,threading,time

BUFLEN=16384
TIMEOUT=60
RESPONSE=b"HTTP/1.1 101 Switching Protocols\\r\\n\\r\\n"

def parse_req(data):
  try:
    s=data.decode("iso-8859-1","ignore")
  except Exception:
    s=""
  lines=s.split("\\r\\n")
  req=lines[0] if lines else ""
  h={}
  for ln in lines[1:]:
    if not ln:
      break
    if ":" in ln:
      k,v=ln.split(":",1)
      h[k.strip().lower()]=v.strip()
  return req,h

def get_header(h,k):
  return h.get(k.lower(),"")

def allowed_target(hostport,passwd,required_pass):
  if required_pass:
    return passwd==required_pass
  hp=(hostport or "").lower()
  return hp.startswith("127.0.0.1") or hp.startswith("localhost")

def connect_target(hostport,default_host):
  hp=hostport or ""
  if not hp:
    hp=default_host
  if ":" in hp:
    host,port=hp.rsplit(":",1)
    port=int(port)
  else:
    host=hp
    port=22
  (fam,typ,proto,_,addr)=socket.getaddrinfo(host,port,0,socket.SOCK_STREAM)[0]
  s=socket.socket(fam,typ,proto)
  s.connect(addr)
  return s

def pipe(client,target):
  client.setblocking(False)
  target.setblocking(False)
  socs=[client,target]
  idle=0
  while True:
    r,_,e=select.select(socs,[],socs,3)
    if e:
      break
    if r:
      for src in r:
        try:
          data=src.recv(BUFLEN)
        except Exception:
          return
        if not data:
          return
        dst=target if src is client else client
        off=0
        while off<len(data):
          try:
            n=dst.send(data[off:])
          except Exception:
            return
          if n<=0:
            return
          off+=n
      idle=0
    else:
      idle+=1
      if idle>=TIMEOUT:
        break

def handle(conn,args):
  try:
    buf=conn.recv(BUFLEN)
    req,h=parse_req(buf)
    if args.path:
      try:
        parts=req.split()
        if len(parts)>=2:
          p=parts[1]
          if p!=args.path:
            conn.sendall(b"HTTP/1.1 400 BadRequest\\r\\n\\r\\n")
            return
      except Exception:
        conn.sendall(b"HTTP/1.1 400 BadRequest\\r\\n\\r\\n")
        return
    hostport=get_header(h,"x-real-host") or args.default_host
    split=get_header(h,"x-split")
    if split:
      try:
        conn.recv(BUFLEN)
      except Exception:
        pass
    passwd=get_header(h,"x-pass")
    if not allowed_target(hostport,passwd,args.passwd):
      if args.passwd and passwd!=args.passwd:
        conn.sendall(b"HTTP/1.1 400 WrongPass!\\r\\n\\r\\n")
      else:
        conn.sendall(b"HTTP/1.1 403 Forbidden!\\r\\n\\r\\n")
      return
    target=connect_target(hostport,args.default_host)
    conn.sendall(RESPONSE)
    pipe(conn,target)
  except Exception:
    try:
      conn.sendall(b"HTTP/1.1 500 Error\\r\\n\\r\\n")
    except Exception:
      pass
  finally:
    try:
      conn.close()
    except Exception:
      pass

def main():
  ap=argparse.ArgumentParser()
  ap.add_argument("--bind",default="::")
  ap.add_argument("--port",type=int,required=True)
  ap.add_argument("--path",default="")
  ap.add_argument("--default-host",default="127.0.0.1:22")
  ap.add_argument("--pass",dest="passwd",default="")
  ap.add_argument("--tls",action="store_true")
  ap.add_argument("--cert",default="")
  ap.add_argument("--key",default="")
  args=ap.parse_args()
  s=None
  fam=socket.AF_INET6 if ":" in args.bind else socket.AF_INET
  for try_fam,try_bind in ((fam,args.bind),(socket.AF_INET6,"::"),(socket.AF_INET,"0.0.0.0")):
    try:
      s=socket.socket(try_fam,socket.SOCK_STREAM)
      if try_fam==socket.AF_INET6:
        try:
          s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        except Exception:
          pass
      s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
      try:
        s.setsockopt(socket.SOL_SOCKET,getattr(socket,"SO_REUSEPORT"),1)
      except Exception:
        pass
      s.bind((try_bind,args.port))
      break
    except Exception:
      try:
        if s:
          s.close()
      except Exception:
        pass
      s=None
  if s is None:
    print("bind failed",file=sys.stderr)
    sys.exit(1)
  s.listen(256)
  ctx=None
  if args.tls:
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert,keyfile=args.key)
  while True:
    try:
      c,_=s.accept()
    except Exception as e:
      print(str(e),file=sys.stderr)
      time.sleep(1)
      continue
    if ctx:
      try:
        c=ctx.wrap_socket(c,server_side=True)
      except Exception:
        try:
          c.close()
        except Exception:
          pass
        continue
    t=threading.Thread(target=handle,args=(c,args),daemon=True)
    t.start()

if __name__=="__main__":
  main()
"""
  write_text(WS_SERVER_PATH,script,0o755)

def make_wsraw_unit(port,secure,ws_path,target,passwd):
  if not have_systemd():
    raise RuntimeError("systemd required")
  ensure_ws_server_script()
  if secure:
    cert,key=tls_paths_required()
    cmd=f"/usr/bin/env python3 {WS_SERVER_PATH} --bind :: --port {int(port)} --path={ws_path} --default-host={target} --pass={passwd} --tls --cert={cert} --key={key}"
  else:
    cmd=f"/usr/bin/env python3 {WS_SERVER_PATH} --bind :: --port {int(port)} --path={ws_path} --default-host={target} --pass={passwd}"
  name=unit_name(port,secure)
  u=f"""[Unit]
Description=VPNMgr SSH WebSocket ({'TLS' if secure else 'Plain'}) {int(port)}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart={cmd}
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
"""
  systemd_unit(name,u)
  systemctl("enable","--now",f"{name}.service",check=True)
  return name

def configure(ws_path,ws_ports,wss_enabled,target,passwd=""):
  p=ws_path if ws_path and ws_path.startswith("/") else "/"+(ws_path or DEFAULT_WS_PATH.lstrip("/"))
  ports=[int(x) for x in (ws_ports or DEFAULT_WS_PORTS)]
  st=load_state()
  st.setdefault("ssh_ws",{})
  st["ssh_ws"]["ws_path"]=p
  st["ssh_ws"]["target"]=target or DEFAULT_SSH_TARGET
  st["ssh_ws"]["pass"]=passwd or ""
  st["ssh_ws"]["ws_ports"]=ports
  st["ssh_ws"]["wss_enabled"]=bool(wss_enabled)
  st["ssh_ws"]["wss_port"]=DEFAULT_WSS_PORT
  save_state(st)
  opened=ports[:]
  if wss_enabled:
    opened.append(DEFAULT_WSS_PORT)
  firewall_open_ports(opened,tcp=True,udp=False)
  for port in ports:
    make_wsraw_unit(port,False,p,st["ssh_ws"]["target"],st["ssh_ws"]["pass"])
  if wss_enabled:
    make_wsraw_unit(DEFAULT_WSS_PORT,True,p,st["ssh_ws"]["target"],st["ssh_ws"]["pass"])

def restart_all():
  if not have_systemd():
    raise RuntimeError("systemd required")
  for u in Path("/etc/systemd/system").glob("vpnmgr-ssh-*.service"):
    systemctl("restart",u.name,check=False)

def stop_all():
  if not have_systemd():
    raise RuntimeError("systemd required")
  for u in Path("/etc/systemd/system").glob("vpnmgr-ssh-*.service"):
    systemctl("stop",u.name,check=False)

def remove_all():
  if not have_systemd():
    raise RuntimeError("systemd required")
  for u in list(Path("/etc/systemd/system").glob("vpnmgr-ssh-*.service")):
    stop_disable_unit(u.name.replace(".service",""))
  systemctl("daemon-reload",check=False)
  st=load_state()
  st.pop("ssh_ws",None)
  save_state(st)
