#!/usr/bin/env python3
"""Deploy da frente A no n8n (CT 106) pela API pública, sem reiniciar o n8n. HOMELAB §15.7.

Roda NO CT 106, como root, com os .js ao lado. A chave da API é lida da credential "n8n account"
(decriptada aqui, só em memória) e nunca é impressa; respostas de erro passam por redação.

Uso:
  deploy_n8n.py check                 testa a chave da API
  deploy_n8n.py ipintel               A3 + A0.1: valida IP público e troca o token fixo do ipinfo pela credential "ipinfo"
  deploy_n8n.py ipintel-test          chama o webhook ip-intel com 1 IP público e 3 inválidos
  deploy_n8n.py oldtoken              confere se o token ANTIGO do ipinfo (no backup) ainda responde
  deploy_n8n.py relay-cred vps1|vps2  cria a credential SSH do relay (chave em /root/.secrets/, nunca impressa)
  deploy_n8n.py workflow [CHANNEL_ID] cria/atualiza e publica o workflow "🛡️ Segurança VPS1 → Discord"
  deploy_n8n.py honeypot [CHANNEL_ID] cria/atualiza e publica o workflow "🍯 Honeypot VPS2 → Discord" (frente D)
  deploy_n8n.py code WF_ID "NÓ" ARQ.js [CHANNEL_ID]
                                      troca SÓ o jsCode de um Code node (16/10). Preserva todo o resto do workflow:
                                      ids, webhookId, IP whitelist dos webhooks, staticData (dedupe). Prefira isto a
                                      "status"/"workflow", que reconstroem o workflow do zero e perderiam a IP whitelist.
  deploy_n8n.py proxmox-cred ARQ.json S27 (16/10): cria a credential com o token de privilégio mínimo (JSON do pveum, 600,
                                      nunca impresso) e troca SÓ a referência de credencial nos nós do workflow do Proxmox
  deploy_n8n.py proxmox-rollback      volta os nós para a credential antiga ("Proxmox", token root)
  deploy_n8n.py heartbeat             tarefa 5 (16/10): cria DESATIVADO o workflow "💓 Heartbeat casa → Healthchecks.io"
                                      (a cada 5 min, GET no link do check). O dono cola o link no nó e ativa pela UI
"""
import json, pathlib, re, subprocess, sys, urllib.error, urllib.request, uuid

API = "http://127.0.0.1:5678/api/v1"
N8N_API_CRED = "ID_CREDENTIAL_N8N_API"   # "n8n account" (n8nApi)
IPINTEL_ID = "ID_WORKFLOW_IP_INTEL"
NOTIFY_CRED = {"id": "ID_CREDENTIAL_NOTIFY", "name": "Discord Bot Notify"}  # X-Notify-Key do discord-bot
RELAYS = {
    "vps1": {"key": "/root/.secrets/crowdsec-relay", "name": "VPS1 crowdsec-relay (só leitura)",
             "host": "203.0.113.10", "port": 22, "user": "crowdsec-relay"},
    "vps2": {"key": "/root/.secrets/hp-relay", "name": "VPS2 hp-relay honeypot (só leitura)",
             "host": "203.0.113.20", "port": 22022, "user": "hp-relay"},
}
RELAY_CRED_NAME = RELAYS["vps1"]["name"]
WF_NAME = "🛡️ Segurança VPS1 → Discord"
HP_WF_NAME = "🍯 Honeypot VPS2 → Discord"
BACKUP = "/root/backup-20261014/n8n-workflows-all.json"
SETTINGS_OK = {"saveExecutionProgress", "saveManualExecutions", "saveDataErrorExecution", "saveDataSuccessExecution",
               "executionTimeout", "errorWorkflow", "timezone", "executionOrder", "callerPolicy", "callerIds",
               "timeSavedPerExecution", "availableInMCP"}
HERE = pathlib.Path(__file__).resolve().parent
KEY = None


def safe(s):
    s = str(s)[:600]
    s = re.sub(r"[0-9a-fA-F]{12,}", "<HEX>", s)
    return re.sub(r"\d{10,}", "<NUM>", s)


def n8n_cli(*args):
    return subprocess.run(["docker", "exec", "n8n", "n8n", *args], capture_output=True, text=True).stdout


def first_json(raw):
    return json.JSONDecoder().raw_decode(raw[min(i for i in (raw.find("["), raw.find("{")) if i >= 0):])[0]


def load_key():
    global KEY
    d = first_json(n8n_cli("export:credentials", f"--id={N8N_API_CRED}", "--decrypted"))
    KEY = d[0]["data"]["apiKey"]


def call(method, path, body=None, url=None):
    req = urllib.request.Request(url or API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-N8N-API-KEY": KEY or "", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, safe((e.read() or b"").decode(errors="replace"))


def creds():
    st, d = call("GET", "/credentials?limit=250")
    return {c["name"]: c for c in (d or {}).get("data", [])} if st == 200 else {}


def put_workflow(wf):
    body = {"name": wf["name"], "nodes": wf["nodes"], "connections": wf["connections"],
            "settings": {k: v for k, v in (wf.get("settings") or {}).items() if k in SETTINGS_OK}}
    if wf.get("staticData") is not None:
        body["staticData"] = wf["staticData"]
    return call("PUT", f"/workflows/{wf['id']}", body)


def cmd_check():
    st, _ = call("GET", "/workflows?limit=1")
    print("API do n8n:", st, "(200 = chave válida)")


def cmd_ipintel():
    st, wf = call("GET", f"/workflows/{IPINTEL_ID}")
    assert st == 200, f"GET ip-intel: {st}"
    nodes = {n["name"]: n for n in wf["nodes"]}
    nodes["Prepare IP"]["parameters"]["jsCode"] = (HERE / "ip-intel-prepare-ip.js").read_text()
    print("Prepare IP: validação de IP público aplicada")
    info, cred = nodes["IPInfo Request"], creds().get("ipinfo")
    if cred and cred["type"] == "httpQueryAuth":
        p = info["parameters"]
        qp = [x for x in (p.get("queryParameters") or {}).get("parameters", []) if x.get("name") != "token"]
        if qp:
            p["queryParameters"] = {"parameters": qp}
        else:
            p.pop("queryParameters", None)
            p["sendQuery"] = False
        p["authentication"], p["genericAuthType"] = "genericCredentialType", "httpQueryAuth"
        info["credentials"] = {"httpQueryAuth": {"id": cred["id"], "name": cred["name"]}}
        print("IPInfo Request: token fixo removido → credential", cred["id"])
    else:
        print("IPInfo Request: credential 'ipinfo' (Query Auth) ainda não existe → token fixo mantido por enquanto")
    st, res = put_workflow(wf)
    print("PUT ip-intel:", st, "" if st == 200 else res)
    st, wf2 = call("GET", f"/workflows/{IPINTEL_ID}")
    still = any(x.get("name") == "token" for n in wf2["nodes"] if n["name"] == "IPInfo Request"
                for x in (n["parameters"].get("queryParameters") or {}).get("parameters", []))
    print("publicado:", wf2.get("active"), "· token fixo ainda no workflow:", still)


def cmd_ipintel_test():
    for ip in ("1.1.1.1", "10.0.0.1", "198.51.100.7", "999.1.1.1"):
        st, r = call("POST", None, {"ip": ip}, url="http://127.0.0.1:5678/webhook/ip-intel")
        if st == 200 and isinstance(r, dict):
            print(f"{ip}: 200 · {r.get('country')} · {r.get('asn')} {r.get('org')} · risco {r.get('risk')} · fontes {r.get('sources')}")
        else:
            print(f"{ip}: {st} · {safe(r)[:160]}")


def cmd_oldtoken():
    old = None
    for w in first_json(open(BACKUP).read()):
        for n in w["nodes"]:
            if w["id"] == IPINTEL_ID and n["name"] == "IPInfo Request":
                old = next((x["value"] for x in n["parameters"].get("queryParameters", {}).get("parameters", []) if x.get("name") == "token"), None)
    st, _ = call("GET", None, url=f"https://ipinfo.io/1.1.1.1/json?token={old}") if old else (None, None)
    print("token antigo no backup:", bool(old), "· ipinfo responde com ele:", st, "(403/401 = revogado; 200 = AINDA VÁLIDO)")


def cmd_relay_cred(which="vps1"):
    r = RELAYS[which]
    if r["name"] in creds():
        print(f"credential do relay {which} já existe")
        return
    st, schema = call("GET", "/credentials/schema/sshPrivateKey")
    print("schema sshPrivateKey:", st, sorted((schema or {}).get("properties", {}).keys()) if st == 200 else schema)
    st, res = call("POST", "/credentials", {"name": r["name"], "type": "sshPrivateKey", "data": {
        "host": r["host"], "port": r["port"], "username": r["user"],
        "privateKey": open(r["key"]).read(), "passphrase": ""}})
    print(f"POST credential do relay {which}:", st, "" if st in (200, 201) else "(erro omitido: pode conter a chave)")


def build(ssh_cred, channel):
    def node(name, type_, ver, params, pos, **extra):
        n = {"id": str(uuid.uuid4()), "name": name, "type": type_, "typeVersion": ver, "position": pos, "parameters": params}
        n.update(extra)
        return n

    def js(fname):
        return (HERE / fname).read_text().replace("__CHANNEL_ID__", channel)

    sshc = {"sshPrivateKey": {"id": ssh_cred["id"], "name": ssh_cred["name"]}}
    sched = lambda rule: {"rule": {"interval": [rule]}}
    ssh = lambda cmd: {"authentication": "privateKey", "command": cmd, "cwd": "/"}
    code = lambda f: {"jsCode": js(f)}
    if_params = {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 2},
                                "conditions": [{"id": str(uuid.uuid4()), "leftValue": "={{ $json.route }}", "rightValue": "enrich",
                                                "operator": {"type": "string", "operation": "equals"}}],
                                "combinator": "and"}, "options": {}}
    nodes = [
        node("⏱️ A cada 1 min", "n8n-nodes-base.scheduleTrigger", 1.2, sched({"field": "minutes", "minutesInterval": 1}), [0, 0]),
        node("⏱️ A cada 15 min", "n8n-nodes-base.scheduleTrigger", 1.2, sched({"field": "minutes", "minutesInterval": 15}), [0, 400]),
        node("⏰ Resumo 08:00", "n8n-nodes-base.scheduleTrigger", 1.2, sched({"field": "days", "triggerAtHour": 8}), [0, 600]),
        node("SSH: alerts", "n8n-nodes-base.ssh", 1, ssh("alerts"), [220, 0], credentials=sshc, onError="continueRegularOutput"),
        node("SSH: stats (saúde)", "n8n-nodes-base.ssh", 1, ssh("stats"), [220, 400], credentials=sshc, onError="continueRegularOutput"),
        node("SSH: stats (resumo)", "n8n-nodes-base.ssh", 1, ssh("stats"), [220, 600], credentials=sshc, onError="continueRegularOutput"),
        node("Processar alertas", "n8n-nodes-base.code", 2, code("processar-alertas.js"), [440, 0]),
        node("Checar saúde", "n8n-nodes-base.code", 2, code("checar-saude.js"), [440, 400]),
        node("Montar resumo", "n8n-nodes-base.code", 2, code("montar-resumo.js"), [440, 600]),
        node("Enriquecer?", "n8n-nodes-base.if", 2.2, if_params, [660, 0]),
        node("📍 IP Intel", "n8n-nodes-base.httpRequest", 4.2, {
            "method": "POST", "url": "http://127.0.0.1:5678/webhook/ip-intel", "sendBody": True, "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify({ ip: $json.ip }) }}", "options": {"timeout": 30000}}, [880, -140],
            onError="continueRegularOutput"),
        node("Juntar alerta + intel", "n8n-nodes-base.merge", 3, {"mode": "combine", "combineBy": "combineByPosition", "options": {}}, [1100, -60]),
        node("Montar aviso de ban", "n8n-nodes-base.code", 2, code("montar-aviso-ban.js"), [1320, -60]),
        node("Discord (bot /notify)", "n8n-nodes-base.httpRequest", 4.2, {
            "method": "POST", "url": "http://192.168.50.31:3001/notify", "authentication": "genericCredentialType",
            "genericAuthType": "httpHeaderAuth", "sendBody": True, "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify($json.payload) }}", "options": {"timeout": 15000}}, [1540, 240],
            credentials={"httpHeaderAuth": NOTIFY_CRED}),
    ]
    to = lambda *t: {"main": [[{"node": n, "type": "main", "index": i} for n, i in t]]}
    conns = {
        "⏱️ A cada 1 min": to(("SSH: alerts", 0)),
        "⏱️ A cada 15 min": to(("SSH: stats (saúde)", 0)),
        "⏰ Resumo 08:00": to(("SSH: stats (resumo)", 0)),
        "SSH: alerts": to(("Processar alertas", 0)),
        "SSH: stats (saúde)": to(("Checar saúde", 0)),
        "SSH: stats (resumo)": to(("Montar resumo", 0)),
        "Processar alertas": to(("Enriquecer?", 0)),
        "Enriquecer?": {"main": [[{"node": "📍 IP Intel", "type": "main", "index": 0},
                                  {"node": "Juntar alerta + intel", "type": "main", "index": 0}],
                                 [{"node": "Discord (bot /notify)", "type": "main", "index": 0}]]},
        "📍 IP Intel": to(("Juntar alerta + intel", 1)),
        "Juntar alerta + intel": to(("Montar aviso de ban", 0)),
        "Montar aviso de ban": to(("Discord (bot /notify)", 0)),
        "Checar saúde": to(("Discord (bot /notify)", 0)),
        "Montar resumo": to(("Discord (bot /notify)", 0)),
    }
    return {"name": WF_NAME, "nodes": nodes, "connections": conns, "settings": SETTINGS}


SETTINGS = {"executionOrder": "v1", "saveDataSuccessExecution": "none", "saveDataErrorExecution": "all",
            "saveManualExecutions": True, "timezone": "America/Sao_Paulo", "callerPolicy": "workflowsFromSameOwner"}


def build_hp(ssh_cred, channel):
    """🍯 Honeypot VPS2: saúde a cada 15 min + resumo diário às 08:05 (frente D)."""
    def node(name, type_, ver, params, pos, **extra):
        n = {"id": str(uuid.uuid4()), "name": name, "type": type_, "typeVersion": ver, "position": pos, "parameters": params}
        n.update(extra)
        return n

    sshc = {"sshPrivateKey": {"id": ssh_cred["id"], "name": ssh_cred["name"]}}
    js = lambda f: {"jsCode": (HERE / f).read_text().replace("__CHANNEL_ID__", channel)}
    ssh = {"authentication": "privateKey", "command": "stats", "cwd": "/"}
    nodes = [
        node("⏱️ A cada 15 min", "n8n-nodes-base.scheduleTrigger", 1.2, {"rule": {"interval": [{"field": "minutes", "minutesInterval": 15}]}}, [0, 0]),
        node("⏰ Resumo 08:05", "n8n-nodes-base.scheduleTrigger", 1.2, {"rule": {"interval": [{"field": "days", "triggerAtHour": 8, "triggerAtMinute": 5}]}}, [0, 240]),
        node("SSH: stats (saúde)", "n8n-nodes-base.ssh", 1, ssh, [220, 0], credentials=sshc, onError="continueRegularOutput"),
        node("SSH: stats (resumo)", "n8n-nodes-base.ssh", 1, ssh, [220, 240], credentials=sshc, onError="continueRegularOutput"),
        node("Checar honeypot", "n8n-nodes-base.code", 2, js("checar-honeypot.js"), [440, 0]),
        node("Montar resumo do honeypot", "n8n-nodes-base.code", 2, js("montar-resumo-honeypot.js"), [440, 240]),
        node("Discord (bot /notify)", "n8n-nodes-base.httpRequest", 4.2, {
            "method": "POST", "url": "http://192.168.50.31:3001/notify", "authentication": "genericCredentialType",
            "genericAuthType": "httpHeaderAuth", "sendBody": True, "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify($json.payload) }}", "options": {"timeout": 15000}}, [680, 120],
            credentials={"httpHeaderAuth": NOTIFY_CRED}),
    ]
    to = lambda n: {"main": [[{"node": n, "type": "main", "index": 0}]]}
    conns = {"⏱️ A cada 15 min": to("SSH: stats (saúde)"), "⏰ Resumo 08:05": to("SSH: stats (resumo)"),
             "SSH: stats (saúde)": to("Checar honeypot"), "SSH: stats (resumo)": to("Montar resumo do honeypot"),
             "Checar honeypot": to("Discord (bot /notify)"), "Montar resumo do honeypot": to("Discord (bot /notify)")}
    return {"name": HP_WF_NAME, "nodes": nodes, "connections": conns, "settings": SETTINGS}


STATUS_WF_NAME = "📊 Status de segurança (Homepage)"


def build_status(cred1, cred2):
    """A6: GET /webhook/homelab-seguranca-status (só LAN, sem segredo, cache de 60 s) → JSON para o customapi do Homepage."""
    def node(name, type_, ver, params, pos, **extra):
        n = {"id": str(uuid.uuid4()), "name": name, "type": type_, "typeVersion": ver, "position": pos, "parameters": params}
        n.update(extra)
        return n
    ssh = {"authentication": "privateKey", "command": "stats", "cwd": "/"}
    cache_js = ("const S = $getWorkflowStaticData('global');\n"
                "const fresh = !!(S.cache && (Date.now() - S.cache.at) < 60000);\n"
                "return [{ json: { fresh, body: fresh ? S.cache.body : null } }];\n")
    if_params = {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 2},
                                "conditions": [{"id": str(uuid.uuid4()), "leftValue": "={{ $json.fresh }}", "rightValue": "",
                                                "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
                                "combinator": "and"}, "options": {}}
    nodes = [
        node("Webhook (GET status)", "n8n-nodes-base.webhook", 2, {"httpMethod": "GET", "path": "homelab-seguranca-status",
             "responseMode": "responseNode", "options": {}}, [0, 0], webhookId=str(uuid.uuid4())),
        node("Cache de 60 s", "n8n-nodes-base.code", 2, {"jsCode": cache_js}, [220, 0]),
        node("Cache fresco?", "n8n-nodes-base.if", 2.2, if_params, [440, 0]),
        node("SSH: stats VPS1", "n8n-nodes-base.ssh", 1, ssh, [660, 120],
             credentials={"sshPrivateKey": {"id": cred1["id"], "name": cred1["name"]}}, onError="continueRegularOutput"),
        node("SSH: stats VPS2", "n8n-nodes-base.ssh", 1, ssh, [880, 120],
             credentials={"sshPrivateKey": {"id": cred2["id"], "name": cred2["name"]}}, onError="continueRegularOutput"),
        node("Montar status", "n8n-nodes-base.code", 2, {"jsCode": (HERE / "status-homepage.js").read_text()}, [1100, 120]),
        node("Responder", "n8n-nodes-base.respondToWebhook", 1.1, {"respondWith": "json",
             "responseBody": "={{ JSON.stringify($json.body) }}", "options": {}}, [1320, 0]),
    ]
    to = lambda n, i=0: {"node": n, "type": "main", "index": i}
    conns = {"Webhook (GET status)": {"main": [[to("Cache de 60 s")]]},
             "Cache de 60 s": {"main": [[to("Cache fresco?")]]},
             "Cache fresco?": {"main": [[to("Responder")], [to("SSH: stats VPS1")]]},
             "SSH: stats VPS1": {"main": [[to("SSH: stats VPS2")]]},
             "SSH: stats VPS2": {"main": [[to("Montar status")]]},
             "Montar status": {"main": [[to("Responder")]]}}
    return {"name": STATUS_WF_NAME, "nodes": nodes, "connections": conns, "settings": SETTINGS}


def cmd_workflow(channel="", kind="vps1"):
    if kind == "status":
        c = creds()
        wf = build_status(c[RELAYS["vps1"]["name"]], c[RELAYS["vps2"]["name"]])
    else:
        ssh_cred = creds().get(RELAYS[kind]["name"])
        assert ssh_cred, f"falta a credential do relay {kind} (rode relay-cred {kind} antes)"
        wf = build(ssh_cred, channel) if kind == "vps1" else build_hp(ssh_cred, channel)
    st, lst = call("GET", "/workflows?limit=250")
    existing = next((w for w in (lst or {}).get("data", []) if w["name"] == wf["name"]), None)
    if existing:
        st, cur = call("GET", f"/workflows/{existing['id']}")
        wf["id"], wf["staticData"] = existing["id"], cur.get("staticData")
        st, res = put_workflow(wf)
        print("PUT workflow:", st, "" if st == 200 else res)
        wid = existing["id"]
    else:
        st, res = call("POST", "/workflows", wf)
        print("POST workflow:", st, "" if st in (200, 201) else res)
        wid = res["id"] if isinstance(res, dict) else None
    if wid:
        st, res = call("POST", f"/workflows/{wid}/activate", {})
        print("publicar:", st, "" if st == 200 else res)
        st, w = call("GET", f"/workflows/{wid}")
        print("workflow", wid, "· publicado:", w.get("active"), "· canal:", channel or "alert (padrão do bot)")


def cmd_code(wf_id, node_name, js_file, channel=""):
    st, wf = call("GET", f"/workflows/{wf_id}")
    assert st == 200, f"GET workflow {wf_id}: {st}"
    node = next((n for n in wf["nodes"] if n["name"] == node_name), None)
    assert node and node["type"] == "n8n-nodes-base.code", f"Code node '{node_name}' não encontrado"
    new = (HERE / js_file).read_text()
    if channel:
        new = new.replace("__CHANNEL_ID__", channel)
    assert "__CHANNEL_ID__" not in new or not channel, "placeholder de canal sobrou"
    old = node["parameters"].get("jsCode", "")
    if old == new:
        print("jsCode já é igual ao arquivo: nada a fazer")
        return
    node["parameters"]["jsCode"] = new
    active_before = wf.get("active")
    st, res = put_workflow(wf)  # mesmo corpo do GET (nós, conexões, staticData); só o jsCode mudou
    print("PUT workflow:", st, "" if st == 200 else res)
    st, w2 = call("GET", f"/workflows/{wf_id}")
    n2 = next(n for n in w2["nodes"] if n["name"] == node_name)
    print(f"{wf_id} · '{node_name}' atualizado: {n2['parameters'].get('jsCode') == new} · publicado: antes {active_before}, agora {w2.get('active')}")


PROXMOX_WF = "ID_WORKFLOW_PROXMOX"           # 📊 Proxmox Status Dashboard v2 (webhook proxmox-status, IP whitelist)
PROXMOX_OLD = {"id": "ID_CREDENTIAL_PROXMOX", "name": "Proxmox"}   # token root@pam!proxmox-n8n (S27)
PROXMOX_NEW_NAME = "Proxmox (n8n@pve, privilégio mínimo)"


def _swap_proxmox_cred(src_id, dst):
    st, wf = call("GET", f"/workflows/{PROXMOX_WF}")
    assert st == 200, f"GET workflow do Proxmox: {st}"
    n = 0
    for node in wf["nodes"]:
        cr = (node.get("credentials") or {}).get("httpHeaderAuth")
        if cr and cr.get("id") == src_id:
            node["credentials"]["httpHeaderAuth"] = {"id": dst["id"], "name": dst["name"]}
            n += 1
    if not n:
        print("nenhum nó usava a credential de origem: nada a fazer")
        return
    st, res = put_workflow(wf)  # mesmo corpo do GET: webhook, IP whitelist e staticData intactos
    print(f"PUT workflow: {st} · {n} nós trocados para '{dst['name']}'", "" if st == 200 else res)
    st, w2 = call("GET", f"/workflows/{PROXMOX_WF}")
    left = sum(1 for x in w2["nodes"] if ((x.get("credentials") or {}).get("httpHeaderAuth") or {}).get("id") == src_id)
    print("publicado:", w2.get("active"), "· nós ainda na credential de origem:", left)


def cmd_proxmox_cred(token_json):
    t = json.load(open(token_json))
    value = f"PVEAPIToken={t['full-tokenid']}={t['value']}"
    new = creds().get(PROXMOX_NEW_NAME)
    if new:
        print("a credential nova já existe: não recrio (para trocar o token, apague-a na UI e rode de novo)")
    else:
        st, res = call("POST", "/credentials", {"name": PROXMOX_NEW_NAME, "type": "httpHeaderAuth",
                                                 "data": {"name": "Authorization", "value": value}})
        print("POST credential:", st, "" if st in (200, 201) else "(erro omitido: pode conter o token)")
        assert st in (200, 201) and isinstance(res, dict)
        new = res
    _swap_proxmox_cred(PROXMOX_OLD["id"], {"id": new["id"], "name": PROXMOX_NEW_NAME})


def cmd_proxmox_rollback():
    new = creds().get(PROXMOX_NEW_NAME)
    assert new, "credential nova não existe"
    _swap_proxmox_cred(new["id"], PROXMOX_OLD)


HB_WF_NAME = "💓 Heartbeat casa → Healthchecks.io"
HB_PLACEHOLDER = "https://hc-ping.com/COLE-AQUI-O-UUID-DO-CHECK"
HB_NOTE = """## 💓 Aviso de "casa fora do ar" (tarefa 5, HOMELAB §15.12.4)
A cada 5 min este workflow "pinga" o Healthchecks.io. Se a energia, a internet, o Proxmox, o CT 106 ou o n8n pararem,
os pings param e o Healthchecks avisa no Discord (ele roda fora de casa).

**Para ligar (uma vez):**
1. No Healthchecks.io, copie o *Ping URL* do check (`https://hc-ping.com/…`). **Não cole no chat.**
2. Abra o nó **Ping Healthchecks** e troque a URL de exemplo por ela.
3. Salve e **ative** o workflow (botão no canto superior direito).
4. Em ~1 min o check fica verde ("up") no Healthchecks.

Execuções com sucesso não são salvas (seriam 288/dia); as com erro, sim."""


def build_heartbeat():
    def node(name, type_, ver, params, pos, **extra):
        n = {"id": str(uuid.uuid4()), "name": name, "type": type_, "typeVersion": ver, "position": pos, "parameters": params}
        n.update(extra)
        return n
    nodes = [
        node("Instruções", "n8n-nodes-base.stickyNote", 1, {"content": HB_NOTE, "height": 420, "width": 520, "color": 4}, [-560, -160]),
        node("⏱️ A cada 5 min", "n8n-nodes-base.scheduleTrigger", 1.2,
             {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}]}}, [0, 0]),
        node("Ping Healthchecks", "n8n-nodes-base.httpRequest", 4.2,
             {"method": "GET", "url": HB_PLACEHOLDER, "options": {"timeout": 15000}}, [240, 0],
             retryOnFail=True, maxTries=3, waitBetweenTries=5000),
    ]
    conns = {"⏱️ A cada 5 min": {"main": [[{"node": "Ping Healthchecks", "type": "main", "index": 0}]]}}
    return {"name": HB_WF_NAME, "nodes": nodes, "connections": conns, "settings": SETTINGS}


def cmd_heartbeat():
    st, lst = call("GET", "/workflows?limit=250")
    if any(w["name"] == HB_WF_NAME for w in (lst or {}).get("data", [])):
        print("o workflow já existe: não mexo (pode já ter o link do dono)")
        return
    st, res = call("POST", "/workflows", build_heartbeat())
    print("POST workflow:", st, "" if st in (200, 201) else res)
    if isinstance(res, dict):
        print("criado", res.get("id"), "· ativo:", res.get("active"), "(fica desativado até o dono colar o link)")


if __name__ == "__main__":
    load_key()
    cmd, args = (sys.argv[1] if len(sys.argv) > 1 else "check"), sys.argv[2:]
    {"check": cmd_check, "ipintel": cmd_ipintel, "ipintel-test": cmd_ipintel_test, "oldtoken": cmd_oldtoken,
     "relay-cred": lambda: cmd_relay_cred(*args), "workflow": lambda: cmd_workflow(*args[:1]),
     "honeypot": lambda: cmd_workflow(*(args[:1] or [""]), kind="vps2"),
     "status": lambda: cmd_workflow("", kind="status"),
     "code": lambda: cmd_code(*args[:4]),
     "proxmox-cred": lambda: cmd_proxmox_cred(*args[:1]), "proxmox-rollback": cmd_proxmox_rollback,
     "heartbeat": cmd_heartbeat}[cmd]()
