"""AndroAI Dashboard - Flask backend."""
from flask import Flask, jsonify, render_template, request
import sqlite3, os, json, glob

app = Flask(__name__)
_AD = os.path.dirname(os.path.abspath(__file__))

_cfg = os.path.join(_AD, "config.env")
if os.path.isfile(_cfg):
    with open(_cfg, "r") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

ANDROAI_DIR = os.environ.get("ANDROAI_DIR", "")
if not ANDROAI_DIR:
    for c in [os.path.join(_AD, "..", "old_llm_with_custom_agent_editor", "llm_V1"),
              os.path.join(_AD, "..", "androAiV2", "llm_V1")]:
        if os.path.isdir(os.path.join(c, "generated_rules")):
            ANDROAI_DIR = c; break
    if not ANDROAI_DIR: ANDROAI_DIR = os.path.join(_AD, "..", "llm_V1")

LDB = os.environ.get("LEDGER_DB", os.path.join(ANDROAI_DIR, "generated_rules", "androai_ledger.sqlite"))
YDB = os.environ.get("YARA_REG_DB", os.path.join(ANDROAI_DIR, "generated_rules", "yara_rule_registry.sqlite"))
SNORT_DIR = os.path.join(ANDROAI_DIR, "generated_rules", "snort")
print(f"[dashboard] LEDGER={LDB}"); print(f"[dashboard] YARA_REG={YDB}")

def _q(db, sql, p=()):
    if not os.path.isfile(db): return []
    try:
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True,timeout=5);c.row_factory=sqlite3.Row
        rows=c.execute(sql,p).fetchall();c.close();return[dict(r) for r in rows]
    except Exception as e:print(f"[db] {e}");return[]

def _s(db, sql, p=()):
    if not os.path.isfile(db): return 0
    try:c=sqlite3.connect(f"file:{db}?mode=ro",uri=True,timeout=5);v=c.execute(sql,p).fetchone()[0];c.close();return v
    except Exception:return 0

@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/overview")
def api_overview():
    total=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples")
    done=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE status=?",("done",))
    mal=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE verdict=?",("malicious",))
    sus=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE verdict=?",("suspicious",))
    cln=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE verdict=?",("clean",))
    fail=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE status=?",("failed",))
    cor=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE status=?",("corrupt",))
    yc=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE yara_created=1")
    sc=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE snort_created=1")
    cc=_s(LDB,"SELECT COUNT(*) FROM analyzed_samples WHERE cif_created=1")
    at=_s(LDB,"SELECT COALESCE(AVG(analysis_time_sec),0) FROM analyzed_samples WHERE status=?",("done",))
    tk=_s(LDB,"SELECT COALESCE(SUM(llm_total_tokens),0) FROM analyzed_samples")
    yd=_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source!=?",("draft","zintel"))+_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source IS NULL",("draft",))
    ya=_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source!=?",("approved","zintel"))+_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source IS NULL",("approved",))
    yr=_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source!=?",("rejected","zintel"))+_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source IS NULL",("rejected",))
    yh=_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source!=?",("retrohunting","zintel"))+_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE status=? AND source IS NULL",("retrohunting",))
    yt=_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE source!=? OR source IS NULL",("zintel",))
    zintel_count=_s(YDB,"SELECT COUNT(*) FROM yara_rules WHERE source=? AND status=?",("zintel","approved"))
    suri=len(glob.glob(os.path.join(SNORT_DIR,"*.rules"))) if os.path.isdir(SNORT_DIR) else 0
    return jsonify({"samples":{"total":total,"done":done,"malicious":mal,"suspicious":sus,
        "clean":cln,"failed":fail,"corrupt":cor},
        "signatures":{"yara":yc,"snort":sc,"cif":cc,"suricata_files":suri},
        "yara_registry":{"total":yt,"draft":yd,"approved":ya,"rejected":yr,"retrohunting":yh,"zintel_approved":zintel_count},
        "performance":{"avg_analysis_sec":round(float(at),1),"total_llm_tokens":int(tk)}})

@app.route("/api/pipeline_breakdown")
def api_pipeline_breakdown():
    return jsonify(_q(LDB,"SELECT pipeline_source,verdict,COUNT(*) as cnt,"
        "SUM(yara_created) as yara,SUM(snort_created) as snort,SUM(cif_created) as cif "
        "FROM analyzed_samples WHERE status=? GROUP BY pipeline_source,verdict",("done",)))

@app.route("/api/timeline")
def api_timeline():
    return jsonify(_q(LDB,"SELECT DATE(finished_at) as day,verdict,COUNT(*) as cnt "
        "FROM analyzed_samples WHERE status=? AND finished_at IS NOT NULL "
        "GROUP BY day,verdict ORDER BY day",("done",)))

@app.route("/api/recent")
def api_recent():
    lim=min(int(request.args.get("limit",50)),200)
    return jsonify(_q(LDB,"SELECT sha256,apk_name,package_name,family,pipeline_source,"
        "verdict,risk_score,status,error_note,analysis_time_sec,"
        "yara_created,yara_rule_name,snort_created,cif_created,"
        "finished_at,runner_id FROM analyzed_samples ORDER BY updated_at DESC LIMIT ?",(lim,)))

@app.route("/api/signatures")
def api_signatures():
    lim=min(int(request.args.get("limit",100)),500);sf=request.args.get("status","")
    if sf:
        return jsonify(_q(YDB,"SELECT rule_id,rule_name,family,category,status,"
            "refinement_round,max_refinement_rounds,fp_count,suspicious_fp_count,"
            "rejection_reason,source,created_at,updated_at,rule_text "
            "FROM yara_rules WHERE status=? AND (source!=? OR source IS NULL) ORDER BY updated_at DESC LIMIT ?",(sf,"zintel",lim)))
    return jsonify(_q(YDB,"SELECT rule_id,rule_name,family,category,status,"
        "refinement_round,max_refinement_rounds,fp_count,suspicious_fp_count,"
        "rejection_reason,source,created_at,updated_at,rule_text "
        "FROM yara_rules WHERE (source!=? OR source IS NULL) ORDER BY updated_at DESC LIMIT ?",("zintel",lim)))

@app.route("/api/signature/<rule_id>")
def api_signature_detail(rule_id):
    rows=_q(YDB,"SELECT * FROM yara_rules WHERE rule_id=?",(rule_id,))
    if not rows:return jsonify({})
    d=rows[0]
    d["versions"]=_q(YDB,"SELECT round_number,rule_text,rule_name_on_vt,retrohunt_job_id,"
        "retrohunt_status,fp_count,suspicious_fp_count,created_at "
        "FROM rule_versions WHERE rule_id=? ORDER BY round_number",(rule_id,))
    d["retrohunt_jobs"]=_q(YDB,"SELECT job_id,corpus,status,progress,num_matches,round_number,"
        "rule_name_on_vt,submitted_at,finished_at "
        "FROM retrohunt_jobs WHERE rule_id=? ORDER BY round_number",(rule_id,))
    return jsonify(d)

@app.route("/api/suricata_rules")
def api_suricata_rules():
    if not os.path.isdir(SNORT_DIR):return jsonify([])
    rules=[]
    for fp in sorted(glob.glob(os.path.join(SNORT_DIR,"*.rules"))):
        try:
            with open(fp,"r",encoding="utf-8",errors="replace") as f:content=f.read()
            rules.append({"filename":os.path.basename(fp),"content":content,
                "size_bytes":os.path.getsize(fp),"modified_at":os.path.getmtime(fp)})
        except Exception:continue
    return jsonify(rules)

if __name__=="__main__":app.run(host="0.0.0.0",port=5000,debug=True)