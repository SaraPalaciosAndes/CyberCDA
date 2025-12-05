from flask import Flask, render_template, request, session, redirect, url_for
import json
from pathlib import Path
from openai import OpenAI
import os
import io
from datetime import datetime
import xml.etree.ElementTree as ET

import httpx


app = Flask(__name__)
app.secret_key = "cambia-esto-por-un-secreto-mas-largo"  

BASE_DIR = Path(__file__).resolve().parent
CHECKLIST_PATH = BASE_DIR / "checklist_cda.json"
ASSESSMENT_PATH = BASE_DIR / "assessment.json"  
ALLOWED_EXTENSIONS = {"pdf", "xml", "json"}

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"),http_client=httpx.Client(verify=False))

def get_last_scan_json_path():
    scan_dir = BASE_DIR / "data" / "scan_results"
    if not scan_dir.exists():
        return None

    json_files = sorted(
        scan_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    return json_files[0] if json_files else None
def extract_relevant_openvas_text(raw_bytes):
    """
    Recibe el contenido crudo de un archivo XML (bytes) de OpenVAS
    y devuelve un texto resumido solo con la información relevante
    para generar controles: host, puerto, nombre, severidad,
    descripción y solución.

    Si no parece un XML válido o no tiene estructura de OpenVAS,
    devuelve None para que el caller haga fallback.
    """
    try:
        root = ET.fromstring(raw_bytes)
    except Exception:
        return None

    results = root.findall(".//result")
    if not results:
        return None

    bloques = []

    for res in results:
        name = (res.findtext("name") or "").strip()
        host = (res.findtext("host") or "").strip()
        port = (res.findtext("port") or "").strip()

        severity = (res.findtext("severity") or res.findtext("threat") or "").strip()

        description = (
            res.findtext("description")
            or res.findtext("nvt/description")
            or ""
        ).strip()

        solution = (
            res.findtext("solution")
            or res.findtext("nvt/solution")
            or ""
        ).strip()

        if len(description) > 600:
            description = description[:600] + "..."
        if len(solution) > 400:
            solution = solution[:400] + "..."

        if not (name or host or port or severity):
            continue

        bloque = [
            "[VULNERABILIDAD]",
            f"Host: {host}" if host else "",
            f"Puerto: {port}" if port else "",
            f"Nombre: {name}" if name else "",
            f"Severidad: {severity}" if severity else "",
            "",
            "Descripción:",
            description,
            "",
            "Solución recomendada:",
            solution,
            "-" * 40,
        ]

        bloque_limpio = "\n".join([l for l in bloque if l.strip()])
        bloques.append(bloque_limpio)

    if not bloques:
        return None

    return "\n\n".join(bloques)
def dividir_texto_en_chunks(texto, max_chars=6000):
    """
    Versión simple y rápida: corta el texto en bloques fijos de max_chars.
    Complejidad O(n).
    """
    print("dividiendo en chunks")

    texto = texto.replace("\r\n", "\n").replace("\r", "\n")

    lineas_limpias = []
    for linea in texto.split("\n"):
        l = linea.strip()

        if not l:
            continue

        lineas_limpias.append(l)

    texto_limpio = "\n".join(lineas_limpias).strip()

    length = len(texto_limpio)
    if length <= max_chars:
        return [texto_limpio]

    chunks = []
    for i in range(0, length, max_chars):
        chunks.append(texto_limpio[i:i + max_chars])
    print(chunks[0])
    print(len(chunks))
    return chunks

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS



def extract_text_from_file(file_storage):
    """
    Dado un archivo subido (FileStorage), devuelve el contenido en texto.
    - XML: si es un reporte de OpenVAS, se extrae solo la info relevante.
    - JSON: se lee como texto.
    - PDF: se intenta extraer texto con PyPDF2.
    """
    filename = file_storage.filename
    ext = filename.rsplit(".", 1)[1].lower()

    raw_bytes = file_storage.read()  

    if ext == "xml":
        texto_openvas = extract_relevant_openvas_text(raw_bytes)
        if texto_openvas:
            return texto_openvas
        try:
            return raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return raw_bytes.decode("latin-1", errors="ignore")

    if ext == "json":
        try:
            return raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return raw_bytes.decode("latin-1", errors="ignore")

    if ext == "pdf":
        try:
            import PyPDF2
        except ImportError:
            return "[PDF content could not be parsed on server. Please install PyPDF2.]"

        reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
        pages_text = []
        for page in reader.pages:
            pages_text.append(page.extract_text() or "")
        return "\n\n".join(pages_text)

    return raw_bytes.decode("utf-8", errors="ignore")




def generar_controles_para_chunk(chunk_text, scan_type, cda_name, idx, total_chunks):
    """
    Llama a GPT solo con un fragmento del escaneo (chunk_text)
    y devuelve un JSON de controles para ese fragmento.
    """
    system_prompt = (
    "Eres un experto en ciberseguridad para pequeñas y medianas empresas "
    "del sector de Centros de Diagnóstico Automotor (CDA) en Colombia. "
    "Recibirás como entrada el TEXTO RESUMIDO de un escaneo de seguridad "
    "(por ejemplo, Nmap u OpenVAS), organizado en bloques con el formato:\n\n"
    "[VULNERABILIDAD]\n"
    "Host: ...\n"
    "Puerto: ...\n"
    "Nombre: ...\n"
    "Severidad: ...\n"
    "Descripción:\n"
    "... \n"
    "Solución recomendada:\n"
    "... \n"
    "----------------------------------------\n\n"
    "Tu tarea es analizar estos bloques y proponer CONTROLES DE CIBERSEGURIDAD "
    "concretos, accionables y alineados con estándares como ISO 27001, NIST CSF y OWASP, "
    "pensados específicamente para un CDA.\n\n"
    "Tu salida DEBE ser EXCLUSIVAMENTE un objeto JSON válido, sin texto adicional."
    )

    user_prompt = f"""
                El siguiente texto corresponde al BLOQUE {idx+1} de {total_chunks} de los resultados
                de un escaneo de seguridad tipo: {scan_type} para el CDA: {cda_name}.

                El texto ya está resumido en bloques de vulnerabilidades con el siguiente estilo:

                [VULNERABILIDAD]
                Host: <IP o nombre>
                Puerto: <puerto/protocolo>
                Nombre: <nombre de la vulnerabilidad>
                Severidad: <Low/Medium/High/Critical o numérico>
                Descripción:
                <descripción breve>
                Solución recomendada:
                <medida sugerida>
                ----------------------------------------

                INSTRUCCIONES:

                1. Analiza únicamente las vulnerabilidades presentes en este fragmento de texto.
                2. Para cada vulnerabilidad relevante, propone uno o más CONTROLES de ciberseguridad
                que un CDA debería aplicar para mitigar el riesgo (por ejemplo: segmentación de red,
                endurecimiento de servicios, actualización de software, control de accesos remotos, etc.).
                3. No repitas controles genéricos; enfócate en acciones específicas derivadas de estos hallazgos
                (por ejemplo, si hay RDP expuesto, un control para restringir o encapsular RDP).
                4. Si una vulnerabilidad es de severidad alta o crítica, asigna un nivel de madurez objetivo más alto
                (por ejemplo 4 o 5). Si es media, usa 3–4; si es baja, 2–3.

                La salida debe tener EXACTAMENTE la siguiente estructura JSON:

                {{
                "Infraestructura_y_Redes": [
                    {{
                    "id": "IR_SCAN_01",
                    "control": "Nombre corto del control",
                    "descripcion": "Descripción clara del control, indicando qué debe hacer el CDA.",
                    "categoria": "Infraestructura y Redes",
                    "dominio": "Subdominio o área (ej. Segmentación, Acceso remoto, Firewall)",
                    "referencia": "Referencias a ISO/NIST/OWASP relevantes",
                    "recomendacion": "Acción concreta recomendada para este CDA, basada en el hallazgo.",
                    "madurez": "calcula el nivel de madurex del control de 1 a 5,
                    "requires_tags": ["Scan_AI"]
                    }}
                ],
                "Aplicativos_y_Datos": [],
                "Gobierno_y_Cumplimiento": [],
                "Personas": [],
                "Proveedores": [],
                "Fisicos": []
                }}

                REGLAS ESTRICTAS:
                - Usa IDs únicos que empiecen por el prefijo del dominio (IR_SCAN_*, AD_SCAN_*, GC_SCAN_*, etc.).
                - Incluye SOLO controles que tengan sentido según las vulnerabilidades de este fragmento.
                - SIEMPRE incluye el campo "requires_tags": ["Scan_AI"] en cada control.
                - No incluyas ningún texto fuera del JSON (sin explicaciones, comentarios ni texto adicional).
                """

    response = client.responses.create(
        model="gpt-5.1",
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": chunk_text},
            {"role": "user", "content": user_prompt},
        ],
    )

    raw_text = response.output_text
    print(raw_text)

    try:
        controls_json = json.loads(raw_text)
    except json.JSONDecodeError:
        controls_json = {
            "Infraestructura_y_Redes": [],
            "Aplicativos_y_Datos": [],
            "Gobierno_y_Cumplimiento": [],
            "Personas": [],
            "Proveedores": [],
            "Fisicos": []
        }

    return controls_json

def fusionar_controles(lista_jsons):
    """
    Recibe una lista de JSONs con la estructura de controles por dominio
    y devuelve un único JSON fusionado.
    """
    resultado = {
        "Infraestructura_y_Redes": [],
        "Aplicativos_y_Datos": [],
        "Gobierno_y_Cumplimiento": [],
        "Personas": [],
        "Proveedores": [],
        "Fisicos": []
    }

    for j in lista_jsons:
        for dominio, controles in j.items():
            if dominio not in resultado:
                resultado[dominio] = []
            resultado[dominio].extend(controles)

    return resultado


def generate_controls_from_scan(scan_text, scan_type, cda_name):
    """
    Procesa un escaneo potencialmente grande dividiéndolo en chunks,
    llama a GPT por cada chunk y fusiona los controles resultantes.
    """

    chunks = dividir_texto_en_chunks(scan_text, max_chars=6000)

    json_parciales = []
    total = len(chunks)

    for idx, chunk in enumerate(chunks):
        parcial = generar_controles_para_chunk(chunk, scan_type, cda_name, idx, total)
        json_parciales.append(parcial)

    controles_finales = fusionar_controles(json_parciales)

    return controles_finales

def load_checklist():
    with open(CHECKLIST_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)

    controls = []
    for top_key, items in raw.items():
        if not isinstance(items, list):
            continue
        for c in items:
            controls.append({
                "id": c.get("id", ""),
                "control": c.get("control", ""),
                "descripcion": c.get("descripcion", ""),
                "categoria": c.get("categoria", top_key),
                "dominio": c.get("dominio", ""),
                "referencia": c.get("referencia", ""),
                "recomendacion": c.get("recomendacion", ""),
                "madurez": c.get("madurez", ""),
                "requires_tags": c.get("requires_tags", [])
            })
    return controls


def load_assessment():
    """Lee el JSON del assessment desde disco."""
    with open(ASSESSMENT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_ai_controls_from_last_scan():
    """
    Lee el archivo JSON más reciente en data/scan_results
    y devuelve una lista de controles IA ya aplanados, listos
    para mezclarse con el checklist.

    Soporta dos formatos:
    - {"meta": {...}, "controls": {...}}  (nuevo)
    - {...} solo con dominios -> lista de controles (antiguo)
    """
    scan_dir = BASE_DIR / "data" / "scan_results"
    if not scan_dir.exists():
        return []

    json_files = sorted(
        scan_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not json_files:
        return []

    latest = json_files[0]
    try:
        with open(latest, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[checklist] Error leyendo {latest}: {e}")
        return []

    if isinstance(data, dict) and "controls" in data:
        controls_by_domain = data["controls"]
    else:
        controls_by_domain = data

    if not isinstance(controls_by_domain, dict):
        return []

    flat_ai_controls = []

    for dominio, controles in controls_by_domain.items():
        if not isinstance(controles, list):
            continue

        for c in controles:
            if not isinstance(c, dict):
                continue

            ctrl = c.copy()

            ctrl["categoria"] = ctrl.get("categoria") or dominio
            ctrl["dominio"] = ctrl.get("dominio") or dominio

            tags = ctrl.get("requires_tags", []) or []
            if "Scan_AI" in tags:
                ctrl["from_ai"] = True
            else:
                ctrl["from_ai"] = True

            flat_ai_controls.append(ctrl)

    return flat_ai_controls

BASE_CONTROLS  = load_checklist()
CATEGORIES = sorted(set(c["categoria"] for c in BASE_CONTROLS ))


def calc_compliance(controls, implemented_ids):
    total = len(controls)
    if total == 0:
        return 0
    implemented = sum(1 for c in controls if c["id"] in implemented_ids)
    return round(implemented * 100 / total)

def eval_condition(condicion, respuesta):
    """
    Evalúa expresiones sencillas como:
    - "respuesta == 'Grande (31 o más)'"
    - "valor >= 2"
    """
    if not condicion:
        return True

    try:
        valor = float(respuesta)
    except (TypeError, ValueError):
        valor = None

    local_ctx = {
        "respuesta": respuesta,
        "valor": valor,
    }
    try:
        return bool(eval(condicion, {"__builtins__": {}}, local_ctx))
    except Exception:
        return False

def compute_category_stats(controls, implemented_ids):
    stats = {}
    for c in controls:
        cat = c["categoria"]
        if cat not in stats:
            stats[cat] = {"total": 0, "implemented": 0}
        stats[cat]["total"] += 1
        if c["id"] in implemented_ids:
            stats[cat]["implemented"] += 1

    for cat, info in stats.items():
        total = info["total"]
        impl = info["implemented"]
        perc = round(impl * 100 / total) if total else 0

        if perc < 50:
            risk_class = "high"
        elif perc < 80:
            risk_class = "medium"
        else:
            risk_class = "low"

        info["perc"] = perc
        info["risk_class"] = risk_class

    return stats

def process_assessment_impacts(assessment_data, answers):
    """
    Lee el JSON del assessment + las respuestas,
    y devuelve:
      - tags_activos: set([...])
      - control_deltas: { control_id: {"madurez_delta": x, "prioridad_delta": y} }
    """
    tags = set()
    control_deltas = {}

    for section in assessment_data.get("sections", []):
        for q in section.get("questions", []):
            qid = q.get("id")
            if not qid:
                continue
            respuesta = answers.get(qid)

            if respuesta in (None, "", []):
                continue

            for imp in q.get("impacts", []):
                tipo = imp.get("tipo")
                condicion = imp.get("condicion")

                if not eval_condition(condicion, respuesta):
                    continue

                if tipo == "tag":
                    tag_val = imp.get("valor")
                    if tag_val:
                        tags.add(tag_val)

                elif tipo == "control":
                    cid = imp.get("control_id")
                    efecto = imp.get("efecto")
                    valor = imp.get("valor", 0)

                    if not cid or not efecto:
                        continue

                    if cid not in control_deltas:
                        control_deltas[cid] = {
                            "madurez_delta": 0,
                            "prioridad_delta": 0,
                        }

                    if efecto == "aumentar_madurez":
                        control_deltas[cid]["madurez_delta"] += valor
                    elif efecto == "aumentar_prioridad":
                        control_deltas[cid]["prioridad_delta"] += valor

    return tags, control_deltas

def build_active_controls(tags, control_deltas):
    """
    Combina:
      - CONTROLES base
      - Filtro por requires_tags
      - Ajustes de madurez / prioridad desde el assessment
    """
    active = []

    for base in BASE_CONTROLS:
        req = base.get("requires_tags") or []
        appears_by_tag = bool(req) and any(t in tags for t in req)
        if req and not appears_by_tag:
            continue

        c = base.copy()
        deltas = control_deltas.get(c["id"], {})

        madurez_base = c.get("madurez", 1)
        mad_delta = deltas.get("madurez_delta", 0)
        c["madurez"] = max(1, madurez_base + mad_delta)

        prioridad_delta = deltas.get("prioridad_delta", 0)
        c["prioridad_delta"] = prioridad_delta

        c["from_assessment_extra"] = appears_by_tag
        c["from_assessment_adjusted"] = bool(mad_delta or prioridad_delta)

        active.append(c)

    return active


def save_scan_results_to_file(ai_controls, scan_name, scan_type, scan_date):
    """
    Guarda los resultados generados por IA en un archivo JSON dentro de /data/scan_results.
    El nombre del archivo incluye tipo de escaneo, nombre y timestamp.
    """
    output_dir = BASE_DIR / "data" / "scan_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_name = scan_name.strip().replace(" ", "_") if scan_name else "scan"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_name}_{scan_type}_{timestamp}.json"

    output_path = output_dir / filename

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ai_controls, f, ensure_ascii=False, indent=2)

    print(f"[import-scan] Resultados guardados en: {output_path}")

    print(json.dumps(ai_controls, ensure_ascii=False, indent=2))

def build_ai_preview_controls(json_path, limit=5):
    """
    Lee un archivo JSON con la estructura de controles generados por IA
    (como openvas_xml_OpenVAS_20251205_103656.json) y devuelve una lista
    con los últimos `limit` controles aplanados, lista para mostrar en la vista.

    Estructura esperada del JSON:
    {
      "Infraestructura_y_Redes": [ { ...control... }, ... ],
      "Aplicativos_y_Datos": [ { ... }, ... ],
      "Gobierno_y_Cumplimiento": [ ... ],
      "Personas": [ ... ],
      "Proveedores": [ ... ],
      "Fisicos": [ ... ]
    }
    """
    json_path = Path(json_path)

    if not json_path.exists():
        print(f"[build_ai_preview_controls] Archivo no encontrado: {json_path}")
        return []

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[build_ai_preview_controls] Error leyendo {json_path}: {e}")
        return []

    if not isinstance(data, dict):
        print(f"[build_ai_preview_controls] Formato JSON inesperado en {json_path}")
        return []

    flat = []

    for dominio, controles in data.items():
        if not isinstance(controles, list):
            continue

        for c in controles:
            if not isinstance(c, dict):
                continue

            flat.append({
                "id": c.get("id"),
                "control": c.get("control"),
                "categoria": c.get("categoria") or dominio,
                "dominio": c.get("dominio") or dominio,
                "madurez": c.get("madurez"),
                "referencia": c.get("referencia"),
                "recomendacion": c.get("recomendacion"),
            })

    if not flat:
        return []

    return flat[-limit:]

@app.route("/import-scan", methods=["GET", "POST"])
def import_scan():
    last_error = None
    ai_controls = None
    ai_preview_controls = []

    if request.method == "POST":
        file = request.files.get("scan_file")
        scan_type = request.form.get("scan_type", "Nmap")
        scan_date = request.form.get("scan_date", "")
        scan_name = request.form.get("scan_name", "")

        if not file or file.filename == "":
            last_error = "Debe seleccionar un archivo."
        elif not allowed_file(file.filename):
            last_error = "Formato de archivo no soportado. Use PDF, XML o JSON."
        else:
            file_text = extract_text_from_file(file)

            cda_name = "MONCUMO SAS"
            ai_controls = generate_controls_from_scan(
                scan_text=file_text,
                scan_type=scan_type,
                cda_name=cda_name,
            )

            session["last_scan_controls"] = ai_controls
            session["last_scan_meta"] = {
                "scan_type": scan_type,
                "scan_date": scan_date,
                "scan_name": scan_name,
            }

    if ai_controls is None:
        ai_controls = session.get("last_scan_controls")

    last_json = get_last_scan_json_path()
    if last_json:
        ai_preview_controls = build_ai_preview_controls(last_json, limit=5)

        with open(last_json, "r", encoding="utf-8") as f:
            ai_controls = json.load(f)

    return render_template(
        "import_scan.html",
        active_page="scan_import",
        ai_controls=ai_controls,
        ai_preview_controls=ai_preview_controls,
      
        error=last_error,
    )

@app.route("/assessment", methods=["GET", "POST"])
def assessment():
    data = load_assessment()
    metadata = data.get("metadata", {})
    sections = data.get("sections", [])

    saved_answers = session.get("assessment_answers", {})

    if request.method == "POST":
        answers = {}

        for section in sections:
            for q in section.get("questions", []):
                qid = q.get("id")
                qtype = q.get("tipo")
                if not qid:
                    continue

                if qtype == "multi_choice":
                    value = request.form.getlist(qid)
                else:
                    value = request.form.get(qid, "").strip()

                answers[qid] = value

        session["assessment_answers"] = answers

        tags, control_deltas = process_assessment_impacts(data, answers)
        session["assessment_tags"] = list(tags)
        session["assessment_control_deltas"] = control_deltas

        return redirect(url_for("checklist"))

    total_questions = sum(len(sec.get("questions", [])) for sec in sections)
    answered_count = 0
    for sec in sections:
        for q in sec.get("questions", []):
            qid = q.get("id")
            val = saved_answers.get(qid)
            if val not in (None, "", []):
                answered_count += 1

    progress_pct = round(100 * answered_count / total_questions) if total_questions else 0

    return render_template(
        "assessment.html",
        metadata=metadata,
        sections=sections,
        saved_answers=saved_answers,
        cda_name="MONCUMO SAS",
        active_page="assessment",
        progress_pct=progress_pct,
        answered_count=answered_count,
        total_questions=total_questions,
    )

@app.route("/assessment/reset")
def assessment_reset():
    """
    Limpia la información del assessment, pero conserva:
    - El checklist base
    - Las selecciones (implemented_ids) de controles base

    Solo se eliminan:
    - Respuestas del assessment
    - Tags
    - Deltas de controles
    - Selecciones de controles que dependían del assessment (requires_tags)
    """
    session.pop("assessment_answers", None)
    session.pop("assessment_tags", None)
    session.pop("assessment_control_deltas", None)

    implemented_ids = session.get("implemented_ids", [])


    base_controls = build_active_controls(tags=set(), control_deltas={})

    base_ids = {c["id"] for c in base_controls}

    filtered_implemented = [cid for cid in implemented_ids if cid in base_ids]

    session["implemented_ids"] = filtered_implemented

    return redirect(url_for("assessment"))

@app.route("/dashboard")
def dashboard():
    implemented_ids = session.get("implemented_ids", [])
    tags = set(session.get("assessment_tags", []))
    control_deltas = session.get("assessment_control_deltas", {}) or {}


    controls = build_active_controls(tags, control_deltas)
    pending_controls = [c for c in controls if c["id"] not in implemented_ids]

    pending_by_category = {}
    for c in pending_controls:
        cat = c["categoria"]
        pending_by_category.setdefault(cat, []).append(c)


    compliance = calc_compliance(controls, implemented_ids)

    critical_controls = [
        c for c in controls
        if c.get("madurez", 1) >= 4 and c["id"] not in implemented_ids
    ]
    critical_count = len(critical_controls)

    critical_alerts = []
    for c in critical_controls[:5]:  
        critical_alerts.append({
            "titulo": c["control"],
            "detalle": c.get("recomendacion") or c.get("descripcion") or "",
            "categoria": c["categoria"],
            "control_id": c["id"],
        })

    last_scan_info = session.get("last_scan_meta")
    if last_scan_info and last_scan_info.get("scan_date"):
        last_scan_label = f"{last_scan_info['scan_date']}"
    else:
        last_scan_label = "No registrado"

    category_stats = compute_category_stats(controls, implemented_ids)

    controls_by_category = {}
    for c in controls:
        cat = c["categoria"]
        controls_by_category.setdefault(cat, []).append(c)

    recomendaciones = []
    pending_sorted = sorted(
        pending_controls,
        key=lambda c: c.get("madurez", 1),
        reverse=True,
    )

    for c in pending_sorted[:5]:  
        madurez = c.get("madurez", 1)
        if madurez >= 4:
            prioridad = "ALTA PRIORIDAD"
        elif madurez == 3:
            prioridad = "PRIORIDAD MEDIA"
        else:
            prioridad = "PRIORIDAD BAJA"

        recomendaciones.append({
            "titulo": c["control"],
            "detalle": c.get("recomendacion") or c.get("descripcion") or "",
            "prioridad": prioridad,
            "categoria": c["categoria"],
        })

    if compliance < 50:
        risk_label = "Alto Riesgo"
        risk_class = "high"
    elif compliance < 80:
        risk_label = "Riesgo Medio"
        risk_class = "medium"
    else:
        risk_label = "Riesgo Bajo"
        risk_class = "low"

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        cda_name="MONCUMO SAS",
        compliance=compliance,
        risk_label=risk_label,
        risk_class=risk_class,
        critical_count=critical_count,
        alerts_count=len(critical_alerts),
        last_scan_label=last_scan_label,
        category_stats=category_stats,
        controls_by_category=controls_by_category,  
        pending_by_category=pending_by_category,    
        critical_alerts=critical_alerts,
        recomendaciones=recomendaciones,
    )

@app.route("/", methods=["GET", "POST"])
def checklist():
    implemented_ids = session.get("implemented_ids", [])

    tags = set(session.get("assessment_tags", []))
    control_deltas = session.get("assessment_control_deltas", {}) or {}

    base_controls = build_active_controls(tags, control_deltas)
    ai_controls = load_ai_controls_from_last_scan()
    controls = base_controls + ai_controls

    categories = sorted(set(c["categoria"] for c in controls))

    if request.method == "POST":
        implemented_ids = request.form.getlist("implemented_ids")
        session["implemented_ids"] = implemented_ids

    for c in controls:
        c["implemented"] = c["id"] in implemented_ids

    control_id = request.args.get("control_id")
    selected = next((c for c in controls if c["id"] == control_id), None) if control_id else None
    if not selected and controls:
        selected = controls[0]

    compliance = calc_compliance(controls, implemented_ids)

    if compliance < 50:
        risk_level = "Alto"
        risk_class = "high"
    elif compliance < 80:
        risk_level = "Medio"
        risk_class = "medium"
    else:
        risk_level = "Bajo"
        risk_class = "low"

    category_stats = compute_category_stats(controls, implemented_ids)
    from_alert = request.args.get("from_alert") == "1"


    return render_template(
        "checklist.html",
        controls=controls,
        categories=categories,
        selected_control=selected,
        compliance=compliance,
        risk_level=risk_level,
        risk_class=risk_class,
        implemented_ids=implemented_ids,
        category_stats=category_stats,
        from_alert=from_alert,
        cda_name="MONCUMO SAS",
        eval_date="12/03/2025",
        next_audit="15 Abr, 2025",
        active_page="checklist",
    )

if __name__ == "__main__":
    app.run(debug=True)
