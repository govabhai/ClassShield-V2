import os
import io
import time
import hashlib
import json
import logging
import base64
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for
from functools import wraps
from PIL import Image, ImageDraw, ImageFilter
import requests
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

try:
    # Nudenet 3.x uses NudeDetector, gracefully handle import errors
    from nudenet import NudeDetector # type: ignore
    LOCAL_MODEL_AVAILABLE = True
    # For NudeNet, we need to ensure it's initialized once
    classifier = NudeDetector()
except Exception as e:
    LOCAL_MODEL_AVAILABLE = False
    classifier = None
    print(f"Local NudeNet model initialization error: {e}")

try:
    from groq import Groq
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
    VISION_AVAILABLE = bool(GROQ_API_KEY)
except Exception as e:
    groq_client = None
    VISION_AVAILABLE = False
    print("Llama Vision (Groq) not available:", e)

SIGHT_USER = os.getenv("SIGHTENGINE_API_USER", "")
SIGHT_SECRET = os.getenv("SIGHTENGINE_API_SECRET", "")

app = Flask(__name__)
app.secret_key = os.getenv("SESSION_SECRET", "dev-secret-key-change-in-production")
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True
)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

flagged_items = []
audit_log = []
# Manual clear request was processed.
DB_PATH = "classshield_cache.db"

def init_cache_db():
    """Initialize SQLite database for caching scan decisions and policies"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_hash TEXT UNIQUE NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT,
                primary_score REAL,
                skin_ratio REAL,
                evidence TEXT,
                keywords_detected TEXT,
                vision_analysis TEXT,
                methods TEXT,
                heatmap TEXT,
                review_status TEXT DEFAULT 'pending',
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_at TIMESTAMP,
                rejected_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policy_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT UNIQUE NOT NULL,
                block_threshold REAL DEFAULT 0.35,
                review_threshold REAL DEFAULT 0.15,
                flag_lingerie INTEGER DEFAULT 1,
                flag_beach_context INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Insert default policy if none exists
        cursor.execute("SELECT COUNT(*) FROM policy_config")
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO policy_config (policy_name, block_threshold, review_threshold, is_active)
                VALUES (?, ?, ?, ?)
            ''', ('Default School Policy', 0.35, 0.15, 1))

        # Migration: Add heatmap column if it doesn't exist
        cursor.execute("PRAGMA table_info(scan_cache)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'heatmap' not in columns:
            cursor.execute("ALTER TABLE scan_cache ADD COLUMN heatmap TEXT")
            print("Migration: Added heatmap column to scan_cache")
            
        conn.commit()
        conn.close()
        print("Cache database initialized successfully")
    except Exception as e:
        print(f"Cache DB initialization error: {e}")

def get_active_policy():
    """Retrieve the currently active policy configuration"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policy_config WHERE is_active = 1 LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
    except Exception as e:
        print(f"Policy retrieval error: {e}")
    # Fallback to hardcoded defaults if DB fails
    return {
        "block_threshold": 0.35,
        "review_threshold": 0.15,
        "flag_lingerie": 1,
        "flag_beach_context": 0
    }

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/api/policy", methods=["GET", "POST"])
@require_admin
def manage_policy():
    if request.method == "POST":
        data = request.get_json()
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            # Deactivate all policies first
            cursor.execute("UPDATE policy_config SET is_active = 0")
            # Update or Insert the new policy
            cursor.execute('''
                INSERT INTO policy_config 
                (policy_name, block_threshold, review_threshold, flag_lingerie, flag_beach_context, is_active, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                ON CONFLICT(policy_name) DO UPDATE SET
                block_threshold=excluded.block_threshold,
                review_threshold=excluded.review_threshold,
                flag_lingerie=excluded.flag_lingerie,
                flag_beach_context=excluded.flag_beach_context,
                is_active=1,
                updated_at=CURRENT_TIMESTAMP
            ''', (
                data.get('policy_name', 'Custom Policy'),
                float(data.get('block_threshold', 0.35)),
                float(data.get('review_threshold', 0.15)),
                1 if data.get('flag_lingerie') else 0,
                1 if data.get('flag_beach_context') else 0
            ))
            conn.commit()
            conn.close()
            log_audit("policy_updated", data)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500
            
    # GET request
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policy_config ORDER BY is_active DESC, updated_at DESC")
        policies = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(policies)
    except Exception as e:
        return jsonify([])

def get_cached_decision(image_hash):
    """Retrieve cached scan decision by image hash"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scan_cache WHERE image_hash = ?', (image_hash,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    except Exception as e:
        print(f"Cache retrieval error: {e}")
        return None

def save_scan_to_cache(image_hash, result_data):
    """Save scan result to cache database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Ensure we have the heatmap string
        heatmap = result_data.get('heatmap')
        if not heatmap:
            # Fallback if somehow missing
            heatmap = ""
            
        cursor.execute('''
            INSERT OR REPLACE INTO scan_cache 
            (image_hash, decision, reason, primary_score, skin_ratio, evidence, 
             keywords_detected, vision_analysis, methods, heatmap, review_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            image_hash,
            result_data.get('decision'),
            result_data.get('reason'),
            result_data.get('primary_score'),
            result_data.get('skin_ratio'),
            json.dumps(result_data.get('evidence', {})),
            json.dumps(result_data.get('keywords_detected', {})),
            result_data.get('vision_analysis'),
            json.dumps(result_data.get('methods', [])),
            heatmap,
            'pending'
        ))
        conn.commit()
        conn.close()
        nsfw_logger.info(f"Cached scan result for hash: {image_hash[:16]} with heatmap")
    except Exception as e:
        print(f"Cache save error: {e}")
        nsfw_logger.error(f"Failed to save scan to cache: {e}")

def update_cache_review_status(image_hash, status, timestamp=None):
    """Update review status in cache (approved/rejected)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        if status == 'approved':
            cursor.execute('UPDATE scan_cache SET review_status = ?, approved_at = ? WHERE image_hash = ?',
                          (status, datetime.now().isoformat(), image_hash))
        elif status == 'rejected':
            cursor.execute('UPDATE scan_cache SET review_status = ?, rejected_at = ? WHERE image_hash = ?',
                          (status, datetime.now().isoformat(), image_hash))
        else:
            cursor.execute('UPDATE scan_cache SET review_status = ? WHERE image_hash = ?', (status, image_hash))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Cache update error: {e}")

def load_flagged_from_db():
    """Load pending review items from SQLite into the in-memory queue on startup"""
    global flagged_items
    try:
        if not os.path.exists(DB_PATH):
            return
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Only load items that were flagged for review or blocked and are still pending
        # Ensure we only load items where decision is NOT 'SAFE'
        cursor.execute("SELECT * FROM scan_cache WHERE decision IN ('REVIEW', 'BLOCK') AND review_status = 'pending' ORDER BY cached_at DESC LIMIT 100")
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            data = dict(row)
            # Reconstruct the item for the admin dashboard
            item = {
                "id": len(flagged_items),
                "timestamp": data['cached_at'],
                "flagged_at": data['cached_at'],
                "image_hash": data['image_hash'],
                "decision": data['decision'],
                "reason": data['reason'],
                "score": data['primary_score'],
                "primary_score": data['primary_score'],
                "skin_ratio": data['skin_ratio'],
                "review_status": data['review_status'],
                "evidence": json.loads(data['evidence'] or '{}'),
                "vision_analysis": data['vision_analysis'],
                "anvesh_vision_analysis": data['vision_analysis'],
                "methods": json.loads(data['methods'] or '[]'),
                "heatmap": data.get('heatmap'),
                "action": "send_to_admin_review" if data['decision'] == 'REVIEW' else "block_and_send_to_admin_review"
            }
            flagged_items.append(item)
        print(f"Loaded {len(flagged_items)} items from cache for review")
    except Exception as e:
        print(f"Error loading flagged from DB: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nsfw_audit.log'),
        logging.StreamHandler()
    ]
)
nsfw_logger = logging.getLogger('nsfw_audit')

def compute_image_hash(image_bytes):
    return hashlib.sha256(image_bytes).hexdigest()

def log_audit(action, details):
    audit_log.append({
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details
    })
    if len(audit_log) > 1000:
        audit_log.pop(0)

def check_with_sightengine_bytes(image_bytes):
    if not SIGHT_USER or not SIGHT_SECRET:
        return None
    url = "https://api.sightengine.com/1.0/check.json"
    files = {'media': ('image.jpg', image_bytes)}
    data = {
        'models': 'nudity-2.0,wad',
        'api_user': SIGHT_USER,
        'api_secret': SIGHT_SECRET
    }
    try:
        resp = requests.post(url, files=files, data=data, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print("Sightengine error:", e)
        return None

def local_nudenet_classify_bytes(image_bytes):
    if not LOCAL_MODEL_AVAILABLE or classifier is None:
        return None
    try:
        import tempfile
        from PIL import Image as PILImage
        # Ensure image is valid before passing to NudeNet
        try:
            PILImage.open(io.BytesIO(image_bytes)).verify()
        except:
            return None
            
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
            tmp.write(image_bytes)
            tmp_path = tmp.name
        
        # Normalize NudeNet output
        try:
            res = classifier.detect(tmp_path)
            nsfw_logger.info(f"NudeNet raw output: {res}")
            
            # NudeNet 3.x returns a list of detections
            if isinstance(res, list):
                unsafe_score = 0
                explicit_classes = ['EXPOSED_GENITALIA', 'EXPOSED_BREAST', 'EXPOSED_BUTTOCKS']
                suggestive_classes = ['EXPOSED_ANUS', 'EXPOSED_ARMPITS', 'EXPOSED_BELLY', 'EXPOSED_FEET', 'EXPOSED_KNEES']
                
                for detection in res:
                    cls = detection.get('class', '').upper()
                    score = detection.get('score', 0)
                    
                    if cls in explicit_classes:
                        unsafe_score = max(unsafe_score, score)
                    elif cls in suggestive_classes:
                        unsafe_score = max(unsafe_score, score * 0.5)
                
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                
                # IMPORTANT: Return a list containing a dict with the specific keys 'unsafe' and 'safe'
                # Ensure the score is a float and within 0-1 range
                normalized_unsafe = min(1.0, max(0.0, float(unsafe_score)))
                return [{"unsafe": normalized_unsafe, "safe": 1.0 - normalized_unsafe}]
        except Exception as e:
            nsfw_logger.error(f"NudeNet detection error: {e}")
            res = None
        
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        
        return None
    except Exception as e:
        print("Local classifier error:", e)
        return None

def calculate_skin_ratio(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        arr = np.array(img)
        h, w = arr.shape[0], arr.shape[1]
        total_pixels = h * w

        r = arr[:, :, 0]
        g = arr[:, :, 1]
        b = arr[:, :, 2]

        skin_mask = (
            (r > 95) & (g > 40) & (b > 20) &
            (r > g) & (r > b) &
            (abs(r - g) > 15) &
            (r - g > 0)
        )

        skin_pixels = np.sum(skin_mask)
        skin_ratio = (skin_pixels / total_pixels) * 100

        return round(skin_ratio, 2)
    except Exception as e:
        print("Skin ratio calculation error:", e)
        return 0

def generate_risk_heatmap(image_bytes, skin_ratio, decision):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        arr = np.array(img)
        h, w = arr.shape[0], arr.shape[1]

        r = arr[:, :, 0]
        g = arr[:, :, 1]
        b = arr[:, :, 2]

        skin_mask = (
            (r > 95) & (g > 40) & (b > 20) &
            (r > g) & (r > b) &
            (abs(r - g) > 15) &
            (r - g > 0)
        )

        blurred_img = img.filter(ImageFilter.GaussianBlur(radius=15))
        darkened_arr = (np.array(blurred_img) * 0.3).astype(np.uint8)
        darkened_img = Image.fromarray(darkened_arr)

        overlay = Image.new('RGBA', (w, h), (0, 0, 0, 0))
        overlay_arr = np.array(overlay)

        non_skin_mask = ~skin_mask
        overlay_arr[non_skin_mask] = [40, 40, 40, 245]

        # Yellow for Skin regions (Neutral/Review)
        overlay_arr[skin_mask] = [255, 255, 0, 248]

        # Red for High-risk (Block)
        if decision == "BLOCK":
            overlay_arr[skin_mask] = [255, 0, 0, 250]

        # Green for Safe
        if decision == "SAFE":
            overlay_arr[skin_mask] = [0, 255, 0, 240]

        overlay_img = Image.fromarray(overlay_arr, mode='RGBA')

        # Limit size to prevent massive DB growth while ensuring visibility
        max_dim = 600
        if w > max_dim or h > max_dim:
            if w > h:
                target_width = max_dim
                target_height = int(max_dim * h / w)
            else:
                target_height = max_dim
                target_width = int(max_dim * w / h)
        else:
            target_width, target_height = w, h
            
        resized_darkened = darkened_img.resize((target_width, target_height), Image.Resampling.LANCZOS)
        resized_overlay = overlay_img.resize((target_width, target_height), Image.Resampling.LANCZOS)

        composite = Image.new('RGBA', (target_width, target_height))
        composite.paste(resized_darkened.convert('RGBA'))
        composite = Image.alpha_composite(composite, resized_overlay)

        buffered = io.BytesIO()
        # Use PNG for better quality on the base64 string
        composite.save(buffered, format="PNG")
        heatmap_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        return f"data:image/png;base64,{heatmap_base64}"
    except Exception as e:
        print("Heatmap generation error:", e)
        nsfw_logger.error(f"Heatmap generation failed: {e}")
        return None

def detect_contextual_keywords(sightengine_response):
    keywords_detected = {
        'bra_lingerie': False,
        'bed_context': False,
        'swimwear': False,
        'beach_context': False
    }

    if not sightengine_response:
        return keywords_detected

    try:
        nudity = sightengine_response.get('nudity', {})

        if 'lingerie' in str(nudity).lower() or 'bra' in str(nudity).lower():
            keywords_detected['bra_lingerie'] = True

        context = sightengine_response.get('weapon', {})
        raw_categories = sightengine_response.get('nudity', {}).get('raw_categories', {})

        if 'bed' in str(sightengine_response).lower():
            keywords_detected['bed_context'] = True

        if 'swimwear' in str(nudity).lower() or 'bikini' in str(nudity).lower():
            keywords_detected['swimwear'] = True

        if 'beach' in str(sightengine_response).lower() or 'pool' in str(sightengine_response).lower():
            keywords_detected['beach_context'] = True

    except Exception as e:
        print("Keyword detection error:", e)

    return keywords_detected

def analyze_with_llama_vision(image_bytes, decision, reason, keywords=None, skin_ratio=0):
    """Llama Vision (Groq): Analyze flagged content with detailed image description"""
    if not VISION_AVAILABLE or not groq_client:
        return None
    
    try:
        # Resize image for faster processing and lower token usage
        img = Image.open(io.BytesIO(image_bytes))
        max_dim = 800
        if max(img.size) > max_dim:
            img.thumbnail((max_dim, max_dim))
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=85)
            image_bytes = buffer.getvalue()
            
        base64_image = base64.b64encode(image_bytes).decode('utf-8')
        
        prompt = f"""Analyze this image as ClassShield AI for a school content safety system.

Current Decision: {decision}
Reasoning: {reason}

Provide a factual analysis:
1. **IMAGE DESCRIPTION**: Describe people, objects, and setting.
2. **WHAT**: Specify flagged visual content.
3. **WHEN**: Note any context or time/place clues.
4. **HOW**: Note visual patterns triggering flags.
5. **CONFIDENCE**: Evaluate if the system decision is accurate.

Be professional and descriptive."""

        # Use the latest supported vision model
        response = groq_client.chat.completions.create(
            model="meta-llama/llama-4-scout-17b-16e-instruct",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}}
                    ]
                }
            ],
            max_tokens=350,
            temperature=0.0,
            timeout=45.0
        )
        
        vision_analysis = response.choices[0].message.content
        if not vision_analysis or "can't describe" in vision_analysis.lower() or "cannot describe" in vision_analysis.lower() or "i am unable to" in vision_analysis.lower():
            # Fallback to local heuristic description
            fallback_parts = []
            if skin_ratio > 30:
                fallback_parts.append(f"Significant skin exposure detected ({skin_ratio}% of image area).")
            if keywords:
                detected = [k.replace('_', ' ') for k, v in keywords.items() if v]
                if detected:
                    fallback_parts.append(f"Contextual signals identified: {', '.join(detected)}.")
            
            refusal_prefix = "[Vision AI Refusal Fallback]: "
            if not fallback_parts:
                return f"{refusal_prefix}The content contains patterns that triggered safety protocols (Decision: {decision}). Contextual reasoning: {reason}."
            return f"{refusal_prefix}{' '.join(fallback_parts)} This combination of signals supports a {decision} status for educational safety."
            
        return vision_analysis
    except Exception as e:
        nsfw_logger.error(f"AI Analysis failed: {e}")
        return f"[System Fallback]: Analysis service reached capacity. Decision based on safety signals: {reason} (Skin: {skin_ratio}%)."

def determine_final_decision(score, skin_ratio, keywords, evidence, content, image_hash, methods):
    policy = get_active_policy()
    decision = "SAFE"
    reason = "No inappropriate content detected"
    action = "allow"

    # Define strict thresholds from policy
    BLOCK_THRESHOLD = policy.get('block_threshold', 0.35)
    REVIEW_THRESHOLD = policy.get('review_threshold', 0.15)

    # Contextual labeling
    context_labels = []
    
    # Policy-driven flags
    is_swimwear_beach = keywords.get('swimwear') and keywords.get('beach_context')
    if is_swimwear_beach:
        if policy.get('flag_beach_context'):
            context_labels.append("Policy Flag: Swimwear/Beach detected")
        else:
            context_labels.append("Educational Context: Swimwear/Beach detected (Neutral)")
    
    if keywords.get('bra_lingerie'):
        if policy.get('flag_lingerie'):
            context_labels.append("Contextual Risk: Potential lingerie detected")
        else:
            context_labels.append("Contextual Signal: Lingerie pattern (Low priority)")

    # Core logic
    if score >= BLOCK_THRESHOLD:
        decision = "block"
        reason = "High-confidence policy violation detected"
        action = "block_and_send_to_admin_review"
    elif score >= REVIEW_THRESHOLD or (policy.get('flag_lingerie') and keywords.get('bra_lingerie')) or (keywords.get('bed_context') and skin_ratio > 40):
        decision = "review"
        reason = "Soft flag: Ambiguous content requiring human context"
        action = "send_to_admin_review"
    else:
        decision = "safe"
        reason = "Content meets safety standards"
        action = "allow"

    if context_labels:
        reason += " | " + " | ".join(context_labels)

    # Vision Analysis for Detail
    vision_analysis = None
    if decision in ['block', 'review']:
        vision_analysis = analyze_with_llama_vision(content, decision, reason, keywords, skin_ratio)

    return decision, reason, action, vision_analysis

@app.context_processor
def inject_appeals_count():
    """Inject appeals count globally into all templates"""
    count = 0
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_cache WHERE review_status = 'pending_appeal'")
        count = cursor.fetchone()[0]
        conn.close()
    except Exception as e:
        print(f"Error injecting appeals count: {e}")
    return dict(appeals_count=count)

@app.route("/")
def index():
    return render_template("index.html", local_model=LOCAL_MODEL_AVAILABLE)

@app.route("/upload")
def upload_page():
    return render_template("upload.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            log_audit("admin_login", {"success": True})
            return redirect(url_for('admin_dashboard'))
        else:
            log_audit("admin_login_failed", {"success": False})
            return render_template("admin_login.html", error="Invalid password")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop('admin_authenticated', None)
    log_audit("admin_logout", {})
    return redirect(url_for('index'))

@app.route("/admin")
@require_admin
def admin_dashboard():
    return render_template("admin.html")

def generate_risk_heatmap_from_data(image_hash, skin_ratio, decision):
    # This is a placeholder as original bytes are not in DB
    # In a real app, you'd store the image in object storage or the heatmap string in DB
    return None

@app.route("/admin/appeals")
@require_admin
def admin_appeals():
    return render_template("appeals.html")

@app.route("/api/flagged")
@require_admin
def get_flagged():
    # Load all items from DB to ensure queue is current
    items = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_cache ORDER BY cached_at DESC LIMIT 200")
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            data = dict(row)
            item = {
                "id": data['id'], # Use DB ID for consistency
                "timestamp": data['cached_at'],
                "flagged_at": data['cached_at'],
                "image_hash": data['image_hash'],
                "decision": data['decision'],
                "reason": data['reason'],
                "score": data['primary_score'],
                "primary_score": data['primary_score'],
                "skin_ratio": data['skin_ratio'],
                "review_status": data['review_status'],
                "evidence": json.loads(data['evidence'] or '{}'),
                "vision_analysis": data['vision_analysis'],
                "anvesh_vision_analysis": data['vision_analysis'],
                "methods": json.loads(data['methods'] or '[]'),
                "heatmap": data.get('heatmap')
            }
            items.append(item)
    except Exception as e:
        print(f"Error in get_flagged: {e}")
    
    return jsonify(items)

@app.route("/api/review/<int:item_id>/<action>", methods=["POST"])
@require_admin
def review_action(item_id, action):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Find hash by ID first
        cursor.execute("SELECT image_hash FROM scan_cache WHERE id = ?", (item_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "message": "Item not found"}), 404
        
        image_hash = row[0]
        
        if action == 'approved':
            cursor.execute('UPDATE scan_cache SET review_status = ?, approved_at = ? WHERE id = ?',
                          (action, datetime.now().isoformat(), item_id))
        elif action == 'rejected':
            cursor.execute('UPDATE scan_cache SET review_status = ?, rejected_at = ? WHERE id = ?',
                          (action, datetime.now().isoformat(), item_id))
        
        conn.commit()
        conn.close()
        
        log_audit(f"review_{action}", {"item_id": item_id, "image_hash": image_hash})
        nsfw_logger.info(f"REVIEW ACTION | ID: {item_id} | Hash: {image_hash[:16]} | Action: {action}")
        return jsonify({"success": True, "message": f"Item {action}ed"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/revoke/<int:item_id>", methods=["POST"])
@require_admin
def revoke_review(item_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT image_hash, review_status FROM scan_cache WHERE id = ?", (item_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "message": "Item not found"}), 404
        
        image_hash, previous_status = row
        cursor.execute('UPDATE scan_cache SET review_status = ?, approved_at = NULL, rejected_at = NULL WHERE id = ?', 
                      ('pending', item_id))
        conn.commit()
        conn.close()
        
        log_audit("review_revoked", {
            "item_id": item_id,
            "image_hash": image_hash,
            "previous_status": previous_status
        })
        nsfw_logger.warning(f"REVIEW REVOKED | ID: {item_id} | Hash: {image_hash[:16]} | Previous: {previous_status}")
        return jsonify({"success": True, "message": "Review revoked, item returned to pending queue"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/ethical-ai")
def ethical_ai():
    return render_template("ethical_ai.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/bias-testing")
def bias_testing():
    return render_template("bias_testing.html")

@app.route("/education")
def education():
    return render_template("education.html")

@app.route("/disclaimer")
def disclaimer():
    return render_template("disclaimer.html")

@app.route("/deployment")
def deployment():
    return render_template("deployment.html")

@app.route("/demo-plan")
def demo_plan():
    return render_template("demo_plan.html")

@app.route("/architecture")
def architecture():
    return render_template("architecture.html")

@app.route("/screenshot")
def screenshot_page():
    return render_template("screenshot.html")

@app.route("/scan", methods=["POST"])
def scan_image():
    if 'image' not in request.files:
        return jsonify({"error": "no image file"}), 400

    f = request.files['image']
    content = f.read()
    image_hash = compute_image_hash(content)
    
    # Check if image was previously scanned and has been approved/rejected
    cached = get_cached_decision(image_hash)
    if cached and cached.get('review_status') in ['approved', 'rejected']:
        review_status = cached.get('review_status')
        review_status_upper = review_status.upper() if review_status else "UNKNOWN"
        nsfw_logger.info(f"Cache HIT | Hash: {image_hash[:16]} | Previous: {review_status} | Decision: {cached.get('decision')}")
        
        # Map decision to action
        cached_decision = cached.get('decision', 'safe').lower()
        if cached_decision == 'block':
            cached_action = 'block_and_send_to_admin_review'
        elif cached_decision == 'review':
            cached_action = 'send_to_admin_review'
        else:
            cached_action = 'allow'
        
        cache_result = {
            "timestamp": int(time.time()),
            "image_hash": image_hash,
            "decision": cached.get('decision'),
            "reason": cached.get('reason'),
            "action": cached_action,
            "primary_score": cached.get('primary_score', 0),
            "skin_ratio": cached.get('skin_ratio', 0),
            "from_cache": True,
            "cache_status": review_status,
            "cached_at": cached.get('cached_at'),
            "summary": f"[FROM CACHE] Decision: {cached.get('decision')} (Previously {review_status_upper}). Score: {cached.get('primary_score', 0)}, Skin Ratio: {cached.get('skin_ratio', 0)}%",
            "vision_analysis": cached.get('vision_analysis'),
            "methods": json.loads(cached.get('methods', '[]')) if isinstance(cached.get('methods'), str) else cached.get('methods', []),
            "evidence": json.loads(cached.get('evidence', '{}')) if isinstance(cached.get('evidence'), str) else cached.get('evidence', {})
        }
        return jsonify(cache_result)
    
    nsfw_logger.info(f"Cache MISS | Hash: {image_hash[:16]} | New scan required")

    result = {
        "timestamp": int(time.time()),
        "image_hash": image_hash,
        "methods": [],
        "decision": "safe",
        "reason": "",
        "evidence": {},
        "thresholds_used": {
            "safe_threshold": 0.15,
            "review_threshold_lower": 0.15,
            "review_threshold_upper": 0.35,
            "block_threshold": 0.35,
            "skin_ratio_review": 40,
            "skin_ratio_suspicious": 60
        },
        "keywords_detected": {},
        "skin_ratio": 0
    }

    skin_ratio = calculate_skin_ratio(content)
    result['skin_ratio'] = skin_ratio
    result['methods'].append("skin_ratio_detection")

    highest_score = 0.0
    sightengine_response = None

    # Layer 1: Local NudeNet Detection
    local = local_nudenet_classify_bytes(content)
    if local and isinstance(local, list) and len(local) > 0:
        try:
            first = local[0]
            unsafe_score = float(first.get("unsafe", 0))
            safe_score = float(first.get("safe", 0))
            
            # Always ensure local_nudenet is added to methods
            if "local_nudenet" not in result['methods']:
                result['methods'].append("local_nudenet")
                
            result['evidence']['nudenet'] = {
                "unsafe": round(unsafe_score, 4),
                "safe": round(safe_score, 4),
                "confidence": round(max(unsafe_score, safe_score), 4)
            }
            highest_score = max(highest_score, unsafe_score)
        except Exception as e:
            nsfw_logger.error(f"NudeNet parsing error: {e}")
    else:
        # If NudeNet returned empty list but succeeded, still count it as a method
        # but with 0 score (meaning it found nothing)
        if "local_nudenet" not in result['methods']:
            result['methods'].append("local_nudenet")
        result['evidence']['nudenet'] = {"unsafe": 0.0, "safe": 1.0, "confidence": 1.0}

    sight = check_with_sightengine_bytes(content)
    if sight:
        sightengine_response = sight
        result['methods'].append("sightengine")
        nudity = sight.get('nudity', {})
        sexual_activity = nudity.get('sexual_activity', 0)
        sexual_display = nudity.get('sexual_display', 0)
        combined_score = sexual_activity + sexual_display

        result['evidence']['sightengine'] = {
            "sexual_activity": round(sexual_activity, 4),
            "sexual_display": round(sexual_display, 4),
            "combined_score": round(combined_score, 4),
            "raw_response": nudity
        }

        highest_score = max(highest_score, combined_score)

    keywords = detect_contextual_keywords(sightengine_response)
    result['keywords_detected'] = keywords

    # Layer 2: Decision Scoring
    decision, reason, action, vision_analysis = determine_final_decision(
        highest_score,
        skin_ratio,
        keywords,
        result['evidence'],
        content,
        image_hash,
        result['methods']
    )

    # Layer 3: Vision Analysis already handled in determine_final_decision
    result['vision_analysis'] = vision_analysis

    # Generate Privacy Heatmap
    heatmap = generate_risk_heatmap(content, skin_ratio, decision)
    if not heatmap:
        heatmap = ""
    result['heatmap'] = heatmap

    result['decision'] = decision
    result['reason'] = reason
    result['action'] = action
    result['primary_score'] = round(highest_score, 4)
    result['summary'] = f"Decision: {decision}. Action: {action.replace('_', ' ').title()}. Score: {highest_score:.4f}, Skin Ratio: {skin_ratio}%"

    nsfw_logger.info(
        f"SCAN | Hash: {image_hash[:16]} | Decision: {decision} | Score: {highest_score:.4f} | "
        f"Skin: {skin_ratio}% | Keywords: {keywords} | Reason: {reason}"
    )

    # Save to SQLite Cache
    save_scan_to_cache(image_hash, result)

    # Determine if item should be added to flagged queue
    if action in ["send_to_admin_review", "block_and_send_to_admin_review"] and decision != "safe":
        # Ensure action is passed correctly to the frontend
        result['action'] = action
        
        flagged_item = {
            "id": len(flagged_items),
            "timestamp": datetime.now().isoformat(),
            "flagged_at": datetime.now().isoformat(),
            "image_hash": image_hash,
            "decision": decision,
            "reason": reason,
            "score": round(highest_score, 4),
            "primary_score": round(highest_score, 4),
            "skin_ratio": skin_ratio,
            "review_status": "pending",
            "evidence": result['evidence'],
            "vision_analysis": vision_analysis,
            "anvesh_vision_analysis": vision_analysis,
            "action": action,
            "heatmap": heatmap,
            "methods": result.get('methods', []),
            "keywords_detected": keywords
        }
        # Avoid duplicate flagging in memory if same hash scanned twice in same session
        if not any(i['image_hash'] == image_hash and i['review_status'] == 'pending' for i in flagged_items):
            flagged_items.append(flagged_item)
        
        # PERSISTENT STORAGE: Ensure it's in the DB with 'pending' status
        save_scan_to_cache(image_hash, result)
        
        log_audit("image_flagged", {
            "image_hash": image_hash,
            "decision": decision,
            "methods": result['methods'],
            "skin_ratio": skin_ratio,
            "keywords": keywords
        })
        nsfw_logger.warning(
            f"FLAGGED | Hash: {image_hash[:16]} | Decision: {decision} | "
            f"Score: {highest_score:.4f} | Skin: {skin_ratio}%"
        )
    else:
        # Also cache SAFE decisions
        save_scan_to_cache(image_hash, result)

    log_audit("image_scanned", {
        "image_hash": image_hash,
        "decision": decision,
        "methods": result['methods']
    })

    return jsonify(result)

@app.route("/api/chat", methods=["POST"])
def chat_assistant():
    data = request.get_json()
    message = data.get('message', '')
    image_hash = data.get('image_hash', '')
    
    if not groq_client:
        return jsonify({"reply": "I'm sorry, my AI analysis brain is currently offline. Please contact an administrator directly."})
    
    context = ""
    if image_hash:
        cached = get_cached_decision(image_hash)
        if cached:
            context = f"\n\nSystem Context: The user's image (hash: {image_hash[:8]}) was flagged as {cached['decision']} because: {cached['reason']}."
            if cached.get('vision_analysis'):
                context += f"\nAI Vision Analysis: {cached['vision_analysis']}"

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-70b-versatile",
            messages=[
                {"role": "system", "content": "You are ClassShield Assistant, a helpful AI guide for a school safety system. Your goal is to explain why images might be flagged in a professional, empathetic, and clear way. Schools use automated tools to protect students. If an image is flagged, it usually means certain patterns (like high skin ratios or specific clothing) triggered a review. Users can appeal if they think it's a mistake." + context},
                {"role": "user", "content": message}
            ],
            max_tokens=300
        )
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        return jsonify({"reply": f"I encountered an error processing your request: {str(e)}"})

@app.route("/api/appeal", methods=["POST"])
def submit_appeal():
    data = request.get_json()
    image_hash = data.get('image_hash')
    reason = data.get('reason')
    
    if not image_hash or not reason:
        return jsonify({"success": False, "message": "Missing image hash or reason"}), 400
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if the scan exists
        cursor.execute("SELECT id FROM scan_cache WHERE image_hash = ?", (image_hash,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Image record not found"}), 404
            
        # Update review status to 'pending_appeal'
        cursor.execute("UPDATE scan_cache SET review_status = 'pending_appeal', vision_analysis = vision_analysis || ? WHERE image_hash = ?", 
                      (f"\n\n[USER APPEAL]: {reason}", image_hash))
        conn.commit()
        conn.close()
        
        # Update in-memory if present
        for item in flagged_items:
            if item['image_hash'] == image_hash:
                item['review_status'] = 'pending_appeal'
                item['anvesh_vision_analysis'] = (item.get('anvesh_vision_analysis') or "") + f"\n\n[USER APPEAL]: {reason}"
                
        log_audit("appeal_submitted", {"image_hash": image_hash, "reason": reason})
        return jsonify({"success": True, "message": "Appeal submitted successfully. An administrator will review it shortly."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/status")
def status():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_cache")
        total_scans = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_cache WHERE decision IN ('REVIEW', 'BLOCK')")
        total_flagged = cursor.fetchone()[0]
        conn.close()
    except:
        total_scans = 0
        total_flagged = len(flagged_items)

    return jsonify({
        "project": "ClassShield V2",
        "status": "ok",
        "local_model": LOCAL_MODEL_AVAILABLE,
        "sightengine_configured": bool(SIGHT_USER and SIGHT_SECRET),
        "flagged_items": total_flagged,
        "total_scans": total_scans,
        "vision_analysis": VISION_AVAILABLE,
        "cache_enabled": True
    })

@app.route("/api/screenshot", methods=["POST"])
def take_screenshot():
    data = request.get_json()
    url = data.get("url", request.host_url)

    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")

        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        time.sleep(2)

        screenshot_bytes = driver.get_screenshot_as_png()
        driver.quit()

        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

        log_audit("screenshot_taken", {"url": url, "timestamp": datetime.now().isoformat()})
        nsfw_logger.info(f"SCREENSHOT | URL: {url}")

        return jsonify({
            "success": True,
            "screenshot": f"data:image/png;base64,{screenshot_base64}",
            "url": url,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        nsfw_logger.error(f"Screenshot error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

if __name__ == "__main__":
    init_cache_db()
    load_flagged_from_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)