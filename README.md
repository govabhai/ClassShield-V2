<p align="center">
   <img src="https://github.com/ClassShield/ClassShield-School-Content-Safety-System-NSFW-Detector/blob/main/images/logo.png" width="25%">
</p>

# ClassShield - AI-Powered School Content Safety

**ClassShield** is a transparent, ethical content moderation prototype designed for educational environments. It combines high-performance machine learning with human oversight to protect students while upholding privacy and institutional trust.

## 🚀 Core Innovation: The Three-Tier Defense
ClassShield processes images through a linear, multi-layered safety pipeline:
1.  **Layer 1 (ML Detection):** Local NudeNet models and Sightengine cloud validation.
2.  **Layer 2 (Contextual Scoring):** RGB skin ratio analysis and keyword-based risk assessment.
3.  **Layer 3 (AI Vision Context):** Groq-powered Llama Vision analysis providing 360-degree situational context.

## 🛡️ Key Features

### 1. Dynamic Policy Configuration Engine
Administrators can customize safety thresholds on the fly.
- **Block Thresholds:** Adjust sensitivity for hard-blocking content.
- **Review Thresholds:** Set "Soft Flags" for human review without interrupting student workflows.
- **Context Toggles:** Enable/disable specific rules for beach context, swimwear, or lingerie patterns.

### 2. High-Trust Admin Review Dashboard
- **Soft vs. Hard Flags:** Clear separation between "Review Only" and "Blocked" content to reduce cognitive load.
- **Privacy Heatmaps:** Blurred risk zones that highlight concerns (Red for risk, Yellow for skin) without exposing admins to explicit content.
- **Deterministic Caching:** SHA-256 image hashing ensures identical images receive identical decisions, guaranteed by SQLite.

### 3. Ethical & Transparent Design
- **No Auto-Deletion:** Human verification is mandatory for all disciplinary actions.
- **Privacy-First:** Images are processed entirely in memory; only cryptographic hashes are stored for audit logs.
- **Contextual Awareness:** Explicitly labels neutral context (e.g., educational beach photos) to prevent false-positive frustration.

## 🛠️ Technology Stack
- **Backend:** Flask (Python 3.11)
- **AI/ML:** NudeNet (Local), Sightengine API, Groq (Llama-3.2-90b-vision)
- **Database:** SQLite (Policy & Decision Caching)
- **Image Processing:** OpenCV, PIL, NumPy
- **Frontend:** Bootstrap 5, Vanilla JavaScript

## 📦 Installation & Setup

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Secrets:**
   Add the following to your environment/secrets:
   - `SIGHTENGINE_API_USER`
   - `SIGHTENGINE_API_SECRET`
   - `GROQ_API_KEY`
   - `ADMIN_PASSWORD`

3. **Launch:**
   ```bash
   python main.py
   ```
   Access the dashboard at `http://localhost:5000`.

## 📖 Project Documentation
The web interface includes comprehensive guides:
- `/ethical-ai`: 6-point core principle breakdown.
- `/bias-testing`: Performance report across Fitzpatrick skin tones I-VI.
- `/education`: Student-facing materials on safety and AI.
- `/submission`: Judge-ready technical package.

---
## Acknowledgments


<img src="https://avatars.githubusercontent.com/u/202682181?v=4" width="25%">

**ClassShield is founded and developed by [Anvesh Raman](https://github.com/developeranveshraman)**

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
**Built for safety, driven by ethics, verified by humans.**
