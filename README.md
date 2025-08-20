# -*- coding: utf-8 -*-
"""
Pre-Run Inspector (Arabic) – by Developer: Osama
فاحص ثابت قبل التشغيل: يحلّل ملف (py/exe) بدون ما يشغّله،
ويعطيك نظرة بالعربي عن المكتبات والسلوكيات المحتملة وروابط الشبكة.
"""

import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os, re, json, sys

# محاولة استيراد pefile لتحليل EXE (اختياري)
try:
    import pefile
    HAS_PEFILE = True
except Exception:
    HAS_PEFILE = False

# ===========================
# خرائط وصف بالعربي للمكتبات
# ===========================
PY_LIB_DESCRIPTIONS = {
    # شبكات
    "socket": "اتصالات شبكية منخفضة المستوى (فتح سَوكِت/بورت وربط/اتصال).",
    "requests": "طلبات HTTP(S) إلى الإنترنت (GET/POST).",
    "urllib": "التعامل مع عناوين وروابط HTTP/FTP وتحميل بيانات.",
    "http": "بناء/استهلاك بروتوكول HTTP.",
    "ftplib": "اتصال FTP لنقل الملفات.",
    "paramiko": "اتصالات SSH/SFTP.",
    "websocket": "قنوات WebSocket ثنائية الاتجاه.",
    # ملفات/نظام
    "os": "عمليات نظام ملفات وبيئة ونفاذ لمسارات ونقاط تنفيذ.",
    "pathlib": "التعامل مع المسارات والملفات.",
    "shutil": "نسخ/نقل/حذف ملفات ومجلدات.",
    "subprocess": "تشغيل أوامر/برامج خارجية.",
    "winreg": "التعامل مع Windows Registry.",
    "ctypes": "نداءات نظام منخفضة المستوى وربط DLLs.",
    "psutil": "معلومات عمليات/موارد النظام.",
    # تشفير/ضغط/تغليف
    "hashlib": "تجزئة/هاش (MD5/SHA…).",
    "hmac": "توقيع HMAC.",
    "base64": "ترميز/فك ترميز Base64 (قد يخفي نصوص/حمولات).",
    "zlib": "ضغط/فك ضغط.",
    "gzip": "ضغط GZip.",
    "cryptography": "تشفير/فك تشفير متقدم.",
    "pycryptodome": "تشفير متنّوع (AES/RSA..).",
    # سلاسل/تعبيرات
    "re": "تعبيرات نمطية (مطابقة/إخفاء بيانات).",
    # رسائل/بوتات معروفة
    "telebot": "Telegram Bot API (اتصال تيليجرام).",
    "aiogram": "Telegram Bot (تيليجرام).",
    "pyrogram": "Telegram API (تيليجرام).",
    "telegram": "Telegram API عامة (تيليجرام).",
    "discord": "Discord API (بوت/اتصال).",
    "slack_sdk": "Slack API.",
}

# DLLs مهمة بويندوز ووصفها
PE_DLL_DESCRIPTIONS = {
    "WS2_32.DLL": "شبكات (Winsock) – اتصالات TCP/UDP.",
    "WININET.DLL": "اتصالات HTTP/FTP على ويندوز.",
    "WINHTTP.DLL": "HTTP على مستوى النظام.",
    "CRYPT32.DLL": "تشفير/شهادات.",
    "ADVAPI32.DLL": "ريجستري وحقوق/خدمات.",
    "KERNEL32.DLL": "وظائف نظام أساسية (ملفات/عمليات).",
    "USER32.DLL": "واجهة مستخدم/نوافذ.",
    "SHELL32.DLL": " shell عمليات ملفات/تشغيل.",
    "NTDLL.DLL": "نداءات نظام منخفضة المستوى.",
    "IPHLAPI.DLL": "عمليات شبكات IP Helper.",
    "URLMON.DLL": "تنزيلات/URLs.",
    "MSWSOCK.DLL": "امتدادات Winsock.",
}

# أنماط نعتبرها "سلوكيات مثيرة للاهتمام" (Python)
SUSPICIOUS_PY_PATTERNS = [
    (r"\bexec\(", "استخدام exec لتشغيل كود ديناميكي."),
    (r"\beval\(", "استخدام eval لتقييم نصوص كس كود."),
    (r"base64\.(b64decode|standard_b64decode)\(", "فك ترميز Base64 (قد يخفي حمولة)."),
    (r"subprocess\.(Popen|call|run)\(", "تشغيل أوامر/برامج خارجية."),
    (r"socket\.(socket|create_connection)\(", "إنشاء اتصال شبكي."),
    (r"requests\.(get|post|put|delete)\(", "طلب HTTP(S) إلى الإنترنت."),
    (r"urllib\.", "نشاط HTTP/FTP عبر urllib."),
    (r"winreg\.", "وصول لسجل ويندوز."),
    (r"ctypes\.", "نداءات نظام منخفضة/تحميل DLL."),
    (r"open\([^,]+,\s*[\"'](w|a|wb|ab)", "فتح ملف للكتابة/الإلحاق (تعديل ملفات)."),
]

URL_REGEX = re.compile(rb"(https?://[^\s'\"<>]+)")
IP_REGEX  = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ===========================
# أدوات تحليل
# ===========================
def read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read(), "utf-8"
    except Exception:
        try:
            with open(path, "r", encoding="latin-1") as f:
                return f.read(), "latin-1"
        except Exception as e:
            return "", None

def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""

def analyze_python(path):
    """
    تحليل ثابت لملف .py:
    - استيرادات
    - أنماط سلوك مشبوهة
    - روابط/IPs ضمن النصوص
    """
    report = {
        "type": "python",

"file": path,
        "imports": [],
        "imports_desc": [],
        "suspicious_hits": [],
        "urls": [],
        "ips": [],
        "summary": "",
    }

    code, enc = read_text(path)
    if not enc:
        report["summary"] = "تعذّر قراءة الملف كنص."
        return report

    # استيرادات بسيطة عبر regex (خفيف وبلا AST لتعويض البيئات المحدودة)
    import_names = set()
    for m in re.finditer(r"^\s*import\s+([a-zA-Z0-9_\.]+)", code, flags=re.MULTILINE):
        import_names.add(m.group(1).split(".")[0])
    for m in re.finditer(r"^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+", code, flags=re.MULTILINE):
        import_names.add(m.group(1).split(".")[0])

    report["imports"] = sorted(import_names)

    # وصف عربي لكل import معروف
    desc_list = []
    for imp in report["imports"]:
        if imp in PY_LIB_DESCRIPTIONS:
            desc_list.append(f"{imp} → {PY_LIB_DESCRIPTIONS[imp]}")
    report["imports_desc"] = desc_list

    # أنماط سلوك
    for pattern, arabic in SUSPICIOUS_PY_PATTERNS:
        if re.search(pattern, code):
            report["suspicious_hits"].append(arabic)

    # روابط و IPs (من النص الخام أيضًا تحسبًا للسلاسل داخل الكود)
    raw = code.encode("utf-8", errors="ignore")
    urls = [u.decode("utf-8", errors="ignore") for u in set(URL_REGEX.findall(raw))]
    ips  = [i.decode("utf-8", errors="ignore") for i in set(IP_REGEX.findall(raw))]

    report["urls"] = sorted(urls)
    report["ips"]  = sorted(ips)

    # خلاصة
    hints = []
    if any(x in report["imports"] for x in ["socket", "requests", "urllib", "telebot", "aiogram", "pyrogram", "telegram", "discord"]):
        hints.append("يرجّح وجود نشاط شبكي/اتصال بخدمات خارجية.")
    if any("تشغيل أوامر/برامج خارجية" in s for s in report["suspicious_hits"]):
        hints.append("يشغّل أوامر/برامج خارجية (قد يعدّل النظام).")
    if any("فتح ملف للكتابة" in s for s in report["suspicious_hits"]):
        hints.append("قد يكتب أو يغيّر ملفات على القرص.")
    if any(x in report["imports"] for x in ["ctypes", "winreg"]):
        hints.append("قد يصل لواجهات نظام منخفضة/الريجستري.")

    if not hints and not report["suspicious_hits"]:
        report["summary"] = "لم يتم رصد مؤشرات واضحة للخطورة ضمن التحليل الثابت. (قد لا يكون هذا كافيًا للحكم النهائي)"
    else:
        report["summary"] = "؛ ".join(hints) or "مؤشرات متنوعة تتطلّب مراجعة."

    return report

def analyze_exe(path):
    """
    تحليل مبسّط للـ EXE (PE):
    - قائمة DLLs المستوردة (إذا متوفر pefile)
    - سلاسل نصية لاستخراج روابط/IPs
    """
    report = {
        "type": "exe",
        "file": path,
        "dlls": [],
        "dlls_desc": [],
        "urls": [],
        "ips": [],
        "summary": "",
        "note": "",
    }

    data = read_bytes(path)
    if not data:
        report["summary"] = "تعذّر قراءة الملف."
        return report

    # روابط/IPs من الباينري
    urls = [u.decode("utf-8", errors="ignore") for u in set(URL_REGEX.findall(data))]
    ips  = [i.decode("utf-8", errors="ignore") for i in set(IP_REGEX.findall(data))]
    report["urls"] = sorted(urls)
    report["ips"]  = sorted(ips)

    if HAS_PEFILE:
        try:
            pe = pefile.PE(path)
            dlls = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    name = entry.dll.decode(errors="ignore").upper() if entry.dll else ""
                    if name:
                        dlls.append(name)
            report["dlls"] = sorted(set(dlls))

            desc = []
            for d in report["dlls"]:
                if d in PE_DLL_DESCRIPTIONS:
                    desc.append(f"{d} → {PE_DLL_DESCRIPTIONS[d]}")
            report["dlls_desc"] = desc
        except Exception as e:
            report["note"] = f"فشل تحليل PE: {e}"
    else:
        report["note"] = "تحليل DLLs يتطلب pefile (اختياري): pip install pefile"

    # خلاصة
    hints = []
    if any(d in report["dlls"] for d in ["WS2_32.DLL", "WININET.DLL", "WINHTTP.DLL", "MSWSOCK.DLL", "URLMON.DLL"]):
        hints. 

       append("اعتماد على مكتبات شبكات → نشاط اتصالات محتمل.")
    if any(d in report["dlls"] for d in ["ADVAPI32.DLL", "KERNEL32.DLL"]):
        hints.append("وصول لوظائف نظام/ملفات/خدمات.")
    if report["urls"] or report["ips"]:
        hints.append("عُثر على روابط/عناوين داخل الملف (محتمل اتصالات خارجية).")

    report["summary"] = "؛ ".join(hints) or "لم تظهر مؤشرات واضحة من تحليل سريع."

    return report

# ===========================
# GUI
# ===========================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("فاحص قبل التشغيل – Developer: Osama")
        self.geometry("880x620")
        self.configure(bg="#0f172a")  # خلفية داكنة

        # عنوان
        tk.Label(self, text="فاحص ثابت قبل التشغيل",
                 font=("Segoe UI", 18, "bold"),
                 fg="#ffffff", bg="#0f172a").pack(pady=8)

        # أزرار
        btn_frame = tk.Frame(self, bg="#0f172a")
        btn_frame.pack(pady=6)

        self.run_btn = tk.Button(btn_frame, text="اختر ملف للفحص",
                                 command=self.choose_file,
                                 font=("Segoe UI", 12), bg="#22c55e", fg="white",
                                 width=16, height=2, bd=0, activebackground="#16a34a")
        self.run_btn.grid(row=0, column=0, padx=6)

        self.save_btn = tk.Button(btn_frame, text="حفظ التقرير",
                                  command=self.save_report,
                                  font=("Segoe UI", 12), bg="#3b82f6", fg="white",
                                  width=16, height=2, bd=0, activebackground="#2563eb", state=tk.DISABLED)
        self.save_btn.grid(row=0, column=1, padx=6)

        self.clear_btn = tk.Button(btn_frame, text="مسح النتائج",
                                   command=self.clear_output,
                                   font=("Segoe UI", 12), bg="#f97316", fg="white",
                                   width=16, height=2, bd=0, activebackground="#ea580c")
        self.clear_btn.grid(row=0, column=2, padx=6)

        # صندوق النتائج
        self.output = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=26,
                                                font=("Consolas", 11),
                                                bg="#111827", fg="#e5e7eb",
                                                insertbackground="#e5e7eb", bd=0)
        self.output.pack(padx=14, pady=10, fill="both", expand=True)

        # تذييل
        tk.Label(self, text="Developer: Osama – هذا الفحص ثابت فقط ولا يشغّل الملف",
                 font=("Segoe UI", 9), fg="#9ca3af", bg="#0f172a").pack(pady=(0,8))

        self.last_report = None

    def log(self, s):
        self.output.insert(tk.END, s + "\n")
        self.output.see(tk.END)

    def clear_output(self):
        self.output.delete("1.0", tk.END)
        self.last_report = None
        self.save_btn.config(state=tk.DISABLED)

    def choose_file(self):
        path = filedialog.askopenfilename(title="اختر ملف للفحص",
                                          filetypes=[("Python/EXE", "*.py *.exe"),
                                                     ("All files", "*.*")])
        if not path:
            return
        self.clear_output()
        self.log(f"📄 الملف: {path}")
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".py":
                rep = analyze_python(path)
            elif ext == ".exe":
                rep = analyze_exe(path)
            else:
                self.log("⚠️ نوع الملف غير مدعوم تحليله تلقائيًا.")
                return

            self.present_report(rep)
            self.last_report = rep
            self.save_btn.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل التحليل: {e}")

    def present_report(self, rep: dict):
        t = rep.get("type")
        self.log("========================================")
        if t == "python":
            self.log("🧠 نوع الهدف: Python script")
            imps = rep.get("imports", [])
            if imps:
                self. 
                log("\n📦 المكتبات المستوردة:")
                self.log(" - " + "\n - ".join(imps))
            desc = rep.get("imports_desc", [])
            if desc:
                self.log("\n📝 وصف المكتبات:")
                self.log(" - " + "\n - ".join(desc))

            hits = rep.get("suspicious_hits", [])
            if hits:
                self.log("\n🚩 سلوكيات مثيرة للاهتمام:")
                self.log(" - " + "\n - ".join(hits))

            urls = rep.get("urls", [])
            ips  = rep.get("ips", [])
            if urls:
                self.log("\n🌐 روابط مرصودة داخل الكود:")
                self.log(" - " + "\n - ".join(urls))
            if ips:
                self.log("\n🌐 عناوين IP مرصودة:")
                self.log(" - " + "\n - ".join(ips))

            self.log("\n📌 الخلاصة:")
            self.log(rep.get("summary", ""))
        elif t == "exe":
            self.log("🧠 نوع الهدف: Windows EXE")
            if not HAS_PEFILE:
                self.log("ℹ️ ملاحظة: لتحليل DLLs بدقة، ثبّت pefile: pip install pefile")

            dlls = rep.get("dlls", [])
            if dlls:
                self.log("\n📦 DLLs المستوردة (من التحليل):")
                self.log(" - " + "\n - ".join(dlls))

            desc = rep.get("dlls_desc", [])
            if desc:
                self.log("\n📝 وصف DLLs المهمة:")
                self.log(" - " + "\n - ".join(desc))

            urls = rep.get("urls", [])
            ips  = rep.get("ips", [])
            if urls:
                self.log("\n🌐 روابط مرصودة داخل الباينري:")
                self.log(" - " + "\n - ".join(urls))
            if ips:
                self.log("\n🌐 عناوين IP مرصودة داخل الباينري:")
                self.log(" - " + "\n - ".join(ips))

            note = rep.get("note")
            if note:
                self.log(f"\nℹ️ ملاحظة: {note}")

            self.log("\n📌 الخلاصة:")
            self.log(rep.get("summary", ""))
        else:
            self.log("نوع تقرير غير معروف.")

        self.log("========================================")

    def save_report(self):
        if not self.last_report:
            return
        # حفظ TXT
        txt_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")],
            title="حفظ تقرير نصي"
        )
        if txt_path:
            try:
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(self.output.get("1.0", tk.END))
                self.log(f"💾 تم حفظ التقرير النصي: {txt_path}")
            except Exception as e:
                messagebox.showerror("خطأ", f"تعذّر حفظ TXT: {e}")

        # حفظ JSON (اختياري)
        json_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="حفظ تقرير JSON"
        )
        if json_path:
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(self.last_report, f, ensure_ascii=False, indent=2)
                self.log(f"💾 تم حفظ تقرير JSON: {json_path}")
            except Exception as e:
                messagebox.showerror("خطأ", f"تعذّر حفظ JSON: {e}")

if name == "__main__":
    app = App()
    app.mainloop()
