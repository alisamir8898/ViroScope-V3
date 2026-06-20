# ViroScope — Malware Triage Console

أداة محلية لفحص ملفات تنفيذية (.exe / .dll / إلخ) باستخدام موديل Machine Learning مُدرَّب
(RandomForest) + تكامل اختياري مع VirusTotal. تعمل بالكامل على جهازك (localhost)، مفيش رفع
لأي سيرفر خارجي غير VirusTotal لو فعّلت الخيار.

## المتطلبات

- Python 3.10 أو أحدث
- اتصال إنترنت فقط عشان تثبيت المكتبات أول مرة، وعشان خدمة VirusTotal (لو استخدمتها)

## التثبيت (مرة واحدة)

افتح Terminal / Command Prompt في مجلد المشروع، ونفّذ:

```bash
# 1. اعمل بيئة افتراضية (مفضّل، مش إجباري)
python -m venv venv

# تفعيل البيئة:
# على Windows:
venv\Scripts\activate
# على macOS/Linux:
source venv/bin/activate

# 2. ثبّت المكتبات
pip install -r requirements.txt
```

> **ملاحظة Windows**: مكتبة `pefile` بتحتاج أحيانًا Microsoft Visual C++ Build Tools لو فشل
> التثبيت. لو حصلت مشكلة، جرّب `pip install --upgrade pip` الأول وبعدين أعد المحاولة.

## إعداد مفتاح VirusTotal (اختياري لكن مُوصى به)

1. اعمل نسخة من ملف `.env.example` باسم `.env`:
   ```bash
   cp .env.example .env        # macOS/Linux
   copy .env.example .env      # Windows
   ```
2. افتح `.env` وضع مفتاحك:
   ```
   VT_API_KEY=ضع_مفتاحك_هنا
   ```
3. احفظ الملف.

لو سيبت `VT_API_KEY` فاضي، الـ app هيشتغل عادي بس بدون فحص VirusTotal (الموديل المحلي
هيفضل شغال طبيعي).

## التشغيل

```bash
python app.py
```

هتشوف في الـ Terminal:

```
ViroScope — Malware Triage Console
Running locally at http://127.0.0.1:5000
```

افتح المتصفح على: **http://127.0.0.1:5000**

للإيقاف: `Ctrl + C` في الـ Terminal.

## بنية المشروع

```
viroscope/
├── app.py                  # نقطة الدخول الرئيسية (Flask routes)
├── feature_extraction.py   # استخراج الـ 23 feature من ملفات PE
├── predictor.py            # تحميل الموديل + التنبؤ
├── vt_scanner.py           # تكامل VirusTotal API v3
├── database.py             # تخزين السجل التاريخي (SQLite)
├── malwareclassifier-V2.pkl # الموديل المدرَّب (RandomForest)
├── requirements.txt
├── .env.example
├── templates/               # صفحات HTML
├── static/css/style.css     # التصميم
├── uploads/                 # تخزين مؤقت للملفات أثناء الفحص (يُحذف تلقائيًا بعد كل فحص)
└── instance/viroscope.db     # قاعدة بيانات السجل التاريخي (تُنشأ تلقائيًا)
```

## الصفحات المتاحة

| الصفحة | الوصف |
|---|---|
| `/` | Dashboard — إحصائيات عامة وآخر الفحوصات |
| `/scan` | فحص ملف واحد |
| `/batch` | فحص عدة ملفات دفعة واحدة |
| `/history` | السجل التاريخي الكامل مع فلاتر بحث |

## ملاحظات أمان مهمة

- الموديل بيفحص **ملفات PE فقط** (.exe, .dll, .sys, .scr, .ocx, .cpl, .drv). أي نوع تاني
  هيرفض تلقائيًا.
- الملفات المرفوعة بتُحذف من السيرفر فورًا بعد انتهاء التحليل — مفيش تخزين دائم للملف نفسه،
  بس بيانات نتيجة التحليل (hash, verdict, confidence) هي اللي بتُحفظ في السجل التاريخي.
- متشغّلش ملفات تنفيذية حقيقية ضارة على جهازك أبدًا أثناء الاختبار — ViroScope بيحلل الملف
  إحصائيًا (static analysis) بدون تشغيله.
