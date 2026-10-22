# HTTP Proxy Control

لوحة تحكم ذاتية الاستضافة لإدارة منافذ **HTTP Proxy**، مع دعم HTTPS للمواقع عبر طريقة **CONNECT**. لكل منفذ اسم مستخدم وكلمة مرور مستقلان. افتراضيًا يستقبل المنفذ بروتوكول HTTP القياسي الذي تتوقعه إعدادات Proxy المعتادة في المتصفحات؛ ويمكن تفعيل TLS اختياريًا عند استخدام عميل يدعم **HTTPS Proxy**.

> **تنبيه:** هذا مستودع برمجي ومُثبت. لا يملك المشروع وصولًا إلى VPS الخاص بك؛ نفّذ التثبيت على خادمك كما هو موضح أدناه.

للاطلاع على الفروق عن المشروع المرجعي `inaz2/proxy2`، راجع [COMPARISON.md](COMPARISON.md).

## الميزات

- لوحة عربية لإضافة مستمعات الوكيل وتشغيلها وإيقافها وتغيير بياناتها أو حذفها.
- منفذ وبيانات دخول منفصلة لكل Proxy. كلمة مرور الوكيل تقبل 3 محارف فأكثر؛ اختر كلمة مرور أطول وفريدة للأمان.
- المستمع الجديد يبدأ افتراضيًا بـHTTP Proxy قياسي، ويقبل طلبات HTTP العادية وHTTPS عبر CONNECT.
- TLS اختياري لكل مستمع. يمكن التبديل بين HTTP وTLS للمنافذ الموجودة من اللوحة؛ عميل TLS يجب أن يضبط نوع الوكيل على HTTPS Proxy.
- تجزئة كلمات المرور بخوارزمية scrypt، جلسات لوحة موقعة، تقييد محاولات الدخول، وفحص Origin لطلبات التعديل.
- حظر الاتصال بعناوين loopback والشبكات الخاصة وlink-local وmetadata والعناوين غير العامة بعد فحص DNS.
- خدمة systemd بمستخدم محدود الصلاحيات. لا يفتح المُثبت منافذ جدار الحماية تلقائيًا.

## التثبيت على VPS

يدعم Ubuntu وDebian مع صلاحية `sudo`. سجّل الدخول إلى الـVPS عبر SSH، ثم شغّل:

```bash
curl -fsSL https://raw.githubusercontent.com/alrufaaey-yahoo/http-proxy-control/main/install.sh -o install.sh
sudo bash install.sh
```

سيطلب المُثبت منفذ لوحة التحكم (الافتراضي `8443`)، اسم مستخدم المدير، وكلمة مرور مدير لا تقل عن 16 محرفًا. يُنشئ شهادة ذاتية التوقيع للوحة، ويجهز Python وخدمة systemd.

بعد التثبيت:

1. افتح TCP لمنفذ لوحة التحكم في جدار حماية مزود الـVPS وUFW إن كان مستخدمًا، مثلًا `sudo ufw allow 8443/tcp` (استبدل الرقم بما اخترته).
2. افتح `https://عنوان-vps:منفذ-اللوحة` وسجّل الدخول. الشهادة الابتدائية ذاتية التوقيع؛ استبدلها بشهادة موثوقة قبل الاستخدام العام.
3. من **إضافة منفذ Proxy** اختر مثلًا `3128`، واسم مستخدم، وكلمة مرور من 3 محارف فأكثر. اترك خيار TLS غير محدد لاستخدام HTTP Proxy المعتاد في المتصفحات.
4. افتح TCP لمنفذ الوكيل في جدار حماية مزود الخادم وUFW، مثلًا: `sudo ufw allow 3128/tcp`.

لفحص الخدمة والسجلات:

```bash
sudo systemctl status http-proxy-control
sudo journalctl -u http-proxy-control -f
```

### إعداد المتصفح

في إعدادات الشبكة في المتصفح اختر نوع **HTTP Proxy**، وأدخل **عنوان IP العام أو اسم نطاق الـVPS** في حقل المضيف، والمنفذ الذي أنشأته (مثل `3128`). أدخل اسم المستخدم وكلمة المرور إذا ظهرت نافذة المصادقة. اترك إعداد SOCKS فارغًا. استعمل مستمع HTTP نفسه لطلبات HTTP وHTTPS؛ يقوم المتصفح بإنشاء CONNECT للمواقع الآمنة تلقائيًا.

**لا تستخدم رابط لوحة التحكم نفسه مع إضافة `:3128`** إلا إذا كان ذلك فعلًا اسم نطاق/عنوان الـVPS. رابط لوحة Preview أو Sandbox مؤقت ولا يمرّر منافذ Proxy إضافية. كذلك لا تستخدم `0.0.0.0` كعنوان في المتصفح؛ هذا عنوان ربط داخل الخادم وليس عنوان الاتصال العام. استخدم IP الـVPS أو DNS الخاص به.

### تغيير منفذ سابق من TLS إلى HTTP

إذا أنشأت مستمعًا قبل هذا التحديث وكان TLS مفعّلًا، فلن يعمل مع إعداد متصفح مضبوط على HTTP Proxy. بعد تحديث البرنامج، افتح لوحة الـVPS واضغط **تحويل إلى HTTP** بجانب المستمع. سيُعاد تشغيل المنفذ بالبروتوكول الجديد. أو أنشئ مستمعًا جديدًا واترك TLS غير محدد.

### شهادة TLS موثوقة للوحة أو لمستمع TLS

الشهادة الافتراضية ذاتية التوقيع ولا يثق بها المتصفح أو عميل الوكيل، واسمها لا يطابق عادة عنوان IP العام. لا تتجاوز تحذير الشهادة على شبكة غير موثوقة. إذا أردت TLS لمستمع الوكيل، أصدر شهادة لاسم نطاقك وضعها في:

```text
/etc/http-proxy-control/tls.crt
/etc/http-proxy-control/tls.key
```

ثم اضبط الصلاحيات وأعد تشغيل الخدمة:

```bash
sudo chown root:proxyctl /etc/http-proxy-control/tls.crt /etc/http-proxy-control/tls.key
sudo chmod 0640 /etc/http-proxy-control/tls.crt /etc/http-proxy-control/tls.key
sudo systemctl restart http-proxy-control
```

لعميل TLS استخدم نوع **HTTPS Proxy** واسم النطاق المطابق للشهادة. لا تفعّل TLS إذا كان عميلك مضبوطًا على HTTP Proxy.

## اختبار سريع باستخدام curl

للوكيل القياسي غير المشفر على المنفذ 3128:

```bash
curl --proxy http://VPS_IP:3128 \
     --proxy-user 'USERNAME:PASSWORD' \
     https://example.com/
```

ولطلب HTTP عادي:

```bash
curl --proxy http://VPS_IP:3128 \
     --proxy-user 'USERNAME:PASSWORD' \
     http://example.com/
```

إذا فعّلت TLS لمستمع الوكيل وكانت الشهادة موثوقة للعميل:

```bash
curl --proxy https://proxy.example.com:3128 \
     --proxy-cacert /path/to/trusted-proxy-ca.pem \
     --proxy-user 'USERNAME:PASSWORD' \
     https://example.com/
```

لا تستخدم `--proxy-insecure` إلا لاختبار شهادة ذاتية التوقيع ولمرة مؤقتة. تجنب وضع كلمة المرور في أوامر الطرفية على أنظمة مشتركة.

## إعدادات الخدمة

- ملف البيئة: `/etc/http-proxy-control.env`.
- قاعدة البيانات: `/var/lib/http-proxy-control/proxy.db`؛ تحفظ كلمات المرور كـscrypt hashes.
- التطبيق: `/opt/http-proxy-control`.
- وحدة systemd: `http-proxy-control.service`.
- يستمع الوكيل على كل واجهات IPv4 (`0.0.0.0`)، لكن الاتصال به يكون عبر IP عام أو DNS للـVPS، وليس `0.0.0.0`.

## الأمان والحدود

- كل مستمع محمي باسم مستخدم وكلمة مرور؛ لا توجد منافذ مجهولة.
- كلمة المرور ذات 3 محارف مسموح بها لتلبية التوافق المطلوب، لكنها ضعيفة جدًا. استخدم 12 محرفًا عشوائيًا على الأقل إن أمكن، ولا تعِد استخدام كلمة مرور أخرى.
- HTTP Proxy غير المشفر يرسل ترويسة مصادقة Basic دون تشفير على وصلة العميل إلى الـVPS. استخدم TLS مع عميل يدعم HTTPS Proxy أو قيّد المنفذ إلى شبكة خاصة/قائمة IP موثوقة. HTTPS للمواقع عبر CONNECT يحمي محتوى الموقع بين المتصفح والموقع، لكنه لا يشفر اعتماد Proxy على وصلة العميل.
- لا تعرض الوكيل للجمهور دون ضوابط. قيّد الوصول في جدار الحماية وشارك بيانات الدخول مع مستخدمين موثوقين.
- يحظر البرنامج عناوين IP غير العامة بعد حل DNS. هذا يقلل الوصول للشبكات الداخلية لكنه ليس سياسة وجهات شاملة.
- حدود الطلب: رؤوس حتى 64 KiB، أجسام حتى 64 MiB، وخمول الاتصال حتى 120 ثانية. لا يدعم SOCKS أو HTTP/2.

## الاختبارات والتطوير

يتطلب Python 3.10 أو أحدث:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

تتضمن الاختبارات رفض الوصول إلى الشبكات الخاصة، المصادقة، كلمة المرور القصيرة المدعومة، تحويل HTTP، ونفق CONNECT.

## تحديث تثبيت موجود

احتفظ بنسخة احتياطية من قاعدة البيانات. حدّث ملفات `app` والاختبارات من إصدار المستودع، مع إبقاء ملف البيئة وقاعدة البيانات، ثم:

```bash
sudo systemctl stop http-proxy-control
sudo cp -a /var/lib/http-proxy-control/proxy.db /var/lib/http-proxy-control/proxy.db.backup
# انقل ملفات مجلد app من الإصدار الجديد إلى /opt/http-proxy-control/app
sudo /opt/http-proxy-control/venv/bin/pip install -r /opt/http-proxy-control/requirements.txt
sudo systemctl start http-proxy-control
```

المنافذ التي كانت محفوظة على TLS لا تتحول تلقائيًا لأسباب أمنية؛ بدّلها من اللوحة بعد التحديث إذا كان عميلك يستخدم HTTP Proxy.

## إلغاء التثبيت

```bash
sudo systemctl disable --now http-proxy-control
sudo rm /etc/systemd/system/http-proxy-control.service
sudo systemctl daemon-reload
sudo rm -rf /opt/http-proxy-control /etc/http-proxy-control /etc/http-proxy-control.env
```

احتفظ بنسخة من `/var/lib/http-proxy-control` إذا أردت الاحتفاظ بقاعدة بياناتك، أو احذفها يدويًا إن لم تعد تحتاجها.

## الترخيص

MIT — راجع [LICENSE](LICENSE).
