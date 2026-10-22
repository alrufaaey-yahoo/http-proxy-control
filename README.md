# HTTP Proxy Control

لوحة تحكم ذاتية الاستضافة لإدارة منافذ **HTTP proxy** ودعم **HTTPS عبر CONNECT** على خادم Ubuntu/Debian. لكل مستمع اسم مستخدم وكلمة مرور منفصلان، ويمكن تشغيل الاتصال إلى الوكيل عبر TLS أو HTTP (الخيار الآمن الافتراضي هو TLS).

> **تنبيه:** هذا مستودع برمجي ومُثبت؛ لا أملك بيانات VPS الخاصة بك، لذلك لم يُنفّذ التثبيت على خادم حقيقي. بعد رفع المشروع، شغّل المُثبت على VPS كما هو موضح أدناه.

## الميزات

- لوحة عربية RTL لتسجيل الدخول، وإنشاء المستمعات وتشغيلها وإيقافها وتغيير بيانات اعتمادها أو حذفها.
- منفذ لوحة تختاره وقت التثبيت، واسم مستخدم وكلمة مرور مدير تُطلب تفاعليًا.
- كل مستمع Proxy يُربط على `0.0.0.0` بمنفذ تختاره، مع بيانات اعتماد خاصة به.
- TLS اختياري لكل منفذ Proxy، ومفعّل افتراضيًا لحماية بيانات Basic Authentication. يدعم المستمع طلبات HTTP الاعتيادية وHTTPS CONNECT.
- تجزئة كلمات المرور بخوارزمية scrypt، جلسات لوحة موقعة، تقييد محاولات الدخول، وفحص Origin لطلبات التعديل.
- حظر DNS إلى عناوين loopback والشبكات الخاصة وlink-local وmetadata والعناوين غير العامة، بما يشمل ردود DNS المختلطة.
- خدمة systemd تعمل بمستخدم محدود الصلاحيات، مع إعدادات تقوية أساسية. لا يفتح المُثبت منافذ جدار الحماية تلقائيًا.

## التثبيت على VPS

يدعم Ubuntu وDebian مع صلاحية `sudo`. سجّل الدخول إلى الخادم عبر SSH، ثم شغّل:

```bash
curl -fsSL https://raw.githubusercontent.com/alrufaaey-yahoo/http-proxy-control/main/install.sh -o install.sh
sudo bash install.sh
```

سيطلب المُثبت منفذ لوحة التحكم (الافتراضي `8443`)، اسم مستخدم المدير، وكلمة مرور لا تقل عن 16 محرفًا. يُنشئ شهادة TLS ذاتية التوقيع صالحة 10 سنوات، ويجهز بيئة Python افتراضية وخدمة systemd. لا تُكتب كلمة مرور المدير بنص صريح؛ تحفظ مشتقةً بـ scrypt.

بعد التثبيت:

1. افتح **TCP لمنفذ لوحة التحكم** في جدار حماية مزود الـVPS، وفي UFW إن كان مستخدمًا، مثلًا: `sudo ufw allow 8443/tcp` (استبدل الرقم بما اخترته). لا تفتح سوى المنافذ التي تحتاجها.
2. افتح `https://عنوان-الخادم:منفذ-اللوحة` وسجّل دخولك. الشهادة الابتدائية ذاتية التوقيع؛ الأفضل استبدالها بشهادة موثوقة قبل استخدام اللوحة عبر الإنترنت.
3. أنشئ مستمعًا: اختر المنفذ، اسم المستخدم، وكلمة مرور لا تقل عن 12 محرفًا. اترك TLS مفعّلًا للاتصال العام.
4. اسمح بمنفذ المستمع في مزود الخادم وUFW عند الحاجة، مثلًا `sudo ufw allow 18080/tcp`، بعد استبدال الرقم بالمنفذ المختار.

لفحص الخدمة والسجلات:

```bash
sudo systemctl status http-proxy-control
sudo journalctl -u http-proxy-control -f
```

### شهادة TLS موثوقة

الشهادة الافتراضية مخصصة لبدء الخدمة وليست موثوقة من المتصفحات أو العملاء، كما أن اسمها لا يطابق عنوان IP العام. لا تتجاوز تحذير الشهادة على شبكة غير موثوقة. للاستخدام الفعلي، استبدلها بشهادة صادرة لاسم نطاقك (ويجب أن يستخدم العملاء ذلك النطاق) مع المحافظة على مسارات البيئة التي تشير إلى:

```text
/etc/http-proxy-control/tls.crt
/etc/http-proxy-control/tls.key
```

مثلًا بعد إصدار شهادة مناسبة، انسخ `fullchain.pem` إلى `tls.crt` و`privkey.pem` إلى `tls.key`، ثم:

```bash
sudo chown root:proxyctl /etc/http-proxy-control/tls.crt /etc/http-proxy-control/tls.key
sudo chmod 0640 /etc/http-proxy-control/tls.crt /etc/http-proxy-control/tls.key
sudo systemctl restart http-proxy-control
```

تأكد أن الشهادة تتضمن اسم النطاق المستخدم للوصول إلى اللوحة وإلى مستمعات TLS، وجدّدها قبل الانتهاء. يمكن استخدام الشهادة نفسها للوحة ولمستمعات الوكيل.

## استخدام الوكيل

استبدل `proxy.example.com` والمنفذ وبيانات الدخول بقيمك. مثال `curl` مع مستمع TLS:

```bash
curl --proxy https://USER:PASSWORD@proxy.example.com:18080 \
     --proxy-cacert /path/to/trusted-proxy-ca.pem \
     https://example.com/
```

يُستخدم الوكيل لطلبات HTTP المعتادة، وتُمرر اتصالات HTTPS عبر CONNECT. يدعم `curl` إشارة `--proxy-insecure` للاختبار فقط مع الشهادة الذاتية التوقيع؛ لا تستخدمها كإعداد دائم على الإنترنت، ولا تضع كلمات المرور في سجلات طرفية مشتركة.

إذا عطّلت TLS لمستمع ما، يكون عنوانه `http://`، مثل:

```bash
curl --proxy http://USER:PASSWORD@proxy.example.com:18081 http://example.com/
```

**لا تستخدم مستمع HTTP غير المشفر عبر الإنترنت العام:** مصادقة Basic ترسل كلمة المرور دون تشفير. استعمله فقط داخل شبكة خاصة موثوقة أو نفق مشفر.

## إعدادات الخدمة

- ملف البيئة: `/etc/http-proxy-control.env` (مملوك لـroot ومقروء لمجموعة الخدمة فقط).
- قاعدة البيانات: `/var/lib/http-proxy-control/proxy.db` (كلمات مرور الوكلاء مخزنة كـscrypt hashes).
- التطبيق: `/opt/http-proxy-control`.
- اسم الخدمة: `http-proxy-control.service`.
- منافذ لوحة التحكم والوكلاء تستمع على كل واجهات IPv4؛ راجع جدار الحماية الخارجي لخادمك.

لا يوجد خيار لعرض كلمات مرور الوكلاء بعد إنشائها؛ غيّر بياناتها من اللوحة عند الحاجة. لا ينفذ البرنامج إعادة توجيه لتسجيلات الدخول، ولا يعيد استخدام بيانات اعتماد الإدارة لمنافذ الوكيل.

## الأمان والحدود

- جميع المستمعات تتطلب مصادقة؛ لا توجد منافذ Proxy مجهولة.
- عند تفعيل TLS (الموصى به)، تستخدم مستمعات الوكيل الشهادة المعرفة في ملف البيئة؛ تحقق من الشهادة في العميل. TLS لا يجعل مشاركة الوكيل العامة بلا مخاطر.
- يُحظر توجيه الطلبات إلى عناوين IP غير عامة بعد حل DNS. هذا يحد من الوصول إلى الشبكات الداخلية، لكنه ليس سياسة وجهات شاملة ولا يمنع إساءة الاستخدام أو استهلاك النطاق الترددي.
- الخدمة لا تنفذ تحديدًا لمعدل النقل، أو حصص استخدام، أو قوائم سماح للمضيفين؛ لا تشغّلها كمورد مفتوح للجمهور. قيّد الوصول في جدار الحماية وشارك بيانات الدخول مع أشخاص موثوقين فقط.
- حدود طلبات HTTP: رؤوس حتى 64 KiB، وجسم حتى 64 MiB، ومهلة خمول للاتصال حتى 120 ثانية.
- لا يوجد دعم لـSOCKS، HTTP/2، أو تحويل تلقائي للوكيل إلى TLS عند تعطيل TLS على المستمع.

## التطوير والاختبارات

يتطلب Python 3.10 أو أحدث:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## تحديث يدوي

احتفظ بنسخة احتياطية من قاعدة البيانات أولًا، ثم حمّل نسخة جديدة من الشيفرة، حدّث الاعتماديات، وأعد تشغيل الخدمة. لا تستبدل `/var/lib/http-proxy-control/proxy.db` أو `/etc/http-proxy-control.env`:

```bash
sudo systemctl stop http-proxy-control
sudo cp -a /var/lib/http-proxy-control/proxy.db /var/lib/http-proxy-control/proxy.db.backup
# حدّث ملفات التطبيق في /opt/http-proxy-control مع إبقاء venv وملف البيئة وقاعدة البيانات.
sudo /opt/http-proxy-control/venv/bin/pip install -r /opt/http-proxy-control/requirements.txt
sudo systemctl start http-proxy-control
```

## إلغاء التثبيت

لإيقاف الخدمة وإزالة ملفات التطبيق والإعدادات (مع الاحتفاظ بقاعدة البيانات إن رغبت):

```bash
sudo systemctl disable --now http-proxy-control
sudo rm /etc/systemd/system/http-proxy-control.service
sudo systemctl daemon-reload
sudo rm -rf /opt/http-proxy-control /etc/http-proxy-control /etc/http-proxy-control.env
```

احتفظ بنسخة آمنة من `/var/lib/http-proxy-control` أو احذفها يدويًا إذا لم تعد تحتاج إعداداتك.

## الترخيص

MIT — راجع [LICENSE](LICENSE).
