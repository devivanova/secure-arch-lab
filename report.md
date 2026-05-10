# report.md

## Архітектурне ревʼю шаблону системи

## Мета

Мета цього звіту — провести архітектурне ревʼю шаблону системи та визначити, чи підтримує він автоматизовані перевірки безпеки.  
Основна увага приділяється наявності архітектурних сигналів, security gates, контрольованості, принципу мінімальних привілеїв та можливості перевірки шаблону через CI/CD, SAST, DAST, IaC та supply chain інструменти.

## Чеклист архітектурних сигналів

| 🔦 Сигнал                               | Є / Немає   | Коментар                                                |
| --------------------------------------- | ----------- | ------------------------------------------------------- |
| OpenAPI / `response_model`              | ❌ Немає    | У `main.py` немає явного API-контракту                  |
| Типізація даних / Pydantic              | ❌ Немає    | Вхідні та вихідні дані не описані через схеми           |
| Secrets через Vault / CSI               | ❌ Немає    | Секрети передаються через `envFrom secretRef`           |
| CI перевірки / Semgrep, Trivy, gitleaks | ❌ Немає    | CI тільки збирає Docker image                           |
| SBOM                                    | ❌ Немає    | Немає генерації software bill of materials              |
| IaC контроль                            | ⚠️ Частково | Є Terraform, але Security Group відкрита на `0.0.0.0/0` |
| OPA / policy-as-code                    | ❌ Немає    | Немає політик, які блокують небезпечні конфігурації     |
| Мінімальні привілеї                     | ❌ Немає    | Контейнер не налаштований на запуск від non-root user   |
| Immutable image tag / digest            | ❌ Немає    | Використовується `user-api:latest`                      |
| Підпис артефактів                       | ❌ Немає    | Немає підпису Docker image через cosign                 |

### Проблема №1: Відсутність типізації та API-контракту

**Файл:** `main.py`

```python
@app.get("/user")
def get_user():
    return {"id": 1, "name": "Alice"}
```

**Опис проблеми:**  
У файлі `main.py` відсутні Pydantic-схеми, типізація даних та параметр `response_model`. API повертає словник напряму, без формального опису структури відповіді.

**Який сигнал або перевірка відсутні:**  
Відсутній сигнал для OpenAPI, DAST, fuzzing та schema validation. Інструменти перевірки не можуть точно зрозуміти, які поля має повертати API, які типи даних очікуються та що саме потрібно перевіряти.

**Порушений принцип або патерн:**  
Порушено патерн **OpenAPI 3.0 контракт + типізовані моделі**. Також порушено принцип контрольованості, тому що API не створює достатньо сигналів для автоматичної перевірки.

**Архітектурне виправлення:**  
Потрібно описати модель відповіді через Pydantic та підключити її до endpoint через `response_model`.

```python
from fastapi import FastAPI
from pydantic import BaseModel
from uuid import UUID

app = FastAPI()

class User(BaseModel):
    id: UUID
    name: str

@app.get("/user", response_model=User)
def get_user():
    return User(id="550e8400-e29b-41d4-a716-446655440000", name="Alice")
```

**Очікуваний результат:**  
Після виправлення FastAPI автоматично згенерує OpenAPI-схему. Це дасть сигнал для DAST, schema validation, fuzzing та інших інструментів перевірки.

### Проблема №2: Захардкоджений пароль у коді

**Файл:** `main.py`

```python
password = "secret"
```

**Опис проблеми:**  
У коді присутній пароль `"secret"`, який зберігається прямо у файлі застосунку. Це є небезпечним анти-патерном, оскільки секрет може потрапити в git-репозиторій, Docker image, CI/CD logs або бути прочитаним будь-ким, хто має доступ до коду.

**Який сигнал або перевірка відсутні:**  
Відсутній сигнал secret management. Також відсутній контроль, який би зупиняв потрапляння секретів у код, наприклад `gitleaks` або `trufflehog` у CI/CD.

**Порушений принцип або патерн:**  
Порушено патерн **Vault CSI для зберігання секретів**. Також порушено принципи **PoLP** та **secure configuration**, оскільки секрет не ізольований від коду.

**Архітектурне виправлення:**  
Секрети потрібно зберігати не в коді, а в окремому secret storage, наприклад HashiCorp Vault. У Kubernetes їх можна передавати через Vault CSI driver як примонтований файл.

```yaml
volumes:
  - name: vault-secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: vault-db-creds
```

```yaml
volumeMounts:
  - name: vault-secrets
    mountPath: "/mnt/secrets-store"
    readOnly: true
```

**Очікуваний результат:**  
Секрет більше не буде зберігатися в коді, git або Docker image. Доступ до нього буде контрольований через Vault, а CI/CD зможе перевіряти, що секрети не передаються небезпечним способом.

### Проблема №3: Секрети передаються через `envFrom secretRef`, без Vault CSI

**Файл:** `deployment.yaml`

```yaml
envFrom:
  - secretRef:
      name: app-secret
```

**Опис проблеми:**  
У `deployment.yaml` секрети передаються в контейнер через environment variables за допомогою `envFrom secretRef`. Такий підхід менш контрольований, тому що змінні середовища можуть потрапити в logs, crash dumps, debug output або бути прочитані процесами всередині контейнера.

**Який сигнал або перевірка відсутні:**  
Відсутній сигнал, що секрети передаються через централізований і контрольований механізм. OPA або conftest не мають позитивного патерну Vault CSI, який можна перевірити як обов’язкову вимогу.

**Порушений принцип або патерн:**  
Порушено патерн **Vault CSI для зберігання секретів**. Також порушено принцип контрольованої доставки секретів.

**Архітектурне виправлення:**  
Замість `envFrom secretRef` потрібно використовувати Vault CSI driver та монтувати секрети як read-only volume.

```yaml
volumes:
  - name: vault-secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: vault-db-creds

containers:
  - name: app
    image: user-api:v1.0.0
    volumeMounts:
      - name: vault-secrets
        mountPath: "/mnt/secrets-store"
        readOnly: true
```

**Очікуваний результат:**  
Секрети не передаються через env, а доступ до них відбувається через контрольований runtime-механізм. Це створює архітектурний сигнал для перевірки: якщо використовується `envFrom secretRef`, policy gate може зупинити збірку або деплой.

### Проблема №4: CI тільки збирає Docker image, але не виконує security checks

**Файл:** `ci.yml`

```yaml
- name: Build Docker image
  run: docker build -t user-api .
```

**Опис проблеми:**  
CI/CD pipeline виконує тільки збірку Docker image. У ньому немає перевірок безпеки, таких як Semgrep, Trivy, gitleaks, генерація SBOM або перевірка контейнера на вразливості.

**Який сигнал або перевірка відсутні:**  
Відсутні сигнали SAST, secret scanning, dependency scanning, container scanning та supply chain контролю. Через це небезпечний код або небезпечний образ може пройти pipeline без блокування.

**Порушений принцип або патерн:**  
Порушено патерн **CI/CD security gates**. Також порушено принцип **Shift Left Security**, тому що перевірки не виконуються на ранньому етапі розробки.

**Архітектурне виправлення:**  
Потрібно додати в CI/CD окремі security jobs: Semgrep для SAST, gitleaks для пошуку секретів, Trivy для перевірки image та syft для створення SBOM.

```yaml
- name: Run Semgrep
  run: semgrep --config auto .

- name: Run gitleaks
  run: gitleaks detect --source .

- name: Build Docker image
  run: docker build -t user-api:v1.0.0 .

- name: Scan image with Trivy
  run: trivy image user-api:v1.0.0

- name: Generate SBOM
  run: syft user-api:v1.0.0 -o json > sbom.json
```

**Очікуваний результат:**  
CI/CD стане security gate. Якщо в коді є секрет, небезпечна залежність, вразливий образ або порушення політик, pipeline зупинить збірку.

### Проблема №5: Security Group відкрита на `0.0.0.0/0`

**Файл:** `main.tf`

```hcl
cidr_blocks = ["0.0.0.0/0"]
```

**Опис проблеми:**  
У Terraform-конфігурації Security Group дозволяє доступ з будь-якої IP-адреси. Це створює зайву поверхню атаки, тому що сервіс може бути доступним для всього інтернету.

**Який сигнал або перевірка відсутні:**  
Відсутній IaC security gate, який би перевіряв Terraform-файли та блокував небезпечні мережеві правила. Наприклад, немає `tfsec`, `checkov` або OPA-політики для заборони `0.0.0.0/0`.

**Порушений принцип або патерн:**  
Порушено принцип **PoLP** і патерн **IaC як єдине довірене джерело конфігурації**. Також порушено принцип мінімальної експозиції сервісу.

**Архітектурне виправлення:**  
Потрібно обмежити доступ тільки дозволеним CIDR, наприклад внутрішньою мережею або адресами load balancer / VPN.

```hcl
resource "aws_security_group" "api" {
  name = "api-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

Також потрібно додати перевірку Terraform у CI/CD.

```yaml
- name: Run tfsec
  run: tfsec .
```

**Очікуваний результат:**  
Доступ до сервісу буде обмежений, а небезпечні зміни в Terraform будуть автоматично виявлятися до деплою.

### Проблема №6: Dockerfile не фіксує версії, не використовує non-root user, не має SBOM/підпису

**Файл:** `Dockerfile`

```dockerfile
FROM python:3.11
```

**Опис проблеми:**  
Dockerfile не містить достатніх security controls. Базовий образ не зафіксований через digest, не створюється окремий non-root user, а також немає процесу генерації SBOM і підпису образу.

**Який сигнал або перевірка відсутні:**  
Відсутні сигнали container hardening та supply chain security. Немає гарантії, що образ є незмінним, перевіреним і створеним із контрольованої бази.

**Порушений принцип або патерн:**  
Порушено принцип **мінімальних привілеїв** та патерни **SBOM + підпис артефактів**. Також порушено принцип reproducible builds, тому що образ не прив’язаний до digest.

**Архітектурне виправлення:**  
Потрібно використовувати конкретну версію або digest базового образу, створити non-root user, а в CI/CD додати SBOM та підпис через cosign.

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser
USER appuser

CMD ["python", "main.py"]
```

Приклад CI/CD для SBOM та підпису:

```yaml
- name: Generate SBOM
  run: syft user-api:v1.0.0 -o json > sbom.json

- name: Sign image
  run: cosign sign user-api:v1.0.0
```

**Очікуваний результат:**  
Контейнер буде запускатися з мінімальними привілеями. Образ стане більш контрольованим, а SBOM і підпис дозволять перевіряти походження та склад артефакту.

### Проблема №7: Використання образу `user-api:latest`

**Файл:** `deployment.yaml`

```yaml
image: user-api:latest
```

**Опис проблеми:**  
У Kubernetes deployment використовується Docker image з тегом `latest`. Це небезпечно, тому що такий тег не гарантує незмінність образу. Сьогодні `latest` може вказувати на один образ, а завтра — на інший.

**Який сигнал або перевірка відсутні:**  
Відсутній сигнал immutable artifact. Неможливо точно перевірити, яка саме версія була задеплоєна, який SBOM до неї належить і чи був цей образ підписаний.

**Порушений принцип або патерн:**  
Порушено патерн **immutable tag / digest** та принцип supply chain transparency.

**Архітектурне виправлення:**  
Потрібно використовувати versioned tag або digest.

```yaml
image: user-api:v1.0.0
```

Або ще краще:

```yaml
image: user-api@sha256:abc123456789
```

Також можна додати OPA-політику, яка забороняє використання `latest`.

```rego
package deployment.security

deny[msg] {
  container := input.spec.containers[_]
  endswith(container.image, ":latest")
  msg := "Використання latest tag заборонене"
}
```

**Очікуваний результат:**  
Деплой стане відтворюваним і контрольованим. Буде зрозуміло, який саме образ використовується, чи він перевірений, чи має SBOM і підпис.

## Підсумок ревʼю

Під час архітектурного ревʼю було виявлено 7 важливих порушень контрольованості та перевіряльності системи.

Основні проблеми:

1. У `main.py` немає типізації, Pydantic-схем і `response_model`.
2. У `main.py` секрет `"secret"` захардкоджений у коді.
3. У `deployment.yaml` секрети передаються через `envFrom secretRef`, без Vault CSI.
4. У `ci.yml` немає security checks: Semgrep, Trivy, gitleaks, SBOM.
5. У `main.tf` Security Group відкрита на `0.0.0.0/0`.
6. У `Dockerfile` немає достатнього container hardening, non-root user, SBOM і підпису.
7. У `deployment.yaml` використовується образ `user-api:latest`.

Головний висновок: система має слабку контрольованість, тому що багато важливих елементів не створюють сигналів для автоматичної перевірки. Архітектура не повинна просто працювати — вона має дозволяти перевіряти себе через гейти, політики, типізацію, контракти, IaC та supply chain controls.

## Рекомендовані патерни для виправлення

| Проблема | Рекомендований патерн |
| Немає API-контракту | OpenAPI 3.0 + `response_model` |
| Немає типізації | Pydantic / DTO |
| Секрет у коді | Vault CSI / external secret storage |
| Секрети через env | Mounted secrets через CSI |
| Немає CI security checks | Semgrep + gitleaks + Trivy |
| Немає SBOM | syft / trivy sbom |
| Security Group `0.0.0.0/0` | IaC policy gate / tfsec |
| Контейнер без non-root user | Kubernetes securityContext / Docker USER |
| Image `latest` | Immutable tag або digest |
| Немає підпису образу | cosign |

## Висновок

Запропоновані виправлення дозволяють зробити шаблон системи контрольованим і перевіряльним.  
Після впровадження патернів архітектура буде подавати сигнали для CI/CD, SAST, DAST, IaC scanning, secret scanning та supply chain контролю.
Це зменшить ризик непомічених помилок і зробить систему більш безпечною ще до етапу деплою.
