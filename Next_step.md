# NGFW Manager — План разработки (Next Steps)

## Текущее состояние

| Функция | Статус |
|---|---|
| Login / Auth | ✅ Работает |
| Sync (pull rules + objects) | ✅ Работает |
| Virtual Folders (Security) | ✅ Работает |
| Создание Security Rule | ✅ Работает |
| Редактирование Security Rule | ✅ Работает (Блок 1) |
| L7 Applications в правиле | ✅ Работает (Блок 1) |
| URL Categories в правиле | ✅ Работает (Блок 1) |
| Source Users в правиле | ✅ Работает (Блок 1) |
| IPS / AV / ICAP профили в правиле | ✅ Работает (Блок 1) |
| Enable/Disable toggle (реальный) | ✅ Работает (Блок 1) |
| Копирование / перемещение правил | ✅ Работает |
| Change Tracking (внешние изменения) | ✅ Работает |
| NAT Rules (папки, sync, deploy) | ✅ Работает (Блок 2) |
| CRUD объектов | ✅ Работает (Блок 3) |
| Logs & Monitoring | ✅ Работает (Блок 4) |
| Decryption / Auth / PBR Rules | ✅ Работает (Блок 5) |
| Управление устройством | ✅ Работает (Блок 6) |

---

## БЛОК 1 — Полноценный редактор Security Rules

> Самое важное. Редактирование правил сейчас "coming soon".

### API endpoints
- `POST /api/v2/UpdateSecurityRule` — обновление любого поля правила
- `POST /api/v2/ListApplications` — список L7 приложений
- `POST /api/v2/ListURLCategories` — список URL категорий
- `POST /api/v2/ListUsers` — список пользователей
- `POST /api/v2/ListUserGroups` — список групп пользователей
- `POST /api/v2/ListIPSProfiles` — список IPS профилей
- `POST /api/v2/ListAntivirusProfiles` — список профилей антивируса
- `POST /api/v2/ListICAPProfiles` — список ICAP профилей

### Что реализовать

1. **Редактирование правила** — открыть модалку с заполненными полями по двойному клику на строку, отправить `UpdateSecurityRule`
2. **L7 Applications пикер** — ObjectPicker с `ListApplications` + новая колонка "Application" в таблице правил
3. **URL Categories пикер** — ObjectPicker с `ListURLCategories` + новая колонка "URL Cat" в таблице
4. **Source Users / UserGroups пикер** — ObjectPicker с `ListUsers` + `ListUserGroups`
5. **IPS / AV / ICAP профили** — дропдауны в редакторе правила (загружать при открытии модалки)
6. **Enable/Disable toggle** — реальный вызов `UpdateSecurityRule {enabled: bool}` по клику на свитч в таблице (сейчас кнопка декоративная)

### Изменения в БД / моделях
- Таблица `cached_rules` уже хранит `data` (JSON) — application, urlCategory, sourceUser уже там после Sync
- Добавить в `rule_to_dict()` поля: `application`, `url_category`, `source_user`
- Добавить в `_initPickers()` загрузку приложений и URL категорий
- Добавить в `CachedObject` категорию `app` и `urlcat` при Sync (уже частично есть)

### Изменения в sync_service
- Добавить синхронизацию Applications → `cached_objects` (category=`app`)
- Добавить синхронизацию URLCategories → `cached_objects` (category=`urlcat`)
- Добавить синхронизацию Users / UserGroups → `cached_objects` (category=`user`)

---

## БЛОК 2 — NAT Rules

> Отдельная полноценная вкладка, критически важна для администратора NGFW.

### API endpoints
- `POST /api/v2/ListNatRules` — список NAT правил
- `POST /api/v2/CreateNatRule` — создание NAT правила
- `POST /api/v2/DeleteNatRule` — удаление NAT правила
- `POST /api/v2/MoveNatRule` — перемещение правила (позиция)

### Структура NatRule (ключевые поля)
```
id, name, description, position, globalPosition, enabled
sourceZone, sourceAddr
destinationZone, destinationAddr
service
srcTranslationType: NONE | DYNAMIC_IP_PORT | STATIC_IP | STATIC_IP_PORT
srcTranslationAddrType: NONE | INTERFACE | TRANSLATED
srcTranslatedAddress: RuleFieldNetwork
srcTranslatedPort: PortType
dstTranslationType: NONE | ADDRESS_POOL
dstTranslatedAddress: RuleFieldNetwork
dstTranslatedPort: int (порт перенаправления)
```

### Что реализовать
1. Страница `/nat` — таблица NAT правил (src/dst зоны, адреса, тип трансляции)
2. Создание NAT правила — модалка с выбором типа SNAT/DNAT
3. Удаление NAT правил (bulk)
4. Drag-and-drop порядка через `MoveNatRule`
5. Виртуальные папки для NAT (наша фишка — расширить существующую систему)
6. Change Tracking для NAT правил (наша фишка)
7. Sync NAT правил — добавить в `SyncService`

### Новые модели БД
```python
class CachedNatRule(Base):
    __tablename__ = "cached_nat_rules"
    id = Column(String, primary_key=True)          # внутренний UUID
    ext_id = Column(String, unique=True)            # UUID на NGFW
    name = Column(String)
    folder_id = Column(String, ForeignKey("nat_folders.id"), nullable=True)
    folder_sort_order = Column(Integer, default=0)
    data = Column(JSON)
    is_modified = Column(Boolean, default=False)
    modified_at = Column(String, nullable=True)

class NatFolder(Base):
    __tablename__ = "nat_folders"
    id = Column(String, primary_key=True)
    name = Column(String)
    device_group_id = Column(String)
    sort_order = Column(Integer, default=0)
```

---

## БЛОК 3 — CRUD объектов ✅ ВЫПОЛНЕН

### Что реализовано
- **`ngfw_client.py`**: `delete_object()` с маппингом типов → API endpoint; `create_zone()`
- **`router.py`**: `POST /api/v1/objects/create` и `POST /api/v1/objects/delete`
- **`objects.html`**: полная переработка
  - Кнопка **Create** (только для поддерживаемых вкладок: Networks, Services, Zones)
  - Модалка с контекстными подтипами:
    - Networks → IP/Subnet / IP Range / FQDN / Group
    - Services → Service (TCP/UDP/ICMP + порты) / Service Group
    - Zones → просто имя
  - Чекбоксы на каждой строке + "Select All"
  - Bulk-bar с кнопкой **Delete from device**
  - Confirmation dialog перед удалением с превью имён

---

## БЛОК 4 — Logs & Monitoring

> Просмотр логов и статистики прямо в интерфейсе без выхода в СУ.

### API endpoints
- `POST /api/v2/TrafficLogsActivity` — логи трафика с фильтрацией
- `POST /api/v2/TrafficLogsMeta` — метаданные полей для построения фильтров
- `POST /api/v2/ListMetricsRulesStats` — счётчики срабатываний правил
- `POST /api/v2/IPSLogsActivity` — логи IPS
- `POST /api/v2/AntivirusLogsActivity` — логи антивируса
- `POST /api/v2/AuditLogsActivity` — аудит действий администраторов

### ✅ ВЫПОЛНЕНО
1. `app/templates/logs.html` — 4 вкладки (Traffic/IPS/AV/Audit), динамические колонки
2. Фильтры: Src IP, Dst IP, Dst Port, Action, период (1h/6h/24h/7d/custom)
3. Авто-обновление каждые 30 сек (toggleable)
4. Экспорт в CSV с BOM для Excel
5. Клик по строке → raw JSON modal
6. Load More пагинация
7. `app/infrastructure/ngfw_client.py` — `get_traffic_logs`, `get_ips_logs`, `get_av_logs`, `get_audit_logs`, `get_rule_stats`
8. `app/web/router.py` — `GET /logs`, `POST /api/v1/logs/query`, `GET /api/v1/logs/rule_stats`
9. Навигация "Logs" добавлена в боковой сайдбар (sidebar.html)

---

## БЛОК 5 — Дополнительные типы правил

> Полный цикл policy management.

### ✅ ВЫПОЛНЕНО
- Страница `/policy` — 3 вкладки: Decryption / Authentication / PBR
- `app/templates/policy.html` — таблица правил, модал создания, toggle enable/disable, bulk delete
- `app/infrastructure/ngfw_client.py` — generics `_list_rules`, `_create_rule_generic`, `_delete_rule_generic`, `_move_rule_generic`, `_toggle_rule_generic` + конкретные методы для каждого типа
- `app/web/router.py` — `GET /policy`, `POST /api/v1/policy/list`, `POST /api/v1/policy/create`, `POST /api/v1/policy/delete`, `POST /api/v1/policy/toggle`
- Навигация POL добавлена во все sidebar'ы (sidebar.html, logs.html, policy.html)
- ObjectPicker для src/dst адресов и сервисов

### Decryption Rules
- `ListDecryptionRules` / `CreateDecryptionRule` / `DeleteDecryptionRule` / `MoveDecryptionRule` / `UpdateDecryptionRule`
- Вкладка Decryption: Action = Decrypt / No Decrypt / Bypass; поля SSL Profile, Certificate Profile

### Authentication Rules
- `ListAuthenticationRules` / `CreateAuthenticationRule` / `DeleteAuthenticationRule` / `UpdateAuthenticationRule`

### PBR Rules (Policy-Based Routing)
- `ListPBRRules` / `CreatePBRRule` / `DeletePBRRule` / `GetPBRRule`

---

## БЛОК 6 — Управление устройством

> Инфраструктурные функции.

### ✅ ВЫПОЛНЕНО — страница `/system` с 5 вкладками

**Admins** (вкладка):
- Таблица: Login, Name, Role, Status (Active/Blocked)
- Create Admin modal, Block/Unblock, Delete, Change Password
- API: `GET /api/v1/system/admins`, `POST /api/v1/system/admins/create`, `POST .../action`, `POST .../password`

**Backup & Snapshot** (вкладка):
- Список бэкапов: Name, Date, Size + кнопка Create Backup (с описанием)
- Список снапшотов + кнопка Take Snapshot (CommitSnapshot)
- API: `GET /api/v1/system/backups`, `POST .../create`, `POST .../delete`, `POST .../snapshots/commit`

**Routing** (вкладка):
- Static Routes: таблица Dest/GW/Interface/Metric + Add Route modal + Delete
- BGP info card: local ASN, peers table (Neighbor/RemoteASN/State)
- OSPF info card: Router ID, Areas table — оба read-only
- API: `GET /api/v1/system/routing`, `POST .../create`, `POST .../delete`

**Interfaces** (вкладка):
- Объединённая таблица Virtual + Logical interfaces (Name/Type/IP/Status/Desc) — read-only
- API: `GET /api/v1/system/interfaces` (параллельный запрос обоих списков)

**Settings** (вкладка):
- Форма Session Timeouts: TCP/UDP/ICMP/TCP-HalfOpen/TCP-TimeWait/UDP-Stream
- API: `GET /api/v1/system/timeouts`, `POST /api/v1/system/timeouts/set`

**ngfw_client.py** — 23 новых метода (admins/backup/snapshot/routes/bgp/ospf/interfaces/timeouts)
**Навигация** — вкладка SYS добавлена во все сайдбары

---

## Наши уникальные фишки (развивать параллельно)

| Фишка | Текущий статус | Развитие |
|---|---|---|
| Виртуальные папки | Security Rules | Расширить на NAT / Decryption / Auth Rules |
| Change Tracking | Security Rules | Расширить на NAT правила |
| Inter-device Transfer | Только в рамках одной СУ | Поддержка переноса между разными СУ (два клиента параллельно) |
| Object Mapping Table | Нет | Таблица `source_uuid → target_uuid` — избегать дублей при повторных копированиях |
| Bulk операции | Delete, Transfer, Move | Добавить Bulk Enable/Disable, Bulk Clone |

---

## Приоритет (рекомендуемый порядок)

```
1. БЛОК 1  — Редактор Security Rules + L7/URL/Users    ✅ ВЫПОЛНЕН
2. БЛОК 2  — NAT Rules                                  ✅ ВЫПОЛНЕН
3. БЛОК 3  — CRUD объектов                             ✅ ВЫПОЛНЕН
4. БЛОК 4  — Logs & Monitoring                         ✅ ВЫПОЛНЕН
5. БЛОК 5  — Decryption / Auth / PBR Rules             ✅ ВЫПОЛНЕН
6. БЛОК 6  — Управление устройством                   ✅ ВЫПОЛНЕН
```

---

## Файлы которые затронут изменения

```
БЛОК 1:
  app/infrastructure/ngfw_client.py     ← добавить update_rule(), get_applications(), get_url_categories()
  app/services/sync_service.py          ← sync Applications, URLCategories, Users
  app/services/rule_creator.py          ← поддержка app_ids, url_ids, user_ids в create
  app/web/router.py                     ← endpoint PUT/PATCH rule, объекты app/urlcat/user
  app/templates/index.html              ← редактор правила, 2 новые колонки, реальный toggle
  app/static/js/picker.js               ← без изменений (ObjectPicker универсален)

БЛОК 2:
  app/db/models.py                      ← CachedNatRule, NatFolder
  app/infrastructure/ngfw_client.py     ← методы NAT
  app/services/sync_service.py          ← sync NAT rules
  app/services/nat_service.py           ← новый файл
  app/web/router.py                     ← /nat routes
  app/templates/nat.html                ← новый файл

БЛОК 3:
  app/infrastructure/ngfw_client.py     ← delete методы для объектов
  app/web/router.py                     ← CRUD endpoints для объектов
  app/templates/objects.html            ← кнопки Create/Delete

БЛОК 4:
  app/infrastructure/ngfw_client.py     ← методы для логов
  app/web/router.py                     ← /logs routes
  app/templates/logs.html               ← новый файл

БЛОК 5:
  app/infrastructure/ngfw_client.py     ← методы Decryption/Auth/PBR
  app/web/router.py                     ← routes
  app/templates/decryption.html         ← новый файл
  app/templates/auth_rules.html         ← новый файл

БЛОК 6:
  app/infrastructure/ngfw_client.py     ← методы admin/backup/routing
  app/web/router.py                     ← routes
  app/templates/admins.html             ← новый файл
  app/templates/backups.html            ← новый файл
  app/templates/routing.html            ← новый файл
```
