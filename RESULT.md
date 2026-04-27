# NGFW Manager — Результат разработки

> Веб-интерфейс поверх корпоративного NGFW (gRPC-gateway REST API).
> Стек: **FastAPI + Jinja2 + SQLAlchemy async + PostgreSQL + Bootstrap 5**.
> Деплой: Docker Compose, volume-mount `./app`.

---

## Общая статистика

| Метрика | Значение |
|---|---|
| Страниц (HTML шаблонов) | 12 |
| API эндпоинтов (router.py) | 51 |
| Методов NGFW-клиента | 76 |
| JS-библиотек (custom) | 1 (picker.js) |
| Блоков реализовано | 6 из 6 |

---

## Навигация (единый сайдбар)

Все страницы объединены единой навигационной панелью в боковом меню:

```
[SEC] [NAT] [OBJ] [LOG] [POL] [SYS]
```

| Аббревиатура | URL | Назначение |
|---|---|---|
| SEC | `/` | Правила безопасности |
| NAT | `/nat` | NAT правила |
| OBJ | `/objects` | Объекты (сети, сервисы, зоны) |
| LOG | `/logs` | Логи и мониторинг |
| POL | `/policy` | Policy Rules (Decryption/Auth/PBR) |
| SYS | `/system` | Управление устройством |

---

## Блок 1 — Security Rules (Редактор правил безопасности)

**URL:** `/`

### Что умеет

- **Список правил** по виртуальным папкам с drag-and-drop изменением порядка (Sortable.js)
- **Создание/редактирование правила** через модальное окно:
  - Источник/назначение: зоны, сетевые объекты (ObjectPicker)
  - Сервисы (ObjectPicker с тегом svc-t)
  - Приложения L7 (ObjectPicker)
  - Пользователи и группы (ObjectPicker)
  - Действие: Allow / Deny / Drop
  - **IPS-профиль** (подбор из списка NGFW)
  - **Antivirus-профиль** (подбор из списка NGFW)
  - **ICAP-профиль** (подбор из списка NGFW)
  - URL-категории (ObjectPicker)
  - Комментарий
- **Включение/выключение** правила (toggle прямо в таблице)
- **Удаление** одного или нескольких правил (bulk delete с подтверждением)
- **Перемещение между папками** (bulk move modal)
- **Перенос правил между устройствами** (Transfer) — копирует правило на другой device_group
- **Change Tracking** — визуальная метка на правилах, изменённых вне нашего интерфейса (внешние изменения)
- **Sync** — загрузка актуальных правил с NGFW в локальный кэш (PostgreSQL)
- **Deploy** — отправка изменений на NGFW с расстановкой правил по позициям согласно порядку папок
- **Виртуальные папки** — секции Pre / Default / Post, произвольный порядок правил внутри

### Уникальные фишки

- Папки существуют только в нашей БД (NGFW не знает про папки)
- При Deploy система вычисляет финальный порядок и вызывает `MoveSecurityRule` для каждого правила
- Change Tracking: при Sync сравниваем хэш данных правила — если изменилось извне, показываем badge "изменено"

---

## Блок 2 — NAT Rules

**URL:** `/nat`

### Что умеет

- **Список NAT правил** с той же папочной системой (Pre/Default/Post), что и Security Rules
- **Создание NAT правила** через модал:
  - Src/Dst Zone, Source/Destination address (ObjectPicker)
  - Service (ObjectPicker)
  - **SNAT**: NONE / DYNAMIC_IP_PORT (PAT) / STATIC_IP / STATIC_IP_PORT
  - **DNAT**: NONE / ADDRESS_POOL
  - IP пул / статический IP для трансляции
- **Включение/выключение** правила (toggle)
- **Удаление** одного или нескольких (bulk delete)
- **Drag-and-drop** изменение порядка внутри папки
- **Sync** — загрузка NAT правил с NGFW
- **Deploy** — расстановка NAT правил по позициям (аналогично Security Rules)
- **Создание папок** для NAT (отдельное дерево от Security)

---

## Блок 3 — CRUD Объектов

**URL:** `/objects`

### Типы объектов

| Тип | Описание |
|---|---|
| Host/Network (`net_ip`) | IP-адрес или подсеть CIDR |
| IP Range (`net_range`) | Диапазон `x.x.x.x–y.y.y.y` |
| FQDN (`net_fqdn`) | Доменное имя |
| Network Group (`net_group`) | Группа сетевых объектов |
| Service (`service`) | TCP/UDP/ICMP сервис с портами |
| Service Group (`service_group`) | Группа сервисов |
| Security Zone (`zone`) | Зона безопасности |

### Что умеет

- **Просмотр** объектов с пагинацией (150 на странице), фильтрация по типу
- **Создание** объекта через модал (тип определяет набор полей)
- **Bulk Delete** — выбор нескольких объектов и удаление с подтверждением
- **ObjectPicker** для Group и Service Group — выбор членов группы

### Inline создание объектов

При создании Security или NAT правила, если нужного объекта нет в списке, прямо из поля поиска ObjectPicker:
- Появляется вариант **"Create '...'"** в dropdown
- Открывается Quick Create модал с **умным определением типа**:
  - `10.0.0.1` или `10.0.0.0/24` → `net_ip`
  - `10.0.0.1-10.0.0.10` → `net_range`
  - `corp.local` → `net_fqdn`
  - `80` или `tcp/443` → `service`
- Созданный объект сразу добавляется в picker как выбранный тег

---

## Блок 4 — Logs & Monitoring

**URL:** `/logs`

### Архитектура хранения логов

Логи **кэшируются в PostgreSQL** (`cached_logs` таблица) — не выгружаются все сразу из NGFW.

```
Пользователь → Fetch → NGFW API (paginated, max N записей) → cached_logs → Просмотр/Фильтр/Экспорт
```

**Автоочистка**: фоновый процесс (`asyncio.create_task`) удаляет записи старше **1 часа** каждые 10 минут.

### Лимиты по периоду

| Период | Макс. записей | Предупреждение |
|---|---|---|
| 1 час (по умолчанию) | 2 000 | нет |
| 6 часов | 5 000 | нет |
| 24 часа | 10 000 | ⚠ Confirm-диалог |

### Вкладки логов

| Вкладка | NGFW API | Колонки |
|---|---|---|
| Traffic | `TrafficLogsActivity` | Time, Src IP, Src Port, Dst IP, Dst Port, Proto, App, Action, Rule, Bytes |
| IPS | `IPSLogsActivity` | Time, Src IP, Src Port, Dst IP, Dst Port, Signature, Severity, Action, Proto |
| Antivirus | `AntivirusLogsActivity` | Time, Src IP, Dst IP, Threat, File, Action |
| Audit | `AuditLogsActivity` | Time, Admin, Action, Object Type, Object, Result, Details |

### Фильтрация (два уровня)

**При Fetch (на стороне NGFW):** Src IP, Dst IP, Dst Port, Action — NGFW возвращает только нужные записи.

**При просмотре (SQL по кэшу):** те же поля + диапазон времени `from/to` — SQL-фильтрация по индексированным колонкам.

### API эндпоинты

| Метод | URL | Назначение |
|---|---|---|
| `POST` | `/api/v1/logs/fetch` | Скачать из NGFW → сохранить в кэш |
| `POST` | `/api/v1/logs/query` | Получить из кэша с SQL-фильтрами |
| `GET`  | `/api/v1/logs/status` | Статус кэша (count, fetched_at, purge_in_sec) |
| `POST` | `/api/v1/logs/clear` | Ручная очистка кэша (по device+type) |
| `GET`  | `/api/v1/logs/export` | Streaming CSV из кэша с фильтрами |

### Дополнительные возможности

- **Статус-бар**: количество записей, время загрузки, «Auto-purge in Xm» (красный если < 5 мин)
- **Load More** — подгружает следующие 100 из кэша (SQL OFFSET)
- **CSV экспорт server-side** — `StreamingResponse`, BOM для Excel, колонки по типу лога
- **Raw JSON** — клик по строке открывает тёмный модал с полным JSON записи
- **Форматирование**: цветные badge для Action, Severity, Result; bytes → KB/MB; proto → TCP/UDP/ICMP
- **Обновление статуса** каждые 60 секунд без перезагрузки страницы

### DB модель `CachedLog`

```python
id              BigInteger PK autoincrement
device_group_id String(128) indexed
log_type        String(32)          # traffic/ips/av/audit
event_time      DateTime(tz) indexed
src_ip          String(64)  indexed
dst_ip          String(64)  indexed
dst_port        Integer
action          String(64)  indexed
data            JSON        # полный оригинальный объект из NGFW
fetched_at      DateTime(tz) indexed  # момент загрузки, основа TTL
```

---

## Блок 5 — Policy Rules (Decryption / Auth / PBR)

**URL:** `/policy`

### Три вкладки

#### Decryption Rules
- Таблица: Name, Src Zone, Source, Dst Zone, Destination, Service, Action, SSL Profile, Status
- **Actions**: Decrypt / No Decrypt / Bypass
- Создание: Name, зоны, адреса, сервисы, action, SSL Profile, Certificate Profile
- NGFW API: `ListDecryptionRules` / `CreateDecryptionRule` / `DeleteDecryptionRule` / `MoveDecryptionRule` / `UpdateDecryptionRule`

#### Authentication Rules
- Таблица: Name, Src Zone, Source, Dst Zone, Destination, Service, Action, Auth Profile, Status
- **Actions**: Allow / Deny
- Создание: Name, зоны, адреса, сервисы, action, Authentication Profile, Timeout
- NGFW API: `ListAuthenticationRules` / `CreateAuthenticationRule` / `DeleteAuthenticationRule` / `MoveAuthenticationRule` / `UpdateAuthenticationRule`

#### PBR Rules (Policy-Based Routing)
- Таблица: Name, Src Zone, Source, Dst Zone, Destination, Service, Action, Nexthop, Status
- **Actions**: Forward / Drop
- Создание: Name, зоны, адреса, сервисы, action, Nexthop IP, Nexthop Interface, Priority
- NGFW API: `ListPBRRules` / `CreatePBRRule` / `DeletePBRRule` / `MovePBRRule` / `UpdatePBRRule`

### Общий функционал для всех вкладок

- **Toggle** enable/disable прямо в таблице
- **Delete** одного правила (кнопка в строке)
- **Bulk Delete** (чекбоксы + bulk bar)
- **ObjectPicker** для src/dst адресов и сервисов
- Динамические колонки — таблица перестраивается в зависимости от вкладки

---

## Блок 6 — System Management

**URL:** `/system`

### Вкладка: Admins

- **Список администраторов**: Login, Name, Role, Status (Active/Blocked)
- **Создание**: Login, Name, Password, Role (SuperAdmin/Admin/ReadOnly/Auditor)
- **Block / Unblock** администратора (кнопка в строке)
- **Delete** с подтверждением
- **Change Password** (отдельный модал)
- NGFW API: `ListAdmins` / `CreateAdmin` / `DeleteAdmin` / `BlockAdmin` / `UnblockAdmin` / `UpdateAdminCredentials`

### Вкладка: Backup & Snapshot

**Бэкапы:**
- Список: Name/File, Date, Size
- **Create Backup** (с опциональным описанием)
- **Delete Backup** с подтверждением
- NGFW API: `ListBackups` / `CreateBackup` / `DeleteBackups`

**Снапшоты:**
- Список: ID, Description, Date
- **Take Snapshot** (CommitSnapshot) с описанием
- NGFW API: `ListSnapshots` / `CommitSnapshot`

### Вкладка: Routing

**Static Routes:**
- Таблица: Destination/Prefix, Gateway, Interface, Metric, Description
- **Add Route** модал: Destination, Prefix Length, Gateway, Interface, Metric, Description
- **Delete Route** с подтверждением
- NGFW API: `ListStaticRoutes` / `CreateStaticRoute` / `DeleteStaticRoute`

**BGP (read-only info card):**
- Local ASN, Enabled status
- Таблица BGP peers: Neighbor IP, Remote ASN, Session State (Established=зелёный)
- NGFW API: `GetBGP` / `ListBGPPeers`

**OSPF (read-only info card):**
- Router ID, Enabled status
- Таблица OSPF areas: Area ID, Type, Networks
- NGFW API: `GetOSPF` / `ListOSPFAreas`

### Вкладка: Interfaces

- Объединённый список Virtual + Logical interfaces
- Таблица: Name, Type, IP Address, Status (Up/Down), Description
- **Read-only** — только просмотр
- NGFW API: `ListVirtualInterfaces` / `ListLogicalInterfaces`

### Вкладка: Settings

- **Session Timeouts** форма:
  - TCP Session Timeout
  - UDP Session Timeout
  - ICMP Session Timeout
  - TCP Half-Open Timeout
  - TCP Time-Wait Timeout
  - UDP Stream Timeout
- Кнопка **Save** — применяет изменения на NGFW
- NGFW API: `GetDeviceTimeouts` / `SetDeviceTimeouts`

---

## Архитектура кода

### Backend

```
app/
├── infrastructure/
│   └── ngfw_client.py       # HTTP-клиент к NGFW REST API (78 методов)
├── web/
│   └── router.py            # FastAPI роутер (53 эндпоинта)
├── services/
│   ├── sync_service.py      # Синхронизация правил NGFW → локальный кэш
│   ├── deploy_service.py    # Deploy: вычисление позиций + MoveSecurityRule
│   └── nat_service.py       # Deploy для NAT правил
└── db/
    └── models.py            # SQLAlchemy модели (ORM)
```

### DB модели

| Таблица | Назначение |
|---|---|
| `cached_rules` | Кэш Security Rules с folder_id и sort_order |
| `folders` | Виртуальные папки для Security Rules |
| `cached_nat_rules` | Кэш NAT Rules |
| `nat_folders` | Виртуальные папки для NAT |
| `cached_objects` | Кэш объектов (сети/сервисы/зоны) |
| `cached_logs` | Кэш логов с TTL 1 час (traffic/ips/av/audit), авто-очистка |
| `device_meta` | Метаданные устройств (name, device_group_id) |

### Frontend

```
app/
├── templates/
│   ├── index.html           # Security Rules
│   ├── nat.html             # NAT Rules
│   ├── objects.html         # CRUD объектов
│   ├── logs.html            # Logs & Monitoring
│   ├── policy.html          # Decryption/Auth/PBR Rules
│   ├── system.html          # Admins/Backup/Routing/Interfaces/Settings
│   ├── login.html           # Страница входа
│   ├── base.html            # Базовый layout
│   └── components/
│       └── sidebar.html     # Общий сайдбар (SEC/NAT/OBJ/LOG/POL/SYS)
└── static/
    ├── js/
    │   └── picker.js        # ObjectPicker + showToast + showLoading + confirmDialog
    └── css/
        └── app.css          # Кастомные стили
```

### picker.js — общие UI компоненты

| Компонент | Описание |
|---|---|
| `ObjectPicker` | Tag-based multi-select с live-поиском, highlight совпадений, inline Create |
| `showToast(msg, type)` | Toast-уведомления (info/success/error/warning) |
| `showLoading(msg)` | Overlay-спиннер на время async операций |
| `hideLoading()` | Скрыть спиннер |
| `confirmDialog(title, msg, okLabel)` | Promise-based диалог подтверждения |

---

## API эндпоинты (полный список)

### Auth
| Метод | URL | Описание |
|---|---|---|
| GET | `/login` | Страница входа |
| POST | `/login` | Аутентификация (сохраняет сессию) |
| GET | `/logout` | Выход |

### Security Rules
| Метод | URL | Описание |
|---|---|---|
| GET | `/` | Страница с таблицей правил |
| POST | `/sync` | Синхронизация с NGFW |
| POST | `/commit` | Deploy правил на NGFW |
| POST | `/create_folder` | Создать папку |
| POST | `/api/v1/rules/create` | Создать правило |
| POST | `/api/v1/rules/update` | Обновить правило |
| POST | `/api/v1/rules/delete` | Удалить правила (bulk) |
| POST | `/api/v1/rules/toggle` | Вкл/выкл правило |
| POST | `/api/v1/rules/reorder` | Изменить порядок (drag-drop) |
| POST | `/api/v1/rules/transfer` | Перенести на другое устройство |
| POST | `/api/v1/rules/acknowledge` | Подтвердить внешнее изменение |
| GET | `/api/v1/rules/folders/tree` | Дерево папок |
| GET | `/api/v1/profiles/list` | Список профилей IPS/AV/ICAP |
| GET | `/api/v1/objects/list` | Список объектов для picker |

### NAT Rules
| Метод | URL | Описание |
|---|---|---|
| GET | `/nat` | Страница NAT |
| POST | `/nat/create_folder` | Создать NAT папку |
| POST | `/nat/deploy` | Deploy NAT правил |
| GET | `/api/v1/nat/folders/tree` | Дерево NAT папок |
| POST | `/api/v1/nat/rules/create` | Создать NAT правило |
| POST | `/api/v1/nat/rules/delete` | Удалить NAT правила |
| POST | `/api/v1/nat/rules/toggle` | Вкл/выкл NAT правило |
| POST | `/api/v1/nat/rules/reorder` | Изменить порядок |

### Objects
| Метод | URL | Описание |
|---|---|---|
| GET | `/objects` | Страница объектов |
| POST | `/api/v1/objects/create` | Создать объект |
| POST | `/api/v1/objects/delete` | Удалить объекты (bulk) |

### Logs
| Метод | URL | Описание |
|---|---|---|
| GET | `/logs` | Страница логов |
| POST | `/api/v1/logs/fetch` | Скачать из NGFW → кэш (1h/6h/24h с предупреждением) |
| POST | `/api/v1/logs/query` | SQL-запрос по кэшу с фильтрами + пагинация |
| GET | `/api/v1/logs/status` | Статус кэша: count, fetched_at, purge_in_sec |
| POST | `/api/v1/logs/clear` | Ручная очистка кэша по device+type |
| GET | `/api/v1/logs/export` | Streaming CSV-экспорт из кэша |
| GET | `/api/v1/logs/rule_stats` | Статистика срабатываний правил |

### Policy Rules
| Метод | URL | Описание |
|---|---|---|
| GET | `/policy` | Страница Policy Rules |
| POST | `/api/v1/policy/list` | Список правил (decryption/auth/pbr) |
| POST | `/api/v1/policy/create` | Создать правило |
| POST | `/api/v1/policy/delete` | Удалить правила (bulk) |
| POST | `/api/v1/policy/toggle` | Вкл/выкл правило |

### System
| Метод | URL | Описание |
|---|---|---|
| GET | `/system` | Страница System |
| GET | `/api/v1/system/admins` | Список администраторов |
| POST | `/api/v1/system/admins/create` | Создать администратора |
| POST | `/api/v1/system/admins/action` | Действие (delete/block/unblock) |
| POST | `/api/v1/system/admins/password` | Сменить пароль |
| GET | `/api/v1/system/backups` | Список backup + snapshot |
| POST | `/api/v1/system/backups/create` | Создать backup |
| POST | `/api/v1/system/backups/delete` | Удалить backup |
| POST | `/api/v1/system/snapshots/commit` | Создать snapshot |
| GET | `/api/v1/system/routing` | Static routes + BGP + OSPF |
| POST | `/api/v1/system/routing/create` | Добавить статический маршрут |
| POST | `/api/v1/system/routing/delete` | Удалить маршрут |
| GET | `/api/v1/system/interfaces` | Список интерфейсов |
| GET | `/api/v1/system/timeouts` | Текущие таймауты |
| POST | `/api/v1/system/timeouts/set` | Сохранить таймауты |

---

## Уникальные фишки проекта

### 1. Виртуальные папки
NGFW хранит правила в плоском списке (Pre/Default/Post секции). Мы добавили собственные "папки" поверх этого:
- Администратор создаёт папки и раскладывает правила
- При Deploy система вычисляет финальный порядок (папки внутри секций) и вызывает `MoveSecurityRule`/`MoveNatRule` для каждого правила
- Папки хранятся в нашей PostgreSQL — NGFW о них не знает

### 2. Change Tracking
- После Sync вычисляется hash данных каждого правила
- При следующем Sync: если hash изменился — правило помечается как "изменено извне"
- В таблице показывается badge с предупреждением
- Администратор может нажать "Acknowledge" — сбросить метку после ревью

### 3. Inter-device Transfer
- Выбрать правила в одной папке → Transfer → выбрать целевое устройство и папку
- Система копирует правило, резолвит объекты по имени на целевом устройстве
- Работает в рамках одной СУ (один NGFW-хост с несколькими device groups)

### 4. Inline Object Creation
- При вводе в ObjectPicker несуществующего объекта появляется опция "Create '...'"
- Открывается Quick Create модал с автоопределением типа объекта по введённому тексту
- Созданный объект сразу добавляется как выбранный тег в поле правила

### 5. Параллельные запросы к NGFW
- Страница Routing загружает Static Routes + BGP + OSPF параллельно через `asyncio.gather`
- Страница Interfaces загружает Virtual + Logical интерфейсы параллельно

---

*Создано: 2026-04-25*
