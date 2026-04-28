# NGFW Manager — Roadmap модернизации

## Текущее состояние
- Реализовано ~68 из 322 API-эндпоинтов (21%)
- Основа: SEC-правила с виртуальными папками, NAT, объекты (просмотр), логи (трафик)

---

## ФАЗА 1 — Полноценное управление объектами
**Цель:** сделать раздел Objects полностью рабочим — не только просмотр, но и CRUD

### 1.1 Сетевые объекты
- [x] CreateNetworkObject (форма создания: IP, FQDN, диапазон)
- [x] UpdateNetworkObject (редактирование через Edit-модалку)
- [x] DeleteNetworkObject (bulk delete с подтверждением)
- [x] ListNetworkObjects (полная пагинация, поиск)

### 1.2 Сетевые группы
- [x] CreateNetworkObjectGroup
- [x] UpdateNetworkObjectGroup (изменить членов группы через Edit-модалку)
- [x] DeleteNetworkObjectGroup
- [x] ListNetworkObjectGroups

### 1.3 Сервисы и группы сервисов
- [x] CreateService / UpdateService / DeleteService
- [x] CreateServiceGroup / UpdateServiceGroup / DeleteServiceGroup
- [x] ListServices / ListServiceGroups (с фильтрами)

### 1.4 URL категории
- [ ] CreateURLCategory / UpdateURLCategory / DeleteURLCategory
- [ ] ListURLCategories (полный список с поиском)

### 1.5 Зоны
- [ ] UpdateZone / DeleteZone
- [ ] Редактирование зон прямо из интерфейса

---

## ФАЗА 2 — Полнота правил
**Цель:** все типы правил — полный CRUD и UI

### 2.1 NAT правила
- [ ] UpdateNatRule (сейчас редактирование невозможно — только delete+create)
- [ ] Inline-редактирование полей в таблице NAT

### 2.2 Правила дешифрования (Decryption Rules)
- [ ] Полноценный UI-раздел (аналог SEC/NAT)
- [ ] Create / Update / Delete / Move / виртуальные папки
- [ ] UpdateDecryptionRule

### 2.3 Правила аутентификации (Authentication Rules)
- [ ] Полноценный UI-раздел
- [ ] Create / Update / Delete / Move

### 2.4 PBR правила (Policy Based Routing)
- [ ] UI-раздел
- [ ] Create / Update / Delete / Move

---

## ФАЗА 3 — Маршрутизация
**Цель:** управление сетевыми настройками устройств

### 3.1 Статические маршруты
- [ ] Полный CRUD (List / Create / Update / Delete)
- [ ] UI-раздел с таблицей маршрутов по device group

### 3.2 BGP
- [ ] Create / Update / Delete BGP-конфигурации
- [ ] BGP Peers: List / Create / Update / Delete
- [ ] BGP Networks, Auth Profiles, Filter Profiles, Redistribution

### 3.3 OSPF
- [ ] Create / Update / Delete OSPF
- [ ] OSPF Areas, Auth Profiles, Redistribution

### 3.4 Виртуальные роутеры и интерфейсы
- [ ] ListVirtualRouters / Create / Update / Delete
- [ ] ListVirtualInterfaces / Create / Update / Delete
- [ ] ListVirtualWires

---

## ФАЗА 4 — Расширенный мониторинг логов
**Цель:** поддержка всех типов логов, не только Traffic

### 4.1 Новые типы логов (уже частично в коде)
- [ ] IPS Logs (полный UI — сейчас только fetch)
- [ ] Antivirus Logs
- [ ] Decrypt Logs
- [ ] ICAP Logs
- [ ] IPSec Logs
- [ ] Auth Event Logs
- [ ] Audit Logs (действия администраторов)
- [ ] Admin Auth Events

### 4.2 Улучшение существующего лог-вьювера
- [ ] SuggestTrafficLogs — автодополнение значений фильтров
- [ ] TrafficLogsActivity — активность по времени (для графиков)
- [ ] TrafficLogsMeta — метаданные доступных полей
- [ ] Графики: top src IP, top dst IP, top порты, top правила

---

## ФАЗА 5 — Резервное копирование и снапшоты
**Цель:** полный цикл управления конфигурацией устройства

### 5.1 Backup
- [ ] UI-раздел Backups (список, статус, размер)
- [ ] CreateBackup (запуск с прогрессом)
- [ ] DownloadBackup / UploadBackup
- [ ] RestoreBackup (с подтверждением)
- [ ] DeleteBackups / RotateBackups
- [ ] GetBackupCreateJob / GetBackupRestoreJob (опрос статуса)
- [ ] GetBackupStorageInfo (сколько места занято)

### 5.2 Snapshots
- [ ] CommitSnapshot (уже есть в client) — UI кнопка
- [ ] PushSnapshot (загрузить снапшот на устройство)
- [ ] GetSnapshotCommitJob / GetSnapshotPushJob (прогресс)
- [ ] ListSnapshots — просмотр доступных снапшотов

---

## ФАЗА 6 — Администрирование
**Цель:** управление учётными записями и профилями безопасности

### 6.1 Администраторы
- [ ] UI-раздел Admin (список, создание, блокировка)
- [ ] CreateAdmin / UpdateAdmin / DeleteAdmin
- [ ] BlockAdmin / UnblockAdmin
- [ ] UpdateAdminCredentials / UpdatePassword
- [ ] GetMe (информация о текущем пользователе)

### 6.2 Профили безопасности
- [ ] IPS Profiles: List / Create / Update / Delete
- [ ] Antivirus Profiles: List / Create / Update / Delete
- [ ] Auth Profiles: List / Create / Update / Delete
- [ ] ICAP Server + ICAP Profile: полный CRUD
- [ ] DecryptionMirroring Profile

### 6.3 Пользователи и группы (LDAP/local)
- [ ] ListUsers / ListUserGroups
- [ ] ListRoles — справочник ролей

### 6.4 Syslog
- [ ] SyslogServer: List / Create / Update / Delete
- [ ] SyslogForwardRule: List / Create / Update / Delete

### 6.5 Устройства
- [ ] ListLogicalDevices / UpdateLogicalDevice
- [ ] ListPhysicalDevices / UpdatePhysicalDevice
- [ ] ListDeviceGroups / CreateDeviceGroup / UpdateDeviceGroup / DeleteDeviceGroup
- [ ] Session Timeouts (уже частично есть)

---

## ФАЗА 7 — Уникальные фичи (нет в оригинальном NGFW)

### 7.1 Policy Analyzer — анализ политики безопасности
Нет в оригинале. Локальный анализ кэша правил.

- [x] **Теневые правила (Shadowed Rules)** — правило полностью перекрывается предыдущим и никогда не сработает. Анализ по src/dst/service/action.
- [x] **Избыточные правила (Redundant Rules)** — два правила с одинаковым действием можно объединить в одно.
- [x] **Слишком широкие правила** — правила с Any/Any в src или dst и действием Allow.
- [x] **Disabled-правила** — список всех выключенных правил с датой последнего изменения.
- [x] Результат: страница /analyzer с отчётом, каждую проблему можно кликнуть и перейти к правилу.

### 7.2 Policy Diff — сравнение политик
Нет в оригинале.

- [ ] **Diff между двумя device groups** — показать что есть в одной, чего нет в другой
- [ ] **Diff до/после sync** — что изменилось на NGFW с момента последней синхронизации (сравнение локального кэша с живыми данными)
- [ ] **Diff до/после deploy** — предпросмотр изменений перед применением порядка правил
- [ ] Визуальный diff: зелёный=добавлено, красный=удалено, жёлтый=изменено

### 7.3 Change Log — журнал локальных изменений
Нет в оригинале.

- [x] Таблица `change_log` в БД: user, action, entity_type, entity_id, entity_name, detail, timestamp
- [x] Запись каждого изменения правила/папки/объекта в журнал
- [x] UI-страница /changelog: кто, что, когда изменил
- [x] Фильтрация по дате, пользователю, типу изменения

### 7.4 Rule Templates — шаблоны правил
Нет в оригинале.

- [ ] Сохранить любое правило как шаблон (с именем и описанием)
- [ ] Библиотека шаблонов — каталог готовых правил
- [ ] Применить шаблон: создать правило на основе шаблона в выбранном DG
- [ ] Массовое применение: развернуть шаблон сразу на несколько device groups
- [ ] Хранение в локальной БД (не зависит от NGFW)

### 7.5 Object Usage Map — карта использования объектов
Нет в оригинале.

- [ ] Для любого объекта (IP, сервис, группа) — показать все правила, где он используется
- [ ] Предупреждение при удалении объекта: "используется в N правилах"
- [ ] Поиск по объектам: "найди все правила, где src = 10.16.0.0/16"
- [ ] Граф зависимостей: объект → список правил (визуально)

### 7.6 Dashboard — главная страница мониторинга
Нет в оригинале (в NGFW есть только базовая статистика).

- [x] **Сводные карточки** — Security Rules, NAT Rules, Objects, Devices, Modified Rules, Recent Changes
- [x] **Per-device статус** — карточка каждого устройства: SEC/NAT/OBJ count, modified count, ссылки на Rules/Diff/Analyzer
- [x] **Externally Modified Rules** — список правил изменённых вне интерфейса, с ссылками
- [x] **Recent Changes** — последние 20 записей из Change Log
- [x] **Алерты** — нет данных (не синкнуто), много изменённых правил
- [x] **Quick Navigation** — иконки быстрого доступа ко всем разделам
- [ ] **Топ правил по трафику** — из ListMetricsRulesStats
- [ ] **Активность по времени** — heatmap: час × день

### 7.7 Bulk Operations — массовые операции
Частично есть (transfer), расширяем.

- [x] **Массовое включение/выключение** правил (enabled/disabled)
- [x] **Массовое изменение action** (allow → deny для группы правил)
- [x] **Массовое изменение logging** — включить логирование для выбранных правил
- [x] **Массовое перемещение** — переложить в другую папку
- [x] **Массовое удаление** — удалить несколько правил одновременно
- [ ] **Find & Replace в объектах** — заменить объект X на объект Y во всех правилах

### 7.8 Export / Import
Частично есть (CSV для логов), расширяем.

- [ ] **Экспорт политики в Excel** — форматированный отчёт: правила с объектами, цветовая кодировка action
- [ ] **Экспорт в PDF** — документация политики безопасности
- [ ] **Экспорт структуры папок в YAML** — бэкап виртуальной структуры (независимо от NGFW)
- [ ] **Импорт структуры папок из YAML** — восстановление виртуальной структуры
- [ ] **Импорт правил из CSV** — массовое создание правил по таблице

### 7.9 Scheduler — планировщик задач
Нет в оригинале.

- [ ] **Автосинхронизация** — sync по расписанию (cron-like): каждый час/день
- [ ] **Автобэкап** — создавать backup NGFW каждые N часов
- [ ] **Автодеплой** — применять изменения по расписанию (например, в ночное окно)
- [ ] **Автоочистка логов** — уже есть (TTL), расширить настройками через UI
- [ ] UI-страница управления задачами: список, статус, журнал выполнения
- [ ] Уведомления об ошибках в задачах (логи + статус-бар)

### 7.10 Smart Rule Search — умный поиск
Нет в оригинале.

- [ ] **Глобальный поиск** по всем правилам и объектам одновременно (Ctrl+K)
- [ ] **Поиск по IP** — найти все правила, где этот IP встречается в src ИЛИ dst (с учётом подсетей)
- [ ] **Поиск по подсети** — 10.16.0.0/16 найдёт и 10.16.1.5 и 10.16.0.0/24
- [ ] **Поиск по порту** — найти все правила, где разрешён/запрещён порт 443
- [ ] SuggestSecurityRuleFilter API — автодополнение в поиске
- [ ] Результаты: ссылка на правило + папка + device group

---

## Порядок реализации (приоритеты)

| Приоритет | Фаза | Обоснование |
|---|---|---|
| 🔴 Высокий | Фаза 1: Object Management | Объекты нужны для всего — без CRUD системой неудобно |
| 🔴 Высокий | Фаза 7.1: Policy Analyzer | Главная уникальная фича, ключевое конкурентное преимущество |
| 🔴 Высокий | Фаза 7.6: Dashboard | Первое что видит пользователь — должно быть информативным |
| 🟡 Средний | Фаза 2: Полнота правил | UpdateNatRule и Decryption — часто нужны |
| 🟡 Средний | Фаза 4: Все типы логов | IPS и Audit логи важны для безопасности |
| 🟡 Средний | Фаза 7.2: Policy Diff | Важно перед деплоем |
| 🟡 Средний | Фаза 7.3: Change Log | Аудит изменений — требование безопасности |
| 🟡 Средний | Фаза 7.7: Bulk Operations | Экономия времени при массовых изменениях |
| 🟢 Низкий | Фаза 3: Маршрутизация | Специфично, нужно не всем |
| 🟢 Низкий | Фаза 5: Backup/Snapshot | Полезно, но не срочно |
| 🟢 Низкий | Фаза 6: Администрирование | Редко меняется |
| 🟢 Низкий | Фаза 7.4: Templates | Удобно, не критично |
| 🟢 Низкий | Фаза 7.8: Export/Import | Полезно для документирования |
| 🟢 Низкий | Фаза 7.9: Scheduler | Автоматизация — долгосрочно |
| 🟢 Низкий | Фаза 7.10: Smart Search | UX-улучшение |


---

## Фаза 8: Современный фронтенд (после завершения Roadmap)

### 8.1 PWA (Progressive Web App)
- [ ] `manifest.json` — установка на рабочий стол, иконки, название
- [ ] Service Worker (Workbox) — оффлайн-кэш статики (CSS, JS, шрифты)
- [ ] Push-уведомления — результаты sync, ошибки деплоя, задачи планировщика

### 8.2 Миграция на Vue 3 (Composition API)
- [ ] Настроить Vite + Vue 3 как отдельный фронтенд-проект
- [ ] FastAPI переводится в режим SPA: все `/` отдают `index.html`, API остаётся `/api/v1/`
- [ ] Портировать страницы по приоритету: index → objects → analyzer → diff → changelog
- [ ] Переписать ObjectPicker как Vue-компонент (переиспользуется везде)
- [ ] Drag-drop сортировки правил — Vue Draggable
- [ ] Все модальные окна — Vue компоненты с реактивным состоянием
- [ ] Авторизация через Pinia store (токен + user)
