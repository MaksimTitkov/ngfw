# Публикация проекта на GitHub

## 1. Создать репозиторий на GitHub

1. Зайти на https://github.com → кнопка **New repository**
2. Название: `ngfw-manager` (или любое удобное)
3. Видимость: **Private** (рекомендуется — в коде есть адреса NGFW)
4. Создать **пустой** репозиторий (без README, .gitignore, license)
5. Скопировать URL вида: `https://github.com/ВАШ-АККАУНТ/ngfw-manager.git`

---

## 2. Создать .gitignore

В корне проекта создать файл `.gitignore`:

```
# Секреты
.env

# База данных
*.db
*.sqlite
*.sqlite3

# Python
__pycache__/
*.pyc
*.pyo
.venv/
venv/
*.egg-info/
dist/
build/
.pytest_cache/

# SSL-сертификаты
nginx/certs/*.crt
nginx/certs/*.key
nginx/certs/*.pem

# Логи
*.log

# IDE
.idea/
.vscode/
```

---

## 3. Инициализация и первый коммит

Выполнить в папке проекта на сервере:

```bash
cd /путь/к/ngfw_manager

git init
git add .
git status          # проверить: .env НЕ должен попасть в список
git commit -m "Initial commit: NGFW Manager v1.0"
```

---

## 4. Подключить GitHub и отправить

```bash
git remote add origin https://github.com/ВАШ-АККАУНТ/ngfw-manager.git
git branch -M main
git push -u origin main
```

При запросе логина/пароля — вместо пароля вставить **Personal Access Token (PAT)**:

- GitHub → Settings → Developer settings → Personal access tokens → **Tokens (classic)**
- Generate new token → поставить галочку **repo** → скопировать токен
- Вставить токен как пароль при `git push`

> Токен можно сохранить чтобы не вводить каждый раз:
> ```bash
> git config --global credential.helper store
> ```
> После первого успешного push токен сохранится автоматически.

---

## 5. Рабочий процесс: коммит изменений

После каждого набора правок:

```bash
git add app/web/router.py app/templates/logs.html   # добавить конкретные файлы
# или
git add .                                            # добавить всё (кроме .gitignore)

git commit -m "Описание что изменилось"
git push
```

---

## 6. Создать релиз

Когда версия готова:

```bash
# Создать тег на текущем коммите
git tag -a v1.1.0 -m "v1.1.0: фильтры логов, пагинация по времени"
git push origin v1.1.0
```

Затем на GitHub:
- **Releases → Draft a new release**
- Выбрать тег `v1.1.0`
- Написать описание изменений
- **Publish release**

---

## 7. Получить изменения на другой машине

Если проект уже склонирован на другом сервере:

```bash
git pull origin main
```

Если только клонируем:

```bash
git clone https://github.com/ВАШ-АККАУНТ/ngfw-manager.git
cd ngfw-manager
# скопировать .env вручную (он не в репозитории)
```

---

## Важные правила

- `.env` **никогда не коммитить** — там пароли. `.gitignore` должен быть создан до первого `git add`
- SSL-сертификаты (`nginx/certs/`) тоже не коммитить — генерируются отдельно через `init_ssl.sh`
- Если `.env` случайно попал в коммит — нужно удалять из истории через `git filter-branch` или `BFG Repo Cleaner`
