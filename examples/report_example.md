# OsintX — отчёт по цели `torvalds@gmail.com`

- **Тип цели:** email
- **ID поиска:** `619d0ee338a945bc`
- **Начато:** 2026-09-20T13:22:39Z, длительность: 39.70 с
- **Находок:** 15
- **Источников проверено:** 203 (недоступно 181, покрытие 10.8%)
- **Оценка экспозиции:** 34/100

## Находки

| Достоверность | Категория | Источник | Что найдено | Ссылка |
|---|---|---|---|---|
| 🟢 high | domain | subdomain-brute | Перебор поддоменов по словарю (120 слов): найдено 4 живых | https://dns.google/query?name=gmail.com&type=A |
| 🟢 high | email | dns | Домен gmail.com: MX найден — почта принимается | https://dns.google/query?name=gmail.com&type=MX |
| 🟢 high | email | email-hygiene | Бесплатный публичный почтовый сервис | — |
| 🟢 high | email | gravatar | Gravatar не найден (аватар отсутствует) | https://www.gravatar.com/avatar/e9c3ee71babc6bd3912b021f1befe6b0?s=200 |
| 🟢 high | email | syntax | Синтаксис корректен, нормализовано: torvalds@gmail.com | — |
| 🟢 high | username | github | github: аккаунт найден | https://github.com/torvalds |
| 🟢 high | username | github-api | GitHub: Linus Torvalds (@torvalds), репозиториев: 12, подписчиков: 324359 | https://github.com/torvalds |
| 🟢 high | username | github-repos | GitHub: 12 последних репозиториев, языки: C, Python, C++, OpenSCAD | https://github.com/torvalds?tab=repositories |
| 🟢 high | username | normalize | Цель нормализована: «torvalds» (длина 8, только буквы) | — |
| 🟡 medium | email | mail-provider | Почта обслуживается: Google Workspace / Gmail | — |
| ⚪ low | breach | breach-links | Прямые ссылки на сервисы проверки утечек | — |
| ⚪ low | domain | dorks | Поисковые операторы (dorks) по домену gmail.com | https://www.google.com/search?q=site%3Agmail.com |
| ⚪ low | email | dorks | Поисковые ссылки по адресу (14) — открыть и проверить вручную | https://www.google.com/search?q=%22torvalds%40gmail.com%22 |
| ⚪ low | telegram | tg-dorks | Аналитика и поиск по Telegram (tgstat/telemetr/lyzem) — ссылки для проверки | https://www.google.com/search?q=site%3At.me+%22torvalds%22 |
| ⚪ low | username | dorks | Поисковые ссылки по логину | https://www.google.com/search?q=%22torvalds%22 |

## Покрытие источников

| Модуль | Проверено | Найдено | Недоступно | Время |
|---|---|---|---|---|
| email | 20 | 2 | 11 | 7.42 с |
| domain | 10 | 2 | 6 | 4.81 с |
| telegram | 4 | 0 | 2 | 3.50 с |
| username | 169 | 3 | 162 | 23.92 с |

## Сущности

| Тип | Значение | Детали |
|---|---|---|
| email | `torvalds@gmail.com` | {} |
| domain | `gmail.com` | {"provider": "Google Workspace / Gmail", "mx": ["alt1.gmail-smtp-in.l.google.com", "gmail-smtp-in.l.google.com", "alt3.g |
| username | `torvalds` | {"sites_total": 93} |
| github | `torvalds` | {"repos": 12, "languages": ["C", "Python", "C++", "OpenSCAD"]} |
| email | `gmail.com` | {} |
| email | `Google Workspace / Gmail` | {} |
| telegram | `torvalds` | {} |

## Связи

| Откуда | Куда | Связь | Вес | Подтверждение |
|---|---|---|---|---|
| `email:torvalds@gmail.com` | `username:torvalds` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds1` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds01` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds7` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds77` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds99` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds007` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvalds_official` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvaldsofficial` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torvaldsreal` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:t0rvalds` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `email:torvalds@gmail.com` | `username:torv4lds` | email_local_part_variant | 0.5 | пользователь обычно берёт логин из локальной части email |
| `domain:gmail.com` | `ip:192.178.163.83` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:192.178.163.19` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:192.178.163.17` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:192.178.163.18` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:2607:f8b0:400e:c17::12` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:2607:f8b0:400e:c17::53` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:2607:f8b0:400e:c17::13` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `ip:2607:f8b0:400e:c17::11` | resolves_to | 1.0 | A/AAAA запись DNS |
| `domain:gmail.com` | `domain:alt3.gmail-smtp-in.l.google.com` | mx_record | 1.0 | MX-запись домена |
| `domain:gmail.com` | `domain:alt2.gmail-smtp-in.l.google.com` | mx_record | 1.0 | MX-запись домена |
| `domain:gmail.com` | `domain:gmail-smtp-in.l.google.com` | mx_record | 1.0 | MX-запись домена |
| `domain:gmail.com` | `domain:alt4.gmail-smtp-in.l.google.com` | mx_record | 1.0 | MX-запись домена |
| `domain:gmail.com` | `domain:alt1.gmail-smtp-in.l.google.com` | mx_record | 1.0 | MX-запись домена |
| `domain:www.gmail.com` | `ip:74.125.135.83` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:www.gmail.com` | `ip:74.125.135.17` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:www.gmail.com` | `ip:74.125.135.19` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:www.gmail.com` | `ip:74.125.135.18` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:gmail.com` | `domain:www.gmail.com` | subdomain | 0.9 | поддомен из словаря, DNS отвечает |
| `domain:smtp.gmail.com` | `ip:74.125.199.108` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:gmail.com` | `domain:smtp.gmail.com` | subdomain | 0.9 | поддомен из словаря, DNS отвечает |
| `domain:pop.gmail.com` | `ip:74.125.20.109` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:pop.gmail.com` | `ip:74.125.20.108` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:gmail.com` | `domain:pop.gmail.com` | subdomain | 0.9 | поддомен из словаря, DNS отвечает |
| `domain:imap.gmail.com` | `ip:74.125.20.109` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:imap.gmail.com` | `ip:74.125.20.108` | resolves_to | 1.0 | перебор поддоменов + DNS-резолв |
| `domain:gmail.com` | `domain:imap.gmail.com` | subdomain | 0.9 | поддомен из словаря, DNS отвечает |
| `username:torvalds` | `site:github` | has_account | 1.0 | HTTP 200 ∈ [200] |

---

_Данные получены из открытых источников в реальном времени. Недоступные источники отмечены отдельно и не считаются «не найдено»._