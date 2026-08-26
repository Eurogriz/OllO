# OllO

Русскоязычный защищённый мессенджер с сквозным шифрованием.

**Приоритеты:** Security > Privacy > Reliability > Performance > UX > Feature richness.

OllO **не заявляет** уровень безопасности Signal. Такой уровень может быть заявлен
только после независимого security-аудита, penetration testing, криптографического
ревью и эксплуатационных тестов. До этого система использует проверенные
стандартизированные примитивы и опубликованные протоколы, но считается
**pre-audit**.

| Документ | Содержание |
|---|---|
| [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) | Архитектура, сервисы, потоки данных |
| [SECURITY_MODEL.md](docs/security/SECURITY_MODEL.md) | Что сервер видит и не видит |
| [THREAT_MODEL.md](docs/security/THREAT_MODEL.md) | STRIDE / LINDDUN, угрозы и остаточный риск |
| [CRYPTOGRAPHY.md](docs/security/CRYPTOGRAPHY.md) | Примитивы, ключи, жизненный цикл |
| [PRIVACY.md](docs/security/PRIVACY.md) | Метаданные, retention, права пользователя |
| [API.md](docs/api/API.md) | HTTP + WebSocket API |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Локальная разработка |
| [DEPLOYMENT.md](docs/operations/DEPLOYMENT.md) | Staging / production |
| [OPERATIONS.md](docs/operations/OPERATIONS.md) | SLO, алерты, runbooks |
| [DISASTER_RECOVERY.md](docs/operations/DISASTER_RECOVERY.md) | RPO / RTO, backup, restore |
| [TESTING.md](docs/TESTING.md) | Стратегия тестов |
| [RELEASE.md](docs/RELEASE.md) | Сборка Android / iOS / backend |

## Что умеет система

- Регистрация по Ed25519-ключу на устройстве (публичный ключ = адрес / QR), username, профиль, аватар
- Поиск пользователей, контакты, блок, жалобы, mute, архив
- Личные и групповые чаты
- Сообщения: ответы, пересылка, редактирование, удаление, реакции, упоминания, закрепление
- Черновики, typing, delivery / read receipts
- Исчезающие сообщения и TTL
- Вложения: изображения, видео, аудио, голосовые, документы — **E2EE на клиенте**
- 1:1 и групповые аудио/видеозвонки (WebRTC + защищённая сигнализация)
- Multi-device, safety number, отзыв устройства
- Offline-first очередь, reconnect, синхронизация
- Push без plaintext содержимого

## Быстрый старт (local)

Требования: Node.js 22+. Docker **не обязателен** — в development используется
встроенный PGlite (реальный PostgreSQL в процессе).

```bash
cp .env.example .env
npm install
npm run dev:all
```

- API / WebSocket: `http://localhost:8080`
- Web-клиент: `http://localhost:5173`
- Health: `GET /healthz`, `GET /readyz`

Регистрация: клиент создаёт Ed25519-пару на устройстве, подписывает
челлендж `POST /v1/auth/challenge` и вызывает `POST /v1/auth/register-key`.
Приватный ключ на сервер не уходит. Сразу после создания аккаунта нужно
скачать зашифрованную резервную копию — без неё потерянный телефон
невосстановим. OTP по телефону остаётся в API только как запасной путь
для существующих тестов — это не корень идентичности.

Два пользователя в двух окнах браузера — можно переписываться. Сообщения на
сервере лежат только как ciphertext envelope.

## Структура репозитория

```text
/apps
  /android          Kotlin + Jetpack Compose
  /ios              Swift + SwiftUI
  /web              React-клиент (dev / staging / internal)
/services
  /server           Modular monolith: auth, users, devices, messaging,
                    groups, attachments, calls, notifications
/packages
  /crypto           Audited primitives + X3DH / Double Ratchet / Sender Keys
  /protocol         Конверты, типы, версионирование протокола
  /shared           Валидация, ошибки, константы
/infrastructure
  /terraform
  /kubernetes
  /helm
  /docker
/docs
/tests
```

Почему modular monolith, а не 10 отдельных бинарников с первого дня:
границы сервисов проведены так, чтобы их можно было вынести, но один процесс
упрощает транзакции, локальную разработку и security review. В production
горизонтально масштабируются **stateless реплики** за load balancer, а не
обязательно отдельные микросервисы. См. trade-offs в ARCHITECTURE.md.

## Криптография — коротко

Клиенты шифруют **до** отправки. Сервер видит только:

- routing metadata (кто кому, какое устройство, timestamp);
- opaque ciphertext;
- размер ciphertext.

Сервер **не** хранит и **не** получает ключи расшифровки сообщений и файлов.

Клиентский протокол:

- Identity: X25519 + Ed25519
- Initial agreement: X3DH (спецификация Signal)
- Сессия: Double Ratchet (спецификация Signal)
- Группы: Sender Keys (спецификация Signal)
- AEAD: XChaCha20-Poly1305
- Вложения: случайный 256-bit ключ, XChaCha20-Poly1305, ключ уходит в E2EE-конверт
- Звонки: DTLS-SRTP + Insertable Streams / SFrame для медиа E2EE

Примитивы берутся из independently audited библиотек (`@noble/curves`,
`@noble/ciphers`, `libsodium`). Android / iOS в production должны использовать
официальный `libsignal`. TypeScript-реализация протокола — reference path для
web и тестов; она **требует отдельного cryptographic review** перед production.

Подробности: [CRYPTOGRAPHY.md](docs/security/CRYPTOGRAPHY.md).

## Чего система не обещает

- Абсолютной анонимности (сервер видит публичный адрес и граф доставки)
- Защиты от скомпрометированного клиента / рутованного устройства
- Невидимости факта общения (traffic analysis на уровне сети остаётся)
- «Уровня Signal» без независимого аудита

## Лицензия

UNLICENSED — исходный код предназначен для продукта OllO.
Не копируйте криптографию «по аналогии» в другие продукты без ревью.
