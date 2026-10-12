# anyhop

OpenAI-совместимый LLM-шлюз с автоматической ротацией аккаунтов и API-ключей.
Один бинарь (~6MB), минимальное потребление ресурсов.

## Возможности

- **Единая точка** `POST /v1/chat/completions` (OpenAI-формат) для всех провайдеров
- **Провайдеры**: `openai_compat` (OpenRouter, DeepSeek, Groq, ...), `gemini` (API-ключи),
  `antigravity` (Google OAuth-аккаунты через cloudcode-pa)
- **Стратегии ротации**: `round_robin`, `least_used`, `fill_first` (дожать квоту ключа → следующий)
- **Failover**: 429 + Retry-After → точный кулдаун, 401/403 → dead, 5xx/timeout → экспоненциальный бэкофф
- **Персистентность** (redb): health ключей, OAuth-токены и статистика переживают рестарт
- **Дашборд** `/dashboard`: статусы ключей в реальном времени (htmx + SSE failover-ленты)
- **Стриминг** без буферизации во всех режимах (SSE→SSE для gemini/antigravity с трансляцией)

## Быстрый старт

```bash
cp anyhop.example.toml anyhop.toml   # вписать ключи
cargo run --release
```

Добавить Antigravity-аккаунт (Google OAuth):

```bash
anyhop auth antigravity              # откроет браузер, напечатает TOML-сниппет
```

Клиенты указывают модель как `провайдер/модель`, например `antigravity/gemini-3-flash`,
или по имени модели из списка провайдера.

## Конфигурация

См. `anyhop.example.toml`. Путь: `ANYHOP_CONFIG` (по умолчанию `anyhop.toml`).

## Тесты

```bash
python3 test/mock_upstream.py &     # openai_compat мок :9100
python3 test/mock_gemini.py &       # gemini мок :9101
python3 test/mock_antigravity.py &  # antigravity мок :9102
ANYHOP_CONFIG=test/anyhop.test.toml cargo run
```
