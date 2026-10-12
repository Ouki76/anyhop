# anyhop

OpenAI-совместимый LLM-шлюз с автоматической ротацией аккаунтов и API-ключей.
Один бинарь (~6MB), минимальное потребление ресурсов.

## Возможности

- **Единая точка** `POST /v1/chat/completions` (OpenAI-формат) для всех провайдеров
- **Провайдеры**: `openai_compat` (OpenRouter, DeepSeek, Groq, ...), `gemini` (API-ключи),
  `antigravity` (Google OAuth-аккаунты через cloudcode-pa), `anthropic` (API-ключи)
- **Combos**: виртуальные модели с fallback-цепочкой между провайдерами (`[[combos]]`)
- **Стратегии ротации**: `round_robin`, `least_used`, `fill_first` (дожать квоту ключа → следующий)
- **Failover**: 429 + Retry-After → точный кулдаун, 401/403 → dead, 5xx/timeout → бэкофф;
  per-model кулдауны для Antigravity (квота одной модели не блокирует остальные)
- **Проактивный drain**: чтение x-ratelimit-* заголовков, уход с ключа до исчерпания лимита
- **Admission control**: `max_concurrent` на ключ
- **Gateway auth**: `[server] api_key` защищает /v1/*
- **Hot-reload**: `kill -HUP` перечитывает конфиг без рестарта
- **Персистентность** (redb): health ключей, OAuth-токены, статистика, добавленные ключи
- **JSON API** `/api/*`: providers, квоты, SSE-события, управление ключами — всегда доступен
- **Дашборд** `/dashboard` (опционально): Sycamore (Rust→WASM) SPA поверх JSON API.
  Рантайм: `[server] dashboard = false`. Сборка без UI: `cargo build --no-default-features`.
  Сборка UI: `cd ui && trunk build --release`
- **FIM-эндпоинт** `/v1/fim/completions` (+ алиас `/v1/completions`) для IDE-автодополнения
- **Стриминг** без буферизации во всех режимах (SSE→SSE для gemini/antigravity с трансляцией)
- **Tool calls**: полный цикл (tools, tool_choice, параллельные вызовы, functionResponse)
- **Thinking**: reasoning_effort → thinkingConfig, мысли отдаются как reasoning_content,
  thoughtSignature захватывается и реплеится обратно (Gemini 3)

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
