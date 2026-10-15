# netSlider — руководство пользователя

[English version](USER_GUIDE.md)

Это руководство для тех, кто хочет **исследовать недокументированный бинарный TCP-протокол** с помощью netSlider: открыть захват (capture), сформулировать гипотезы о framing (разбиении на сообщения) и полях, проверить их и передать портативный проект другому человеку.

Подробности установки, Docker demo stand, сборка Windows zip и рецепты для разработчиков — в [RUN.md](RUN.md). Архитектура — в [ARCHITECTURE.md](ARCHITECTURE.md).

Имена меню, команд, файлов и технические идентификаторы ниже оставлены на английском, как в интерфейсе.

---

## 1. Что это такое

netSlider — **локальная настольная лаборатория протоколов**. Вы приносите:

- PCAP или PCAPNG с трафиком Ethernet + TCP/IPv4, и по желанию
- **action log** (журнал действий клиента: read / set / measure),

а инструмент помогает собрать направленные TCP-потоки (directed streams), смотреть байты с provenance (связью обратно к пакетам), писать **interpretation** (интерпретацию: YAML, опционально Python), проверять её на корпусе захватов и экспортировать отчёт плюс переиспользуемый проект.

Работает офлайн: без облака, без UI для live capture, без расшифровки TLS.

Сделано для передачи исследования: другой инженер должен открыть вашу папку проекта и пройти тот же путь от выводов обратно к байтам.

---

## 2. Зачем этим пользоваться

TCP отдаёт **поток байт**, а не готовые прикладные сообщения. Один кадр может растянуться на несколько пакетов; в одном пакете может лежать несколько кадров. Ретрансмиты и переупорядочивание не должны «придумать» байты.

Значение, которое появилось после «set 21», — только **hypothesis** (гипотеза), пока оно не выдержит другие параметры и counterexamples (контрпримеры).

netSlider держит эти различия на виду:

| Понятие | Смысл |
|---------|--------|
| Observation | То, что видно в байтах или в логе |
| Rule result | То, что извлекает interpretation |
| Hypothesis | Заявленный смысл — ещё на проверке |
| Counterexample | Конкретные данные, где правило ломается |

Имеет смысл, если нужно:

1. Честно собирать потоки (`UNKNOWN` / `AMBIGUOUS` вместо угаданных байт).
2. Сопоставить трафик с тем, что делал оператор.
3. Писать и перепроверять правила framing и полей на нескольких захватах.
4. Отдать портативный проект + Markdown-отчёт + машиночитаемую интерпретацию для CLI.

**Вне области:** UI live capture, расшифровка TLS, кодеки сжатия, полное восстановление state machine, разбор non-Ethernet / IPv6 как прикладного payload (такие случаи диагностируются, но не разбираются как app data).

---

## 3. Установка и запуск

### Из исходников (Python 3.11+)

```bash
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

netslider                  # GUI
netslider-cli --help       # headless-инструменты
```

### Windows zip (на целевом ПК Python не нужен)

Сборка: `.\scripts\build_windows.ps1`, затем `NetSlider.exe` из zip (или `NetSlider.bat` после локальной сборки). **Не** запускайте EXE из `build\netslider\`. Подробности: [RUN.md](RUN.md).

### Захваты

| Формат | Требование |
|--------|------------|
| Классический `.pcap` (demo / `samples/lab`) | Встроенный парсер — TShark не нужен |
| `.pcapng` | Wireshark / **TShark** в `PATH` |

Полная установка, генерация demo corpus и Docker stand: [RUN.md](RUN.md).

---

## 4. Тур за пять минут (`samples/lab`)

В репозитории уже есть готовый портативный проект. Docker не нужен.

1. Запустите GUI: `netslider`.
2. **File → Open Project…** и выберите `samples/lab`.
3. В списке Captures выберите `captures/main.pcap`.
4. Toolbar: **Load selected capture** (или double-click). Дождитесь появления sessions.
5. Выберите session. Установите **Direction** (`A → B` или `B → A`). Заполнятся hex и packets.
6. Кликните байт в hex или строку пакета — label provenance покажет stream offset ↔ packet.
7. Нижняя вкладка **Interpret / Validate**:
   - Откройте interpretation проекта в file combo или нажмите **Load demo YAML**.
   - **Apply to stream** — появятся разобранные сообщения и поля.
   - Отметьте захваты корпуса → **Validate corpus**.
8. Вкладка **Report**: заполните rationale → **Refresh preview** → **Export…**  
   (interpretation должна быть **сохранена на диск** в проекте — одного буфера редактора мало).
9. По желанию: **File → Package Project as Zip…**, чтобы отдать папку.

Вы прошли один research loop: load → inspect → apply → validate → export.

---

## 5. Анатомия workbench

```text
+------------------+---------------------------+--------------------+
| Project / path   | Direction A→B / B→A       | Packets table      |
| Captures list    | Hex dump                  | Provenance label   |
| Sessions list    | Defects (UNKNOWN/…)       |                    |
+------------------+---------------------------+--------------------+
| Investigate | Interpret / Validate | Observations | Report        |
+-------------------------------------------------------------------+
```

| Область | Роль |
|---------|------|
| Captures | Файлы портативного проекта (`captures/`) |
| Sessions | TCP-соединения (5-tuple + instance) в загруженном захвате |
| Direction | Одна направленная половина соединения; hex показывает только этот поток |
| Hex dump | Собранный payload выбранного направления |
| Defects | Пробелы / конфликты как `UNKNOWN` или `AMBIGUOUS` |
| Packets | Исходные кадры; клик связывает их с байтами потока |
| Provenance | Связь от диапазона байт обратно к пакетам и смещениям |

**Меню File:** New / Open / Save Project → Import Capture / Action Log / Interpretation → Open Capture in Workspace → Export Report → Package Project as Zip → Quit.

**Toolbar:** Load selected capture · Open action log… · Cancel load.

---

## 6. Investigate

Нижняя вкладка **Investigate** — три инструмента. Используйте их **до** того, как зафиксируете interpretation.

### Actions

Сопоставление action log (метки времени read / set / measure) с захватом.

- Если в проекте уже есть action log, он может подгрузиться сам.
- Или toolbar **Open action log…**.
- Выберите действие, чтобы прыгнуть к связанным пакетам / диапазонам потока (режимы time window в панели).

### Framing

Гипотезы о границах сообщений:

- **Find magic** (в demo по умолчанию `MD01`).
- **Probe / Auto grid** для схем length-prefix.
- Byte **histogram** — подсказки по разделителям.

### Compare

Выделите диапазон в hex → **Mark as A** / **Mark as B** → unified diff двух диапазонов. Удобно, когда два сообщения должны отличаться только полем setpoint.

---

## 7. Interpretations

Вкладка **Interpret / Validate**.

**Interpretation** описывает, как резать поток на сообщения и декодировать поля. Предпочтительно декларативный **YAML**. Опциональные хуки на **Python** — только когда YAML не хватает.

### Загрузка и Apply

1. Выберите файл в combo (папка проекта `interpretations/`) или **Load demo YAML**.
2. При необходимости правьте буфер.
3. **Apply to stream** — на текущие session + direction.
4. **Save to project**, когда нужны история validate и экспорт отчёта по этой версии.

Цвета / status полей показывают observation, rule, hypothesis или unverified (см. легенду панели).

### Минимальная форма YAML

```yaml
id: my_proto_v1
description: optional
framing:
  type: length_prefixed
  header:
    magic: MD01
    magic_offset: 0
    len_offset: 4
    len_size: 2          # 1, 2 или 4
    endian: be           # be | le
    len_includes_header: false
messages:
  - name: example
    when: { field: opcode, eq: 0x01 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: param_id, offset: 1, type: u16le, hypothesis: "optional claim" }
unknown_policy: leave_unparsed
```

Готовый пример: [`samples/lab/interpretations/device_v1.yaml`](../samples/lab/interpretations/device_v1.yaml).

### Типы полей

`u8` / `i8`, `u16le` / `u16be`, `i16*`, `u32*` / `i32*`, `bytes` / `rest` / `raw`, `bytes:N`.

Опционально у поля: текст `hypothesis` и/или `status`: `observation` | `rule` | `hypothesis` | `unverified`.

### Python-хуки (advanced)

Рядом с YAML файл `.py` может экспортировать:

- `frame(stream) -> [(start, end), ...]`
- `parse(message) -> dict`

Запуск в ограниченном subprocess с timeout. Пример: `samples/lab/interpretations/device_v1_frame.py`.

---

## 8. Validate на корпусе

Всё ещё на **Interpret / Validate**:

1. Отметьте, какие захваты проекта включать.
2. При необходимости — оба направления / все sessions.
3. **Validate corpus** (асинхронно; при необходимости **Cancel**).

### Виды hit

| Kind | Смысл |
|------|--------|
| `ok` | Правило применилось чисто |
| `contradict` | Правило расходится со status спана или ожиданиями decode |
| `uncovered` | Байты / области, которые interpretation не покрыла как ожидалось |
| `unknown` | Спан потока `UNKNOWN` (пробел / нет данных) |
| `ambiguous` | Спан потока `AMBIGUOUS` (конфликт overlap) |
| `inapplicable` | Захват / session не подходит для этой проверки |

Фильтруйте hits в панели; клик по hit прыгает в hex (может перезагрузить другой захват).

### Stale results

Если правите interpretation после validate, сохранённые результаты помечаются **stale** (изменился hash interpretation). Перед доверием к цифрам перезапустите validate.

---

## 9. Observations

Вкладка **Observations**.

Человеческие заметки, привязанные к текущему выделению:

- capture, session, direction, stream offset, length

**Save observation** пишет JSON в `observations/`. Можно листать сохранённые заметки и прыгать к диапазону. Нужен открытый проект.

Удобно для заметок вроде «похоже на length field», которые ещё не оформлены как YAML-правила.

---

## 10. Экспорт отчёта и package zip

### Report

Вкладка **Report** (или **File → Export Report**):

1. Title, rationale, scope, open questions.
2. **Refresh preview**.
3. **Export…** в папку — Markdown плюс машиночитаемый JSON interpretation (basename `netslider_report`).

Нужны открытый проект **и** файл interpretation на диске в проекте (import или **Save to project**).

### Package zip

**File → Package Project as Zip…** собирает zip портативного каталога проекта (только относительные пути). Распакуйте в другом месте и **Open Project** — исходники остаются неизменяемыми копиями в `captures/` и т.д.

---

## 11. Свой собственный захват

| Действие | Эффект |
|----------|--------|
| **File → Import Capture…** | Копия в `captures/` с relative path в манифесте (портативно) |
| **File → Import Action Log…** | Копия в `action_logs/` |
| **File → Import Interpretation…** | Копия в `interpretations/` |
| **File → Open Capture in Workspace…** | Загрузка для осмотра без импорта в проект |

Для validate, observations, report и zip handoff предпочтителен **Import**. Workspace-only подходит для быстрого взгляда.

Типичный поток:

1. **File → New Project…** (пустая папка) или открыть существующий.
2. Import capture (+ action log, если есть).
3. Load capture → session / direction → Investigate → YAML → Validate на `extra` → Report → Zip.

---

## 12. Шпаргалка CLI

Тот же research loop без GUI. Точка входа: `netslider-cli` (или `python -m netslider.cli.main`).

```bash
netslider-cli project-info ./samples/lab

netslider-cli apply ./samples/lab/interpretations/device_v1.yaml \
  ./samples/lab/captures/extra.pcap

netslider-cli validate --project ./samples/lab

netslider-cli report --project ./samples/lab \
  --pcap ./samples/lab/captures/main.pcap --out ./out

netslider-cli project-package ./samples/lab --out ./lab.zip
```

Больше рецептов (inspect, align, demo-corpus): [RUN.md](RUN.md).

---

## 13. Глоссарий

| Термин | В UI |
|--------|------|
| Session | Одно TCP-соединение в списке Sessions |
| Direction | Половина потока `A → B` или `B → A` в hex |
| Provenance | Отображение байт потока обратно на пакеты |
| `UNKNOWN` | Пропущенный / дырявый payload — никогда не заполняется нулями |
| `AMBIGUOUS` | Конфликтующий overlapping payload |
| Interpretation | YAML (и опционально Python), который режет и парсит сообщения |
| Apply | Запуск interpretation на текущем направленном потоке |
| Validate | Прогон по одному или нескольким захватам проекта; счётчики hits |
| Stale | Validation больше не соответствует hash текущей interpretation |
| Portable project | Папка с `project.netslider.json` и только relative paths |
| Observation (заметка) | Аннотация человека на вкладке Observations |
| Hypothesis | Утверждение о поле ещё на проверке (`hypothesis:` в YAML / status) |

---

## 14. Troubleshooting

| Симптом | Что попробовать |
|---------|-----------------|
| Пустой hex после load | Выберите session и direction; у части направлений payload мало или нет |
| PCAPNG не импортируется | Установите Wireshark, чтобы `tshark` был в `PATH` |
| Загрузка зависла / не тот файл | **Cancel load**, затем load снова |
| Export Report отказывается | Save или import interpretation в проект (файл на диске, не только editor) |
| Validate странный после правок | Перезапустите Validate; прошлый прогон может быть **stale** |
| Предупреждения об absolute path после переноса | Держите relative imports; откройте папку проекта заново; см. `project-info` / portability в [RUN.md](RUN.md) |
| Windows SmartScreen / медленный первый запуск | Нормально для unsigned zip; Defender может один раз просканировать `dist` |
| Не тот путь к EXE | `dist\NetSlider\NetSlider.exe` или `NetSlider.bat`, никогда `build\netslider\` |

---

## 15. Приложение — справка по YAML и примеры

**Обязательно:** `id`, `framing` (сейчас `type: length_prefixed`), `messages`.

**Поля framing header:** `magic`, `magic_offset`, `len_offset`, `len_size` (1/2/4), `endian` (`be`|`le`), `len_includes_header`.

**Message `when`:** `{ field: <name>, eq: <value> }` (и связанные clauses из схемы).

**`unknown_policy`:** по умолчанию `leave_unparsed`.

**Примеры:**

- [`samples/lab/interpretations/device_v1.yaml`](../samples/lab/interpretations/device_v1.yaml)
- [`samples/lab/interpretations/device_v1_frame.py`](../samples/lab/interpretations/device_v1_frame.py)
- Копия в demo corpus: `netslider/demo/corpus/interpretations/`

**Research loop (напоминание):**

```text
PCAP + action log
      → session / directed stream (hex + provenance)
      → framing hypotheses
      → YAML / Python interpretation
      → corpus validate → refine on counterexamples
      → portable project + report + netslider-cli apply
```
