# Проверенное исследование: водяные знаки в тексте LLM

**Дата проверки:** 2026-08-16
**Область:** только текстовые файлы, включая Markdown и текст внутри исходного кода
**Провайдеры:** Anthropic, Google и OpenAI
**Цель:** определить, что локальная CLI-утилита может честно обнаружить без секретных ключей провайдера.

> Этот документ не является юридической консультацией. Обнаруженная аномалия Unicode не доказывает использование ИИ, а отсутствие обнаруженного сигнала не доказывает человеческое авторство.

## 1. Итог проверки

Локальный детектор без ключей провайдера может надёжно обнаруживать только наблюдаемые сигналы в представлении текста:

- невидимые и управляющие символы Unicode;
- необычные пробелы и их подозрительные распределения;
- bidi controls, Unicode tags и variation selectors;
- смешение визуально похожих символов разных письменностей;
- отдельные известные стеганографические каналы.

Он **не может надёжно определить** наличие закрытого statistical/token-sampling watermark в произвольном тексте Claude или Gemini. Для этого нужны как минимум алгоритм, tokenizer, конфигурация и ключ либо официальный provider detector.

Поэтому корректный результат сканирования формулируется так:

> No supported surface signal detected; statistical watermark status is indeterminate.

Формулировки `clean`, `human-written`, `infected` и общий `is_ai: bool` технически неверны.

## 2. Подтверждённое состояние провайдеров

### 2.1. Anthropic

Anthropic официально сообщает следующее:

- модели Claude, выпущенные 2 августа 2026 года или позже, получают machine-readable marking при запуске;
- watermark встраивается непосредственно в текст на уровне модели;
- он переносится при копировании и вставке и может переживать часть изменений;
- механизм обнаружения и техническая документация ещё публикуются;
- поддержка моделей, выпущенных до 2 августа, находится в процессе внедрения.

Claude Opus 5 был выпущен 24 июля 2026 года. Следовательно, он относится к переходной группе. На 11 августа Anthropic не опубликовала per-model status, который подтверждал бы наличие watermark именно в Opus 5. Официальная страница указывает, что старые модели ещё переводятся на marking; вывод «в Opus 5, вероятно, пока нет watermark» разумен, но не является окончательно подтверждённым фактом.

Источники:

- [How Claude marks AI-generated content](https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content)
- [Anthropic release notes: Claude Opus 5, July 24, 2026](https://docs.claude.com/en/release-notes/overview)

### 2.2. Google Gemini / SynthID Text

Google подтверждает, что SynthID Text:

- применяется к текстам в Gemini app и web experience;
- изменяет распределение токенов во время генерации с помощью секретной конфигурации g-функций;
- обнаруживается вероятностно;
- хуже работает на коротких и low-entropy ответах;
- ослабляется при глубоком переписывании и переводе.

Открытая реализация предназначена прежде всего для разработчика, который сам встраивает watermark и владеет конфигурацией. Она не предоставляет ключи Google и не превращается в универсальный detector текстов Gemini. Публично описанная проверка через Gemini относится к изображениям, видео и аудио; официального публичного verifier для произвольного вставленного текста Gemini в проверенных источниках нет.

Источники:

- [Google AI: SynthID Text](https://ai.google.dev/responsible/docs/safeguards/synthid)
- [Google DeepMind: SynthID](https://deepmind.google/technologies/synthid/)
- [Scalable watermarking for identifying large language model outputs](https://www.nature.com/articles/s41586-024-08025-4)

### 2.3. OpenAI

В официальной документации OpenAI подтверждены provenance-проверки C2PA/SynthID для изображений и аудио. Публичного официального описания intentional statistical watermark для обычного текстового вывода или API его обнаружения в проверенной документации нет.

Наблюдения про необычные пробелы в отдельных ответах нельзя автоматически считать intentional watermark. Они полезны как тестовые случаи для Unicode-сканера, но не как атрибуция OpenAI.

Источник:

- [OpenAI Content provenance](https://developers.openai.com/api/docs/guides/content-provenance)

## 3. EU AI Act

Article 50(2) требует, чтобы providers систем, генерирующих synthetic text, обеспечивали machine-readable marking и detectability, насколько это технически осуществимо. Article 50 применяется с 2 августа 2026 года.

Для generative AI systems, выведенных на рынок до этой даты, принята переходная дата 2 декабря 2026 года. Этот срок следует ссылать на последующие Guidelines/AI Omnibus, а не приписывать исходному тексту Article 50.

Важно учитывать исключение: Article 50(2) не применяется в той мере, в которой система выполняет стандартное assistive editing или существенно не изменяет входные данные либо их семантику. Провайдер при этом может добровольно маркировать более широкий набор результатов.

За нарушение Article 50 предусмотрены штрафы до EUR 15 млн или 3% мирового годового оборота; правила для SMEs и конкретное назначение санкции имеют дополнительные условия.

Источники:

- [EU AI Act, Articles 50, 99 and 113](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401689)
- [European Commission Guidelines on Article 50](https://ec.europa.eu/newsroom/dae/redirection/document/131215)
- [Code of Practice on Transparency of AI-generated Content](https://digital-strategy.ec.europa.eu/en/policies/code-practice-ai-generated-content)

## 4. Типы текстовых сигналов

### 4.1. Statistical/token-sampling watermark

Примеры: KGW red-green, SynthID Text и fixed-sampling families.

Общая схема:

1. Секретный ключ и предыдущий контекст определяют score или предпочтительное подмножество токенов.
2. Во время генерации logits либо sampling слегка изменяются.
3. Detector с тем же tokenizer, алгоритмом, параметрами и ключом вычисляет статистический score.
4. Результат зависит от длины текста и возвращает confidence, а не абсолютное доказательство.

Без ключа нельзя восстановить секретное разбиение vocabulary или g-функции. Частотный анализ слов, perplexity, stylometry и generic AI classifiers не являются заменой detector.

### 4.2. Surface/Unicode steganography

Сигнал кодируется непосредственно в последовательности code points или bytes:

- zero-width characters;
- bidi embeddings, overrides и isolates;
- Unicode tag characters;
- variation selectors;
- разные виды визуально одинаковых пробелов;
- homoglyphs и mixed-script identifiers/words;
- combining marks и normalization-sensitive representations;
- BOM и другие управляющие символы в неожиданных позициях.

Эти признаки можно обнаруживать локально, но они не обязательно являются watermark. Многие из них законны в emoji, RTL-тексте, персидском, арабском, индийских письменностях, CJK и профессиональной типографике.

### 4.3. Black-box model probing

Black-box experiments многократно вызывают один и тот же endpoint и ищут статистический fingerprint семейства watermarking. Они могут помочь ответить на вопрос «использует ли сервис определённый класс watermark», но не дают надёжного ответа о происхождении отдельно взятого Markdown-файла.

Источник:

- [ETH SRI: Black-Box Detection of Language Model Watermarks](https://github.com/eth-sri/watermark-detection)

## 5. Что означает finding

| Результат | Допустимая интерпретация |
|---|---|
| Zero-width/tag/bidi finding | В тексте есть наблюдаемый необычный code point |
| Mixed Latin/Cyrillic/Greek token | Возможен homoglyph channel или случайная ошибка раскладки |
| Non-ASCII spaces | Типографика либо потенциальный пробельный канал |
| No surface findings | Поддерживаемые scanner rules ничего не нашли |
| Statistical status: indeterminate | Proprietary watermark не проверен |

Недопустимые выводы:

- «это точно написал Gemini/Claude»;
- «watermark полностью отсутствует»;
- «текст написал человек»;
- «файл заражён».

## 6. Требования к `wmtext`

### 6.1. Назначение

`wmtext` – локальный CLI для агентов и CI. Команда `scan` только обнаруживает наблюдаемые текстовые сигналы. Команда `sanitize` удаляет распознанные invisible/format и private-use code points, но не изменяет лексику или token choices.

### 6.2. Вход

- один или несколько файлов или каталогов;
- UTF-8 text-like files;
- явный файл сканируется независимо от расширения;
- при обходе каталога используются allowlisted extensions и правила `.gitignore`;
- symlinks не обходятся;
- бинарные, слишком большие и не-UTF-8 файлы пропускаются с явным статусом.

### 6.3. Действующие правила MVP

1. Unexpected zero-width and format controls.
2. Bidi controls.
3. Unicode tags.
4. Variation-selector channels and unusual density.
5. Context-aware ZWJ/ZWNJ detection.
6. Non-ASCII whitespace distribution.
7. Mixed Latin/Cyrillic/Greek words.
8. Suspicious runs of combining marks.
9. Non-NFC representation as informational evidence.
10. Trailing spaces and tabs as a possible line-level whitespace channel.

Правила обязаны хранить `rule_id`, severity, позицию, code point, контекст и ограничение интерпретации.

### 6.4. Выход

- human-readable report;
- versioned JSON schema;
- стабильные exit codes:
  - `0`: сканирование завершено, findings выше выбранного threshold нет;
  - `1`: findings достигли threshold;
  - `2`: operational error.

JSON не должен содержать поля `is_ai`, `clean` или `infected`.

### 6.5. Privacy и безопасность

- полностью локальная работа;
- отсутствие сетевых запросов;
- явный выбор `--dry-run`, отдельного output path или `--in-place` с backup;
- ограничение размера файла и количества findings;
- контекст findings должен быть коротким и безопасно экранированным;
- провайдерские detector APIs могут появиться позднее как отдельные adapters.

## 7. Стек

Production CLI реализуется на Rust:

- `clap` для CLI;
- `serde` и `serde_json` для versioned output;
- `ignore` для безопасного обхода каталогов с учётом `.gitignore`;
- `unicode-normalization` для NFC checks;
- собственные небольшие таблицы правил для high-signal code points;
- unit tests и property-oriented тестовые случаи без Python runtime.

UTS #39 confusable tables могут быть добавлены отдельной версионированной зависимостью после MVP. В первой версии mixed-script detection является явной эвристикой, а не полным confusable detector.

## 8. Non-goals первой версии

- обнаружение или удаление statistical/token-sampling watermark;
- автоматическое переписывание прозы, комментариев, docstrings или identifiers;
- определение автора или провайдера;
- generic AI detection;
- проверка закрытого SynthID/Claude watermark без ключа;
- AST-анализ кода;
- GUI;
- Python/Transformers/PyTorch;
- C2PA и любые медиаданные.

## 9. План валидации на Gemini

Для исследования нужен корпус, а не один текст:

- несколько длинных high-entropy ответов;
- несколько constrained factual ответов;
- русский, английский и смешанный текст;
- Markdown с таблицами, списками и code fences;
- несколько независимых генераций одного prompt;
- файлы, сохранённые без ручной правки и normalization.

`wmtext` сначала проверит corpus на surface signals. Если ничего не будет найдено, корректный вывод – «Gemini не использовала поддерживаемые Unicode-каналы в этом корпусе». Это не опровергает наличие SynthID token-sampling watermark.

## 10. Проверенные академические основы

- [A Watermark for Large Language Models](https://arxiv.org/abs/2301.10226)
- [Scalable watermarking for identifying large language model outputs](https://www.nature.com/articles/s41586-024-08025-4)
- [Google DeepMind synthid-text reference implementation](https://github.com/google-deepmind/synthid-text)
- [Black-Box Detection of Language Model Watermarks](https://github.com/eth-sri/watermark-detection)

## 11. Главный принцип

> Детектор сообщает наблюдаемое доказательство и границы метода, а не выдаёт бинарный вердикт о происхождении текста.
