# YARA rules

Когда AntiStealer запускается, он автоматически подхватывает `*.yar` / `*.yara`
из следующих директорий (в этом порядке):

1. `%APPDATA%\AntiStealer\yara\` — ваши локальные правила.
2. `./yara-rules/` — правила, лежащие рядом с `AntiStealerOneExe.exe`.
3. `./rules/` — альтернативное имя.

Чтобы YARA реально отработал, в PATH (или рядом с `.exe`) должен быть бинарь
`yara64.exe` / `yara.exe`. Скачать: <https://github.com/VirusTotal/yara/releases>.

Если YARA не найден — ничего не падает, просто секция `== YARA matches ==`
не появляется в отчёте.

Хитрости:
- Каждый хит увеличивает `CredentialTheft` capability score на 12 (до +30 суммарно).
- Первые 64 правила и первые 64 хита на файл — hard-cap.
- На каждое правило стоит 8-секундный timeout.

В этом каталоге лежит минимальный набор стартовых правил для популярных
семейств (RedLine / Vidar / Lumma / Raccoon / StealC) и общий
`Stealer_Generic_BrowserDbs`. Расширяйте / заменяйте своими community-правилами.
