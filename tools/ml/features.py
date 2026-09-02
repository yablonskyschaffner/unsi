"""Feature-vector schema reference.

The .NET runtime in `AntiStealer.Core/MlClassifier.cs` extracts a
deterministic 64-float vector from every `AnalysisResult`. This file
documents the schema so anyone exporting training data from a corpus
(or hand-crafting test rows) can stay in sync.

Layout:

    0..15   numeric features (each normalised to [0, 1]):
        0  StringHits.Count / 200
        1  SectionNames.Count / 20
        2  SuspiciousApiHits.Count / 30
        3  CustomHeuristicHits.Count / 100
        4  UrlsFound.Count / 20
        5  Ipv4Hits.Count / 20
        6  EmailHits.Count / 10
        7  CryptoWalletHits.Count / 5
        8  JwtHits.Count / 5
        9  TelegramBotTokenHits.Count / 3
        10 DiscordTokenHits.Count / 3
        11 IsDll (0 / 1)
        12 IsDotNetLikely (0 / 1)
        13 IsSigned (0 / 1)
        14 PackerHints.Count > 0 (0 / 1)
        15 ExecutableWritableSections.Count > 0 (0 / 1)

    16..31  one-hot file-type bucket (Other = 31):
        16 PE
        17 DLL
        18 Mach-O
        19 ELF
        20 APK
        21 IPA
        22 ZIP
        23 CRX
        24 Word
        25 Excel
        26 RTF
        27 OOXML
        28 JS
        29 PHP
        30 HTML
        31 Other

    32..63  hashed bag-of-strings (32 FNV-1a buckets, L1-normalised
            over the bucket sum). Tokens are lower-cased alpha-num
            runs of length ≥ 3 extracted from `r.StringHits`.

Output column ordering (CSV header):

    label,f0,f1,...,f63

The `label` column is the family name (e.g. "RedLine", "Lumma",
"clean"). Both `train.py` and the runtime classifier preserve the
original feature ordering.
"""

NUMERIC_FEATURES: list[tuple[str, str]] = [
    ("string_hits",                "StringHits.Count / 200"),
    ("section_names",              "SectionNames.Count / 20"),
    ("suspicious_apis",            "SuspiciousApiHits.Count / 30"),
    ("custom_heuristics",          "CustomHeuristicHits.Count / 100"),
    ("urls_found",                 "UrlsFound.Count / 20"),
    ("ipv4_hits",                  "Ipv4Hits.Count / 20"),
    ("email_hits",                 "EmailHits.Count / 10"),
    ("crypto_wallet_hits",         "CryptoWalletHits.Count / 5"),
    ("jwt_hits",                   "JwtHits.Count / 5"),
    ("telegram_bot_token_hits",    "TelegramBotTokenHits.Count / 3"),
    ("discord_token_hits",         "DiscordTokenHits.Count / 3"),
    ("is_dll",                     "IsDll"),
    ("is_dotnet",                  "IsDotNetLikely"),
    ("is_signed",                  "IsSigned"),
    ("has_packer",                 "PackerHints.Count > 0"),
    ("has_rwx",                    "ExecutableWritableSections.Count > 0"),
]

FILE_TYPE_BUCKETS = [
    "PE", "DLL", "Mach-O", "ELF", "APK", "IPA", "ZIP", "CRX",
    "Word", "Excel", "RTF", "OOXML", "JS", "PHP", "HTML", "Other",
]

EMBEDDING_DIM = 32
FEATURE_DIM = 64
