# Hashcat クイックリファレンス

> **スコープ**: パスワードハッシュのクラックツール。各種ハッシュモード・ルールファイル・マスクアタックのクイックリファレンス。GPU が使える環境では hashcat、CPU のみの場合は john を代替として使う。

## 着火条件

- SMB / LDAP / SAM / LSASS / DB から NTLM ハッシュ・パスワードハッシュを取得した
- Kerberoasting / ASREPRoasting でハッシュを取得した
- Web アプリの DB から PBKDF2 / bcrypt / MD5 等のハッシュを取得した

---

## エラーが出たらまずここを確認

| エラーメッセージ | 原因 | 見るべきセクション |
|----------------|------|-----------------|
| `Separator unmatched` | ハッシュ形式がモードと合っていない | → 「ハッシュ形式の特定方法」 |
| `No hashes loaded` | フォーマットが完全に違う / ファイルが空 | → 「ハッシュ形式の特定方法」 |
| `Token length exception` | ハッシュの長さがモードと不一致 | → 「ハッシュ形式の特定方法」→ モードを再確認 |
| 速度が極端に遅い（< 100 H/s） | 反復回数が多い / GPU未使用 | → 「反復回数が多くて極端に遅い場合の対処」（Flask/Werkzeug セクション） |

---

## よく使うハッシュモード

| モード番号 | ハッシュタイプ | 取得方法 |
|-----------|-------------|---------|
| `13100` | Kerberos TGS-REP etype 23（RC4）| Kerberoasting |
| `19700` | Kerberos TGS-REP etype 17（AES128）| Kerberoasting |
| `19800` | Kerberos TGS-REP etype 18（AES256）| Kerberoasting |
| `18200` | Kerberos AS-REP etype 23 | ASREPRoasting |
| `1000` | NTLM | secretsdump / Pass-The-Hash |
| `5600` | NetNTLMv2 | Responder / NTLM リレー |
| `10900` | PBKDF2-HMAC-SHA256 | Grafana DB / 各種Webアプリ |
| `20` | md5($salt.$pass) | CMS Made Simple 等 |
| `0` | MD5（ソルトなし） | 各種 |
| `100` | SHA1 | 各種 |

---

## 基本的なクラックコマンド

```bash
# Kerberoasting ハッシュ
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# ASREPRoasting ハッシュ
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt

# NTLM ハッシュ
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## ルールを使った強化

```bash
# best64 ルール（基本的な変形）
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# OneRuleToRuleThemAll（強力）
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```

---

## マスクアタック（パスワードパターンがわかっている場合）

```bash
# ?u=大文字, ?l=小文字, ?d=数字, ?s=記号, ?a=全文字
# 例: 大文字1文字 + 小文字7文字 + 数字2文字
hashcat -m 13100 hashes.txt -a 3 ?u?l?l?l?l?l?l?l?d?d

# 既知のプレフィックス + 数字4桁
hashcat -m 13100 hashes.txt -a 3 Password?d?d?d?d
```

---

## よく使うオプション

| オプション | 説明 |
|-----------|------|
| `-m [MODE]` | ハッシュモード |
| `-a 0` | 辞書攻撃（デフォルト） |
| `-a 3` | マスク攻撃 |
| `-a 6` | 辞書 + マスクのハイブリッド |
| `-r [FILE]` | ルールファイルを適用 |
| `--show` | クラック済みハッシュを表示 |
| `-o [FILE]` | クラック結果をファイルに保存 |
| `--force` | 警告を無視して強制実行 |
| `-w 3` | ワークロードプロファイル（高） |

---

## GPU の使用確認と高速化

```bash
# GPU デバイスの確認
hashcat -I

# GPU を使ったクラック（自動で GPU を使用）
hashcat -m 13100 hashes.txt rockyou.txt -w 4 -O
```

---

## クラック済みハッシュの確認

```bash
# クラック済みを表示
hashcat -m 13100 hashes.txt --show

# ポットファイルの確認（クラック済みハッシュのキャッシュ）
cat ~/.hashcat/hashcat.potfile
```

---

## ハッシュ形式の特定方法

### 形式を「読む」

多くのWebフレームワークはハッシュの先頭にアルゴリズム名を埋め込む。**接頭辞を見れば形式がほぼわかる。**

| ハッシュの形式 | アルゴリズム | 対応 hashcat モード |
|----------------|-------------|---------------------|
| `$2y$...` / `$2b$...` | bcrypt | `3200` |
| `sha256:ITER:SALT:HASH` | PBKDF2-HMAC-SHA256（Grafana等） | `10900` |
| `pbkdf2_sha256$ITER$SALT$HASH` | Django PBKDF2-SHA256 | `10000` |
| `pbkdf2:sha256:ITER$SALT$HASH` | Flask / Werkzeug PBKDF2 | `10000`（変換が必要） |
| `md5crypt` / `$1$...` | MD5-crypt | `500` |
| `$6$...` | SHA-512-crypt（Linux /etc/shadow 等） | `1800` |
| 32文字の16進数のみ | MD5（ソルトなし） | `0` |
| 40文字の16進数のみ | SHA1（ソルトなし） | `100` |
| 64文字の16進数のみ | SHA256（ソルトなし） | `1400` |

### 形式から読めないときは `hashid` を使う

```bash
# [Attacker] hashid はペネトレ用Linuxディストリ標準搭載
hashid '[ハッシュ文字列]'

# 例
hashid 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4...'
```

### kedalab に記載のないモードに当たったときの調べ方

```bash
# hashcat の全モード例を検索（キーワードで絞る）
hashcat --example-hashes | grep -i "pbkdf2"
hashcat --example-hashes | grep -i "django"
hashcat --example-hashes | grep -B2 "pbkdf2_sha256"
# → 対応するモード番号と、hashcat に渡す形式例が確認できる
```

Webでの確認：`https://hashcat.net/wiki/doku.php?id=hashcat`（Example Hashes のページ）

---

## Flask / Werkzeug PBKDF2-SHA256（mode 10000）— Pythonベース Webアプリ

### 着火条件
- WebアプリのDBから `pbkdf2:sha256:ITERATIONS$SALT$HASH_HEX` 形式のハッシュを取得した
- アプリが Python + Flask / Werkzeug で実装されている（`app.py` 等のソースコードから確認できることがある）

### ハッシュ形式の識別

Werkzeug の形式は Django と似ているが**区切り文字が異なる**。

| フレームワーク | 形式 |
|----------------|------|
| Flask / Werkzeug | `pbkdf2:sha256:600000$SALT$HASH_HEX`（ドルマーク2個、ハッシュが16進数） |
| Django | `pbkdf2_sha256$600000$SALT$HASH_B64`（ドルマーク3個、ハッシュがBase64） |

Werkzeug 形式を hashcat に渡す場合は Django 形式（mode 10000）に変換する必要がある。

### Django 形式への変換（mode 10000 で使うため）

```python
# [Attacker] Python で変換する
import base64, binascii

# DBから取得したハッシュ文字列（例）
werkzeug_hash = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"

# パースして変換
parts = werkzeug_hash.split("$")
# parts[0] = "pbkdf2:sha256:600000"
# parts[1] = "SALT"
# parts[2] = "HASH_HEX"

alg_parts   = parts[0].split(":")   # ["pbkdf2", "sha256", "600000"]
iterations  = alg_parts[2]          # "600000"
salt        = parts[1]              # "AMtzteQIG7yAbZIa"
hash_hex    = parts[2]              # "0673ad90..."

hash_b64    = base64.b64encode(bytes.fromhex(hash_hex)).decode()

django_fmt  = f"pbkdf2_sha256${iterations}${salt}${hash_b64}"
print(django_fmt)
# → pbkdf2_sha256$600000$AMtzteQIG7yAbZIa$BnOt...
```

### クラックコマンド

```bash
# 変換結果をファイルに保存してから実行
echo 'pbkdf2_sha256$600000$[SALT]$[HASH_B64]' > hash.txt
hashcat -m 10000 hash.txt /usr/share/wordlists/rockyou.txt
```

### 反復回数が多くて極端に遅い場合の対処

PBKDF2 の反復回数（iterations）が多いほどクラックは遅くなる。**10000回でも遅いが、600000回はさらに60倍遅い。** CPU のみの環境では2日以上かかることがある。

**まず試すべき代替手段（クラックをあきらめる前に）：**

```bash
# 1. 辞書を絞ってスピードを稼ぐ（よく使われるパスワード上位1000件）
head -n 1000 /usr/share/wordlists/rockyou.txt > top1000.txt
hashcat -m 10000 hash.txt top1000.txt

# 2. 同じDBの別ユーザー（一般ユーザー）のハッシュを試す
#    管理者より一般ユーザーのパスワードが弱い可能性がある
SELECT username, password_hash FROM users;   -- 全ユーザーのハッシュを取得

# 3. クラックできなければ別の侵入経路を探す
#    「ハッシュがクラックできない = 詰まり」ではない
```

**速度の目安（CPU のみ環境の場合）：**

| 反復回数 | 目安速度（CPU5コア） | rockyou.txt 全件の推定時間 |
|----------|---------------------|--------------------------|
| 10,000   | 約 700 H/s          | 約 6 時間 |
| 100,000  | 約 70 H/s           | 約 2.5 日 |
| 600,000  | 約 12 H/s           | 約 14 日 |

> GPU 環境では10〜100倍程度速くなる。VMではなく物理GPUが使える環境があれば使う。

### 注意点
- `Separator unmatched` エラーが出た場合、hashcat に渡しているハッシュ形式がモードに合っていない（変換が必要）
- mode 10900 と mode 10000 は似ているが**形式が異なる**。Werkzeug ハッシュに 10900 を使っても `No hashes loaded` になる
- 反復回数が多すぎてクラックを断念した場合は Webアプリへのログイン以外の経路（パスワードスプレー・別サービス）を探す

---

## MD5+Salt（mode 20）— CMS 等のWebアプリ

### 着火条件
- タイムベースブラインドSQLiなどでWebアプリのDBから **MD5ハッシュ** と **ソルト文字列** を別々に取得した
- ハッシュ形式が `md5(salt + password)` であることが判明している（例: CMS Made Simple）

### 観点・着眼点

**mode 0（MD5）と mode 20（md5($salt.$pass)）の違いを間違えると全くヒットしない。**
ソルトが存在する場合は必ず mode 20 を使う。ソルトの位置（前付き/後付き）もアプリによって異なる。

| モード | 計算式 |
|--------|--------|
| `0` | `md5(pass)` |
| `20` | `md5($salt.$pass)` ← ソルトが前 |
| `10` | `md5($pass.$salt)` ← ソルトが後 |

### Hashcat コマンド

```bash
# フォーマット: hash:salt
hashcat -m 20 "[HASH]:[SALT]" /usr/share/wordlists/rockyou.txt

# 例（CMS Made Simple から取得した場合）
hashcat -m 20 "[HASH_VALUE]:[SALT]" /usr/share/wordlists/rockyou.txt
```

### Python での手動クラック（hashcat が使えない環境）

```python
import hashlib

salt  = "取得したソルト"
hash_ = "取得したMD5ハッシュ"

with open("/usr/share/wordlists/rockyou.txt", errors="ignore") as f:
    for line in f:
        word = line.strip()
        candidate = hashlib.md5((salt + word).encode()).hexdigest()
        if candidate == hash_:
            print(f"[+] クラック成功: {word}")
            break
```

### 注意点
- ハッシュとソルトを hashcat に渡す形式は `[HASH]:[SALT]`（コロン区切り）
- `md5($pass.$salt)` の場合は mode `10` を使う（ソルトとパスワードの順序が逆）
- Python で実装する場合も `.encode()` を忘れるとバイト/文字列エラーになる

---

## PBKDF2-HMAC-SHA256（mode 10900）— Grafana 等のWebアプリ

### 着火条件
- Grafana の SQLite DB（`grafana.db`）からユーザーハッシュを取得した
- ハッシュが HEX 文字列、salt が別カラムに格納されている

### Hashcat 形式への変換

Grafana はパスワードを PBKDF2-HMAC-SHA256（10000 反復、44バイト出力）でハッシュ化する。
Hashcat の mode 10900 に渡すためには HEX → base64 変換が必要。

```python
import base64, binascii

# sqlite3 grafana.db "SELECT login,password,salt FROM user;" で取得した値
salt_str = '[SALT]'          # 例: LCBhdtJWjl
hash_hex = '[HEX_HASH]'      # 例: dc6beccc...

salt_b64  = base64.b64encode(salt_str.encode()).decode()
hash_b64  = base64.b64encode(binascii.unhexlify(hash_hex)).decode()

print(f'sha256:10000:{salt_b64}:{hash_b64}')
# → sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45...
```

### クラックコマンド

```bash
hashcat -m 10900 "sha256:10000:[SALT_B64]:[HASH_B64]" \
  /usr/share/wordlists/rockyou.txt --force
```

### 複数ハッシュをファイルで指定

```bash
# hashes.txt に変換済みハッシュを1行ずつ書いておく
hashcat -m 10900 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### 注意点
- `--force` が必要な場合が多い（GPU 最適化の問題）
- 反復回数（10000）が多いため、GPU でも遅い。辞書を絞るか、ルールを使う
- admin ハッシュが強固でもユーザー（一般）ハッシュがクラックできることがある

---

## 注意点・落とし穴

- `rockyou.txt` が見つからない場合: `/usr/share/wordlists/rockyou.txt` または `gunzip /usr/share/wordlists/rockyou.txt.gz`
- GPU がない環境（VM等）では大幅に速度が低下する。CPU 専用の場合は `--force` が必要な場合がある
- ハッシュが AES 暗号化（etype 17/18）の場合は RC4（etype 23）より解析が困難。取得時に RC4 ダウングレードを試みる

---

## 刺さらなかったとき（クラックが進まないときの判断フロー）

| 状況 | 次のアクション |
|------|--------------|
| rockyouで30分以上ヒットしない | ルール変更（`-r best64.rule` → `OneRuleToRuleThemAll.rule`）を試す |
| ルール変更後もヒットしない | そのハッシュは強固と判断し、同DBの別ユーザーのハッシュを試す |
| 推定完了まで1日以上かかる | **担当者・対象組織に平文パスワードの提供を確認する**（グレーボックス前提では正当な選択肢）。または同DBの別ユーザーのハッシュを試す |
| 全ユーザーがヒットしない | ハッシュクラックは一時中断し、別の侵入経路（認証情報使い回し・別サービスへのアクセス）を探す |
| GPUなしのVM環境で極端に遅い | `--force` オプションを追加。それでも遅い場合はCPU専用として割り切り辞書を絞る |

**「クラックできなかった＝詰まり」ではない。** 認証情報が取れなければ別の経路を探すのがペネトレの鉄則。

---

## 関連技術
- 前：`../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md`（Kerberoasting ハッシュの取得）
- 前：`../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`（ASREPRoasting ハッシュの取得）
- 前：`../02_Initial_Access/Credential_Discovery.md`（Grafana DB からのハッシュ取得）
- 前：`../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`（Grafana パストラバーサルでの DB 取得）
- 前：`../02_Initial_Access/Web_Vulnerabilities/SQLi.md`（CMS Made Simple SQLi からのハッシュ取得）
- 前：`../02_Initial_Access/MSSQL_Exploitation.md`（MSSQL DB からの Werkzeug/Django PBKDF2 ハッシュ取得）
