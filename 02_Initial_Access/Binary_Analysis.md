# バイナリ解析・ハードコード認証情報の抽出

> **スコープ**: 実行ファイルや DLL にハードコードされた認証情報・接続先・暗号化ロジックを調査する手法。特に .NET バイナリは逆コンパイルが容易で認証情報が見つかりやすい。§1 strings → §2 .NET 逆コンパイル → §3 XOR 復号 → §4 ネットワークキャプチャ の順で試す。

## 着火条件

- バイナリファイル（.exe, .dll, ELF 等）が取得できた場合
- 設定ファイル（web.config / appsettings.json / .env）では認証情報が見つからなかった場合
- アプリケーションがサービスに接続している動作を確認したが認証情報が不明な場合

## 環境前提

- 実行環境: テスター端末（Linux / Windows どちらでも）
- 必要なツール（§別に記載）:
  - `strings`（標準搭載）、`file`（標準搭載）
  - `ilspycmd`（.NET 逆コンパイル。`dotnet tool install ilspycmd -g`）
  - `dnSpy`（Windows GUI 逆コンパイル・編集。GitHub から入手）
  - `de4dot`（.NET 難読化解除。GitHub から入手）
  - `wine`（Linux 上で Windows バイナリを実行。`apt install wine`）
  - `tcpdump` / `tshark`（ペネトレ用 Linux ディストリ標準搭載）
  - `FLOSS`（難読化文字列抽出。`pip install flare-floss`）
  - `msgconvert` / `extract-msg`（OLE2/.msg 解析）
- オフライン代替: Python 3 は標準搭載のため §3・§6 の復号スクリプトはオフライン実行可

## 先に確認すること

- **ファイル形式の確認**: `file [binary]` で PE / ELF / DLL / OLE2 を判定してから手法を選ぶ
- **設定ファイルを先に確認する**: `web.config` / `appsettings.json` / `.env` / `docker-compose.yml` を先に見る。バイナリ解析より速い

**攻撃者の思考トレース:** `strings` を最初にやる理由は逆コンパイル・デバッガ不要で数秒で終わるから。ハードコード認証情報の 7 割はこの段階で見つかる。`.NET` バイナリは IL（中間言語）にコンパイルされており、ほぼ完全にソースコードを復元できる。

---

## 1. strings コマンドによる文字列抽出

**コマンド:**

```bash
# [Attacker] ASCII 文字列の抽出（grep でキーワード絞り込み）
strings [binary_file] | grep -i "pass\|user\|key\|secret\|token\|ldap\|http"

# [Attacker] Unicode（UTF-16LE）文字列の抽出（Windows バイナリに有効）
strings -e l [binary_file] | grep -i "pass\|user\|key"

# [Attacker] Python で UTF-16LE を確実に抽出
python3 -c "
with open('[binary_file]', 'rb') as f:
    data = f.read()
import re
utf16_strings = re.findall(b'(?:[\x20-\x7e]\x00){4,}', data)
for s in utf16_strings:
    decoded = s.decode('utf-16-le', errors='ignore')
    if any(kw in decoded.lower() for kw in ['pass', 'user', 'ldap', 'key', 'secret']):
        print(repr(decoded))
"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `ldap://` / `smb://` 等の URL | 接続先サーバーの特定 | その接続先に対してアクセス経路を検討 |
| `password=`, `pwd:`, `apikey=` のような代入形式 | ハードコード認証情報 | そのまま認証情報として試す |
| Base64 っぽい長い文字列（末尾 `=`）| 暗号化 / エンコード済みデータ | `base64 -d` で復号 → バイナリか文字列か判定 |
| `mscoree.dll` / `.NETFramework` / `mscorlib` | .NET バイナリ確定 | §2 逆コンパイルに進む |
| `UPX!` / 高エントロピー | パックされている | `upx -d` で解凍 → 再度 strings |
| ASCII は出ないが UTF-16LE では出る | Windows バイナリ典型 | `strings -e l` で再試行 |
| XOR キーらしき短い文字列 + Base64 データ | 簡易暗号化の痕跡 | §3 XOR 復号に進む |

**注意:** `strings` だけでは UTF-16LE エンコードの文字列を見逃すことが多い。`strings -e l` を必ず併用する。

---

## 2. .NET バイナリの逆コンパイル

`.NET` バイナリは IL（中間言語）にコンパイルされており、ほぼ完全にソースコードを復元できる。暗号化されたパスワードでも、暗号化ロジック自体がコード内にあるため復号の手掛かりが得られる。

**コマンド（Linux — ilspycmd）:**

```bash
# [Attacker] ilspycmd のインストール（要 .NET SDK）
dotnet tool install ilspycmd -g

# [Attacker] 逆コンパイル
ilspycmd [binary.exe] -o ./decompiled/

# 出力された C# コードを確認
grep -r "password\|ldap\|encrypt\|decrypt\|xor" ./decompiled/ -i
```

**コマンド（Windows — dnSpy GUI）:**

1. dnSpy で対象バイナリを開く
2. 左ペインのクラスツリーからエントリポイント（`Main` メソッド）を探す
3. パスワード文字列が渡されている行を確認

**事前処理（難読化されている場合）:**

```bash
# [Attacker/Windows] de4dot でコードの難読化を解除してから dnSpy で開く
de4dot.exe [obfuscated.exe] -o [cleaned.exe]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Convert.FromBase64String` + `^` 演算子 | Base64 → XOR の典型構造 | §3 XOR 復号に進む |
| `RC4.Encrypt` / `RC4.Decrypt` が同一メソッド | RC4 実装（暗号化 = 復号）| §6 RC4 復号に進む |
| パスワードが `new SecureString()` / 動的生成 | 静的解析だけでは取れない | §7 dnSpy コード編集に進む |
| 平文パスワードがそのまま変数に | 即認証情報として使用可能 | 取得した値で認証試行 |

**注意:** 難読化されている場合は de4dot を先に通してから逆コンパイルする。

---

## 3. XOR 暗号化されたパスワードの復号

バイナリ中に Base64 エンコードされた文字列と短いキー文字列が見つかった場合に適用する。

**攻撃者の思考トレース:** 開発者が「難読化すれば十分」と判断しているケースが多い。コード内にキーがあるので数学的には必ず解ける。

**コマンド:**

```python
# [Attacker] XOR 復号スクリプト（Python 3）
import base64

enc_password = '[BASE64_ENCODED_STRING]'
key = '[XOR_KEY]'
magic_byte = 0xdf  # バイナリから特定した定数（ない場合は 0x00 にする）

decoded = base64.b64decode(enc_password)
key_bytes = key.encode('ascii')
result = []
for i, b in enumerate(decoded):
    decrypted = b ^ key_bytes[i % len(key_bytes)] ^ magic_byte
    result.append(decrypted)

print('復号結果:', bytes(result).decode('utf-8'))
```

```python
# [Attacker] magic_byte がわからない場合: 0x00〜0xff を総当たり
for magic in range(256):
    try:
        result = bytes([b ^ key_bytes[i % len(key_bytes)] ^ magic for i, b in enumerate(decoded)])
        decoded_str = result.decode('utf-8')
        if decoded_str.isprintable():
            print(f'magic=0x{magic:02x}: {decoded_str}')
    except:
        pass
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| 印字可能な文字列が出力された | XOR 復号成功 | 取得したパスワードで認証試行 |
| 複数 magic 候補が出力された | どれが正しいか不明 | 全候補で実際に認証を試す |
| 復号結果にヌルバイトが混ざる | UTF-16LE の可能性 | `.decode('utf-16-le')` で再解釈 |

---

## 4. バイナリ実行 + ネットワークキャプチャによるクレデンシャル取得

逆コンパイルで暗号化ロジックが複雑すぎる場合、実際に動かしてネットワークを見れば認証情報が流れることがある。

**事前準備（必須）:** バイナリが接続先に実際に到達できる状態にしておく（`/etc/hosts` への登録、対象サービスへの疎通確認）。

**コマンド:**

```bash
# [Attacker] strings でバイナリ内の接続先ホスト名を特定
strings [binary_file] | grep -iE "ldap://|smb://|://[a-z]"

# [Attacker] 判明したホスト名を登録（テスト識別子マーカー付き）
echo "192.0.2.10  [HOSTNAME]  # kedalab-[CASE_ID]" | sudo tee -a /etc/hosts

# [Attacker] tcpdump でキャプチャ開始（別ターミナルで）
sudo tcpdump -i [INTERFACE] -w /tmp/capture.pcap port 389 or port 445 or port 80

# [Attacker] Wine でバイナリを実行（上記と別ターミナルで）
wine [binary_file]

# [Attacker] pcap を解析（tshark）
tshark -r /tmp/capture.pcap -Y "ldap.bindRequest" -T fields -e ldap.name -e ldap.simple
```

**LDAP Simple Authentication の出力例:**

```
# WireShark での表示例:
# authentication: simple (0)
#   └─ simple: [PASSWORD]  ← これがパスワード
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| LDAP `bindRequest` パケットが見える | 認証情報が平文で流れている | `authentication` フィールドからパスワードを取得 |
| SMB `NTLMSSP_AUTH` パケットが見える | NTLM ハッシュが流れている | Responder / ntlmrelayx でリレー攻撃も検討 |
| HTTP `Authorization: Basic` ヘッダー | Base64 エンコードの平文認証 | `echo '[BASE64]' \| base64 -d` で復号 |
| パケットが一切流れない | バイナリが接続に失敗 | `/etc/hosts` の登録・疎通確認を先に行う |
| Wine がクラッシュ | 特定の Windows ランタイムが必要 | `winetricks` で依存コンポーネントを追加 |

**注意:** LDAP over TLS（LDAPS / ポート 636）や Kerberos 認証を使っている場合は平文パケットが得られない。§2 逆コンパイルと並行して実施する。

---

## 5. OLE2 / .msg ファイルの解析

SMB 共有・FTP 等から `.msg` 拡張子のファイル（Outlook メッセージ形式）を取得した場合。内部にメール本文・添付ファイル・送受信情報が格納されている。

**コマンド:**

```bash
# [Attacker] ファイル形式の確認
file [filename.msg]
# → "Composite Document File V2 Document" なら OLE2

# [Attacker] msgconvert で .eml 形式に変換
msgconvert [filename.msg]
cat [filename.eml]

# [Attacker] extract-msg で本文・添付を個別展開
python3 -m extract_msg [filename.msg]
ls ./[展開されたフォルダ]/

# [Attacker] strings での強引な抽出（インストール不要の代替）
strings [filename.msg] | grep -iE "password|user|smtp|server|from:|to:|subject:|http"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| サービス名・接続先・ユーザー名が本文に記載 | 内部システム構成の手掛かり | 記載されたサービスへのアクセスを試みる |
| `From:` / `To:` にメールアドレス | 内部ユーザー名の候補 | sAMAccountName として LDAP / Kerbrute で検証 |
| 添付ファイルが展開された | バイナリ・スクリプトの可能性 | `file` → 該当する解析パターンへ |

---

## 6. RC4 暗号化されたパスワードの復号（.NET バイナリ）

.NET バイナリを逆コンパイルした結果、`RC4`（キーストリーム暗号）を使った暗号化ロジックがソースコードに含まれている場合。`Encrypt` / `Decrypt` メソッドが同一ロジックで、`byte[] password_cipher` と `byte[] key` がソースコード内に定義されているときに適用する。

**攻撃者の思考トレース:** RC4 は暗号化と復号が同じ操作のため、暗号化バイト列とキーさえ分かれば Python で即復号できる。

**コマンド:**

```python
# [Attacker] RC4 復号スクリプト（Python 3）
def rc4_decrypt(key_bytes, cipher_bytes):
    key = list(key_bytes)
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) % 256
        box[i], box[j] = box[j], box[i]
    a = j = 0
    result = []
    for byte in cipher_bytes:
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        box[a], box[j] = box[j], box[a]
        k = box[(box[a] + box[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)

# 逆コンパイルで得た値を貼り付ける
key_str   = "[KEY_STRING]"          # Encoding.ASCII.GetBytes のキー文字列
cipher    = bytes([0x00, 0x00, ...]) # password_cipher 配列の値

key_bytes = key_str.encode('ascii')
plain     = rc4_decrypt(key_bytes, cipher)
print("復号結果:", plain.decode('utf-8', errors='replace'))
```

**観測される出力 → 次のアクション:**

| 逆コンパイル結果の観察 | 示唆 | 次のアクション |
|---------------------|------|--------------|
| `RC4.Encrypt` / `RC4.Decrypt` が同一メソッド | RC4 実装（暗号化 = 復号）| キーと暗号化済みバイト列を抽出して Python で復号 |
| `byte[] key = Encoding.ASCII.GetBytes(...)` | 平文キーがソースコードに埋め込み | そのままキーとして使う |
| キーが空文字 `""` や実行時動的生成 | デバッガで実行時の値をキャプチャが必要 | §7 dnSpy コード編集に進む |

---

## 7. dnSpy コード編集・再コンパイルによるパスワード取得

パスワードが実行時に動的生成・暗号化・SecureString 変換されており、静的解析だけでは平文が取れない場合に使う。dnSpy はコードを編集して再コンパイルできるため、パスワードを使う直前に `Console.WriteLine` を差し込むだけで平文が取れる。

**環境前提（本手法のみ）:** Windows 環境（テスター側 Windows マシンまたはターゲット内部）が必要。

**手順:**

1. `de4dot.exe [obfuscated.exe] -o [cleaned.exe]`（難読化解除が必要な場合）
2. dnSpy で対象バイナリを開く
3. パスワード変数の直前に `Console.WriteLine(password);` を挿入
4. 右下の「Compile」ボタンをクリック → エラーがなければ成功
5. `File → Save Module` で保存 → 実行してパスワードを確認

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| コンソールにパスワードが表示された | コード編集成功 | 取得したパスワードで認証試行 |
| `Compile` でエラー | 変更範囲が多すぎる | `Console.WriteLine` 追加のみの最小変更に絞る |
| 実行しても表示されない | 実行パスが別の条件分岐に入っている | 条件分岐前にも `Console.WriteLine` を追加する |

---

## 刺さらなかったとき

| 状況 | 原因 | 代替 |
|------|------|------|
| strings で何も見つからない | UTF-16LE または難読化 | `strings -e l` で再試行 / FLOSS（`pip install flare-floss`）を使う |
| ilspycmd でエラー | .NET Framework のバージョン不一致 | .NET SDK バージョンを合わせるか dnSpy（Windows GUI）を使う |
| Wine がクラッシュ | 依存 DLL が不足 | `winetricks` で依存コンポーネントを追加 / 実 Windows 環境で実行 |
| LDAP/SMB が暗号化されている | SASL/GSSAPI / LDAPS / NTLM v2 | §2 逆コンパイルで鍵取得を試みる |
| RC4 のキーが実行時動的生成 | デバッガが必要 | §7 dnSpy コード編集でパスワード直前に `Console.WriteLine` を差し込む |

---

## 注意点・落とし穴

- `strings` だけでは UTF-16LE エンコードの文字列を見逃すことが多い（Windows バイナリは UTF-16LE を多用）
- `.NET` バイナリかどうかは `file` コマンドまたは `strings` 結果に `.NETFramework` が含まれるかで判断
- RC4 は「暗号化と復号が同じ操作」なので、Encrypt / Decrypt メソッドが同一実装でも正常（仕様通り）
- キャプチャには root 権限が必要（`sudo tcpdump`）。`/etc/hosts` に追記した行は原状回復する

---

## 関連技術

- 前：SMB 共有からバイナリを取得した → `../01_Reconnaissance/SMB_Enumeration.md`
- 前：FTP からファイルを取得した → `./FTP.md`
- 前：取得ファイルのメタデータ確認 → `../01_Reconnaissance/Metadata_Analysis.md`
- 後：復号・キャプチャした認証情報の使い回し確認 → `./Credential_Discovery.md`
- 後：LDAP 接続先が判明した → `../01_Reconnaissance/LDAP_Enumeration.md`
- 後：取得した認証情報でパスワードスプレー → `../05_Tools_Reference/Netexec.md`
