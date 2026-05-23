# バイナリ解析・ハードコード認証情報の抽出

## 概要

実行ファイルや DLL にハードコードされた認証情報・接続先・暗号化ロジックを調査する手法。特に .NET バイナリは逆コンパイルが容易で、認証情報が見つかりやすい。

---

## パターン1: strings コマンドによる文字列抽出

### 着火条件
バイナリファイル（.exe, .dll, ELF等）が取得できた場合。まず最初に試す。

### 観点・着眼点

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| `ldap://...` / `smb://...` 等の URL | 接続先サーバーの特定 | その接続先に対してアクセス経路を検討 |
| `password=`, `pwd:`, `apikey=` のような代入形式 | ハードコード認証情報 | そのまま認証情報として試す |
| Base64 っぽい長い文字列（末尾 `=`） | 暗号化 / エンコード済みデータ | `base64 -d` で復号 → バイナリか・文字列か判定 |
| `mscoree.dll` / `.NETFramework` / `mscorlib` | .NET バイナリ確定 | パターン2（逆コンパイル）に進む |
| `UPX!` / `packed` / 高エントロピー | パックされている | `upx -d` で解凍 → 再度 strings |
| ASCII は出ないが UTF-16LE では出る | Windows バイナリ典型 | `strings -e l` で再試行 |
| XOR キーらしき短い文字列 + Base64 データ | 簡易暗号化の痕跡 | パターン3（XOR 復号）に進む |

**なぜ strings を最初にやるのか：** 逆コンパイル・デバッガ不要で数秒で終わる。ハードコード認証情報の 7 割はこの段階で見つかる。

### 手順

```bash
# ASCII文字列の抽出
strings [binary_file] | grep -i "pass\|user\|key\|secret\|token\|ldap\|http"

# Unicode（UTF-16LE）文字列の抽出（Windowsバイナリに有効）
strings -e l [binary_file] | grep -i "pass\|user\|key"

# Python で UTF-16LE を確実に抽出
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

---

## パターン2: .NET バイナリの逆コンパイル

### 着火条件
`.exe` が .NET アプリケーションの場合（`strings` で `mscoree.dll` や `.NETFramework` が見える）。

### 観点・着眼点
- .NET バイナリは IL（中間言語）にコンパイルされており、**ほぼ完全にソースコードを復元できる**
- 暗号化された認証情報でも、**暗号化ロジック自体がコード内にある**ため復号できる
- 接続先URL（LDAP, SMB, HTTP）、ユーザー名、暗号化されたパスワードを探す

### 手順

**Linux環境での逆コンパイル（ilspycmd）：**
```bash
# ilspycmd のインストール
dotnet tool install ilspycmd -g

# 逆コンパイル
ilspycmd [binary.exe] -o ./decompiled/

# 出力されたC#コードを確認
grep -r "password\|ldap\|encrypt\|decrypt\|xor" ./decompiled/ -i
```

**Windows環境での逆コンパイル（dnSpy / ILSpy）：**
GUI ツールで `.exe` を開き、クラス一覧から認証関連のクラスを探す。

---

## パターン3: XOR暗号化されたパスワードの復号

### 着火条件
バイナリ中に Base64 エンコードされた文字列と、短いキー文字列が見つかった場合。

### 観点・着眼点

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| 逆コンパイルコードに `Convert.FromBase64String` + `^` 演算子 | Base64 → XOR の典型構造 | 下の復号スクリプトにパラメータを差し替えて実行 |
| XOR キーがソースコードに平文で書かれている | 復号に必要な情報が揃った | そのまま復号して平文パスワード取得 |
| XOR キーが別関数で動的生成（`Environment.MachineName` 等） | 実行環境依存 | 実機と同じ値を与えるか、デバッガで実行時キーを取得 |
| キーらしき文字列が複数候補 | どれが XOR キーか不明 | 全候補で総当たり → 印字可能文字列になるものを採用 |
| 復号結果が一部だけ印字可能（先頭が崩れる） | 追加の magic byte が入っている | magic byte を 0x00〜0xFF で総当たり |
| 復号結果にヌルバイトが混ざる | UTF-16LE の可能性 | `.decode('utf-16-le')` で再解釈 |

**なぜ簡易 XOR が残り続けるか：** 開発者が「難読化すれば十分」と判断しているケースが多い。コード内にキーがあるので数学的には必ず解ける。

**簡易 XOR を特定する手順：**
1. 暗号化されたデータ（Base64文字列）
2. XORキー（短い文字列）
3. 追加のXORマジックバイト（`0xdf` など定数）

の3つを特定して復号する。

### 手順

**典型的なXOR復号パターン：**
```python
import base64

enc_password = '[BASE64_ENCODED_STRING]'
key = '[XOR_KEY]'
magic_byte = 0xdf  # バイナリから特定した定数（ない場合もある）

decoded = base64.b64decode(enc_password)
key_bytes = key.encode('ascii')
result = []
for i, b in enumerate(decoded):
    decrypted = b ^ key_bytes[i % len(key_bytes)] ^ magic_byte
    result.append(decrypted)

print('復号結果:', bytes(result).decode('utf-8'))
```

**magic_byte がわからない場合：**
```python
# 0x00 〜 0xff を総当たり
for magic in range(256):
    try:
        result = bytes([b ^ key_bytes[i % len(key_bytes)] ^ magic for i, b in enumerate(decoded)])
        decoded_str = result.decode('utf-8')
        if decoded_str.isprintable():
            print(f'magic=0x{magic:02x}: {decoded_str}')
    except:
        pass
```

---

## パターン4: バイナリ実行 + ネットワークキャプチャによるクレデンシャル取得

### 着火条件

以下のどちらかが当てはまる場合に試す：

- 逆コンパイルで暗号化ロジックが複雑すぎて復号が難しい
- バイナリが外部サービス（LDAP・SMB・HTTP 等）に接続する動作を確認した

**攻撃者の思考トレース：** 「解読できなくても、実際に動かしてネットワークを見れば認証情報が流れる」。
バイナリは接続の際に認証情報を送信しなければサービスと通信できない。
暗号化していない LDAP Simple Authentication（平文バインド）や HTTP Basic 認証はパケット上にそのまま現れる。
逆コンパイルと並行して、または逆コンパイルが難しい場合の代替として試す。

### 環境前提

- 実行環境: テスター端末（Linux）
- 必要なツール:
  - `wine`（Linux上でWindowsバイナリを実行するエミュレーター。別途インストール要）
  - `tcpdump`（ペネトレ用Linuxディストリ標準搭載）または WireShark（GUI。別途インストール可）
- ネットワーク: バイナリが接続しようとするサービス（LDAP 389等）がテスター端末から到達可能であること

### 観点・着眼点

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| LDAP `bindRequest` パケットが見える | 認証情報が平文で流れている | `authentication` フィールドからパスワードを取得 |
| LDAP `bindResponse resultCode: success` | バインド成功。認証情報が正しい | 取得したユーザー名・パスワードで LDAP 列挙へ |
| SMB `NTLMSSP_AUTH` パケットが見える | NTLMハッシュが流れている | Responder / impacket-ntlmrelayx でリレー攻撃も検討 |
| HTTP `Authorization: Basic` ヘッダーが見える | Base64エンコードの平文認証 | `echo '[BASE64]' \| base64 -d` で復号 |
| ツールが `Connect error` / 名前解決失敗 | 接続先のホスト名を解決できていない | バイナリ内のホスト名を確認し `/etc/hosts` に登録してから再試行 |
| バイナリが即終了・無応答 | Wine非対応の依存DLLが不足している可能性 | `wine [binary] 2>&1 \| grep -i err` でエラーを確認。不足DLLをインストール |

**先に確認すること：**
バイナリが接続先に実際に到達できる状態になっているかを先に確認する（`/etc/hosts` への登録、対象サービスへの疎通）。
到達できない状態でキャプチャしてもパケットは流れない。

### 手順

**Step 1: バイナリの接続先ホスト名を特定して登録する**

```bash
# [Attacker] strings またはパターン1・2の逆コンパイル結果から接続先ホスト名を確認
strings [binary_file] | grep -iE "ldap://|smb://|://[a-z]"

# [Attacker] 判明したホスト名を登録（案件識別子マーカー付き）
echo "192.0.2.10  [HOSTNAME]  # kedalab-[CASE_ID]" | sudo tee -a /etc/hosts
```

**Step 2: キャプチャを開始してからバイナリを実行する**

```bash
# [Attacker] tcpdump でキャプチャ開始（別ターミナルで）
# インターフェース名は環境により異なる。`ip a` で到達可能なインターフェースを確認する
sudo tcpdump -i [INTERFACE] -w /tmp/capture.pcap port 389 or port 445 or port 80 or port 443

# [Attacker] Wine でバイナリを実行（上記と別ターミナルで）
wine [binary_file] [options]
```

> **`[INTERFACE]` について：** テスター端末から対象サービスに到達できるインターフェース（環境によって物理 NIC・VPN アダプター・専用線インターフェース等が異なる）。`ip a` で全インターフェースを確認してから指定する。

**Step 3: pcap を解析する**

```bash
# [Attacker] tshark でクイック解析（WireShark の CLI 版。別途インストール要）
tshark -r /tmp/capture.pcap -Y "ldap.bindRequest" -T fields \
  -e ldap.name -e ldap.simple

# または WireShark GUI で開いて以下を確認
# LDAP の場合：
#   Lightweight Directory Access Protocol → protocolOp → bindRequest → authentication
# HTTP Basic の場合：
#   Authorization: Basic [BASE64] を右クリック → Follow HTTP Stream
```

**LDAP Simple Authentication の例（tcpdump の出力イメージ）：**

```
# WireShark での表示例：
# Lightweight Directory Access Protocol
#   └─ LDAPMessage bindRequest(1) "[DOMAIN]\[USER]" simple
#        ├─ messageID: 1
#        └─ protocolOp: bindRequest (0)
#             └─ authentication: simple (0)
#                  └─ simple: [PASSWORD]
```

### 刺さらなかったとき

| 状況 | 原因・対処 |
|------|-----------|
| パケットが一切流れない | バイナリが接続に失敗している。`/etc/hosts` の登録・疎通確認を先に行う |
| LDAP パケットが見えるが authentication が暗号化されている | `SASL/GSSAPI` 等の暗号化バインドが使われている。パターン2（逆コンパイル）での鍵取得が必要 |
| Wine がクラッシュ・依存DLLエラー | 特定の Windows ランタイムが必要。`winetricks` で依存コンポーネントを追加するか、実 Windows 環境で実行する |
| バイナリが64bit でWineが32bitモード | `WINEARCH=win64 wine [binary]` で64bitモードを指定する |

### 注意点・落とし穴

- LDAP over TLS（LDAPS / ポート636）や Kerberos 認証を使っている場合は平文パケットが得られない。その場合はパターン2（逆コンパイル）でクレデンシャルを復元する
- Wine はWindowsバイナリの完全エミュレーターではないため、一部のバイナリは動作が異なることがある（ネットワーク送信前の処理が途中で止まる等）。パターン2との並行実施を推奨する
- キャプチャには root 権限が必要（sudo tcpdump）。書き込み先（`/tmp/capture.pcap`）の権限も確認する
- 原状回復：`/etc/hosts` に追記した行を削除する
  ```bash
  sudo sed -i.bak '/# kedalab-\[CASE_ID\]/d' /etc/hosts
  ```

---

---

## パターン5: OLE2 / .msg ファイルの解析

### 着火条件

SMB 共有・FTP 等から **`.msg` 拡張子のファイル**（Outlook メッセージ形式）を取得した場合。内部にメール本文・添付ファイル・送受信情報が格納されている。`file` コマンドで `Composite Document File V2 Document` と出れば OLE2 形式。

**攻撃者の思考トレース：** `.msg` ファイルは単なる電子メールのバックアップだが、業務用途で使われる場合、**設定変更通知・サービスアカウント情報・接続情報**が書かれていることがある。

### 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `libemail-outlook-message-perl`（`msgconvert` コマンドを提供。`sudo apt install libemail-outlook-message-perl`）または
  - `extract-msg`（Python 製。`pip install extract-msg --break-system-packages`）
  - `strings`（ペネトレ用Linuxディストリ標準搭載）
- オフライン代替: `strings [file.msg]` でテキスト部分を強引に抽出（書式は崩れる）

### 手順

```bash
# [Attacker] Step 1: ファイル形式の確認
file [filename.msg]
# → "Composite Document File V2 Document" なら OLE2

# [Attacker] Step 2a: msgconvert で .eml 形式に変換（テキスト閲覧）
msgconvert [filename.msg]
cat [filename.eml]

# [Attacker] Step 2b: extract-msg で本文・添付を個別展開
python3 -m extract_msg [filename.msg]
# → カレントディレクトリにフォルダが作成され、本文(.txt)・添付ファイルが展開される
ls ./[展開されたフォルダ]/

# [Attacker] Step 3: strings での強引な抽出（インストール不要の代替）
strings [filename.msg] | grep -iE "password|user|smtp|server|from:|to:|subject:|http"
```

**何が出たら次に何をするか：**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| サービス名・接続先・ユーザー名が本文に記載 | 内部システム構成の手掛かり | 記載されたサービスへのアクセスを試みる |
| 「サービスを Oracle から MSSQL に変更」等のメッセージ | サービスアカウント名・パスワードの命名パターンが推測できる | サービス名・年号を変えたパスワードパターンを試す（下記参照）|
| 添付ファイルが展開された | バイナリ・スクリプト等の可能性 | `file` → 該当する解析パターンへ |
| `From:` / `To:` にメールアドレス | 内部ユーザー名の候補 | sAMAccountName として LDAP / Kerbrute で検証 |

**パスワード命名パターン推測（サービス名 + 年号型）：**

業務システムでは、サービス名と年号を組み合わせた単純なパスワード命名規則を採用していることがある。サービス移行に伴いパスワードも機械的に更新されているケースが多い。

```
# 命名パターンの例（プレースホルダー）:
# [service_prefix]_[type][year]   → 例: #[SVC]_s3rV1c3![YEAR]
# [ServiceName][Year]!            → 例: [Service][Year]!
#
# サービス名が変わったら → 新しいサービス名で同じパターンを試す
# 年号が変わったら       → 新しい年号で同じパターンを試す
# svc_[oracle] → svc_[mssql] のようにサービスアカウント名も変わる可能性がある
```

### 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `msgconvert` が文字化けする | `strings -e l [file.msg]` で UTF-16LE として再試行 |
| `extract-msg` がエラーになる | ファイルが破損しているか別の OLE2 ファイル形式の可能性。`strings` で直接抽出 |

---

## パターン6: RC4 暗号化されたパスワードの復号（.NET バイナリ）

### 着火条件

.NET バイナリを逆コンパイル（パターン2）した結果、**`RC4`（キーストリーム暗号）を使った暗号化ロジック**がソースコードに含まれている場合。`Encrypt` / `Decrypt` メソッドが同一ロジックを使い（RC4 の特性：Encrypt = Decrypt）、`byte[] password_cipher` と `byte[] key` がソースコード内に定義されているときに発火する。

**攻撃者の思考トレース：** RC4 は暗号化と復号が同じ操作のため、暗号化バイト列とキーさえ分かれば Python で即復号できる。バイナリを実行しなくても、逆コンパイルしてコード内の定数を抽出するだけで復号できる。

### 環境前提

- 実行環境: テスター端末（Python）
- 必要なツール: Python 3（標準搭載）

### 観点・着眼点

**何が出たら次に何をするか：**

| 逆コンパイル結果の観察 | 示唆 | 次のアクション |
|---------------------|------|--------------|
| `RC4.Encrypt` / `RC4.Decrypt` が同一メソッド | RC4 実装（暗号化=復号） | キーと暗号化済みバイト列を抽出してPythonで復号 |
| `byte[] key = Encoding.ASCII.GetBytes("[キー文字列]")` | 平文キーがソースコードに埋め込まれている | そのままキーとして使う |
| `byte[] password_cipher = { 0x??, 0x??, ... }` | 暗号化済みパスワードが定数配列 | バイト列を Python に貼り付けて復号 |
| キーが空文字 `""` や定数のみ | キーが実行時に動的決定されている可能性 | デバッガ（x64dbg / dnSpy）で実行時の値をキャプチャ |

### 手順

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
cipher    = bytes([0x??, 0x??, ...]) # password_cipher 配列の値

key_bytes = key_str.encode('ascii')
plain     = rc4_decrypt(key_bytes, cipher)
print("復号結果:", plain.decode('utf-8', errors='replace'))
```

---

## パターン7: dnSpy コード編集・再コンパイルによるパスワード取得

### 着火条件

パターン2（.NET 逆コンパイル）でソースコードを取得済みだが、パスワードが **実行時に動的生成・暗号化・SecureString 変換** されており、静的解析だけでは平文が取れない場合。dnSpy はコードを編集して再コンパイルできるため、パスワードを使う直前に `Console.WriteLine` を差し込むだけで平文が取れる。

**攻撃者の思考トレース：** 「デバッガで追うより、コードを書き換えて自分から吐かせる方が速い」。バイナリを再コンパイルして実行するだけで済む。

### 環境前提

- 実行環境: Windows 環境（テスター側 Windows マシン or ターゲット内部）
- 必要なツール:
  - `dnSpy`（.NET アセンブリの逆コンパイル・編集・再コンパイルツール。GitHub から入手、インターネットアクセス要）
  - `de4dot`（難読化された .NET バイナリを事前に平文化するツール。dnSpy 適用前に使う）

### 手順

**Step 1: 難読化解除（必要な場合）**

```bash
# [Attacker/Windows] de4dot でコードの難読化を解除してから dnSpy で開く
de4dot.exe [obfuscated.exe] -o [cleaned.exe]
```

**Step 2: dnSpy でパスワード使用箇所を特定してコードを編集**

1. dnSpy で対象バイナリを開く
2. 左ペインのクラスツリーからエントリポイント（`Main` メソッド）を探す
3. パスワード文字列が渡されている行を右クリック → 「Edit Method（C#）」
4. パスワード変数の直前に `Console.WriteLine(password);` を挿入する
5. 右下の「Compile」ボタンをクリック → エラーがなければ成功

**Step 3: 再コンパイル済みバイナリを保存して実行**

```
dnSpy メニュー: File → Save Module → 保存先を指定
```

```bash
# [Target/Windows または Attacker] 保存した実行ファイルを実行
[saved_binary.exe]
# → Console.WriteLine で挿入した行にパスワードが表示される
```

### 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `Compile` でエラーになる | 削除・変更した行が多すぎる。`Console.WriteLine` を追加する最小変更に絞る |
| 実行しても `Console.WriteLine` が表示されない | 実行パスが別の条件分岐に入っている。条件分岐前にも挿入する |
| バイナリが難読化されており逆コンパイル結果が読めない | de4dot を先に通してから再度 dnSpy で開く |

---

## 注意点・落とし穴

- `strings` だけでは UTF-16LE エンコードの文字列を見逃すことが多い（Windowsバイナリは UTF-16LE を多用）
- `.NET` バイナリかどうかは `file` コマンドや PE ヘッダーの確認（`strings` 結果に `.NETFramework` が含まれるか）で判断
- 暗号化ロジックが複数層になっている場合もある（Base64 → XOR → RC4 → Base64 など）
- RC4 は「暗号化と復号が同じ操作」なので、Encrypt メソッドと Decrypt メソッドが同一実装でも正常（仕様通り）

---

## 関連技術
- 前：SMB 共有からバイナリを取得した → `../01_Reconnaissance/SMB_Enumeration.md`
- 前：FTP からファイルを取得した → `./Protocol_Exploitation.md`（FTP セクション）
- 前：取得ファイルのメタデータ確認 → `../01_Reconnaissance/Metadata_Analysis.md`
- 後：復号・キャプチャした認証情報の使い回し確認 → `./Credential_Discovery.md`
- 後：LDAP 接続先が判明した → `../01_Reconnaissance/LDAP_Enumeration.md`
- 後：取得した認証情報でパスワードスプレー → `../05_Tools_Reference/Netexec.md`
