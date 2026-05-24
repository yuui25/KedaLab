# メールプロトコル（SMTP / POP3 / IMAP）の動作原理

> **このファイルの位置づけ:** [`../02_Initial_Access/Mail_Services.md`](../02_Initial_Access/Mail_Services.md) で扱うメール系プロトコル攻撃の **動作原理ファイル**。「なぜ VRFY が無効化されたか」「なぜ Open Relay が悪いのか」「なぜ STARTTLS が後から導入されたか」「なぜ SPF だけでは不十分で DKIM/DMARC が必要なのか」等、攻撃が成立する/しないの背景となるプロトコル仕様と歴史的経緯を集約する。
>
> 攻撃手順そのものは `Mail_Services.md` に書く。本ファイルは「詰まったときに原因を特定する」「新環境で同じ手が使えるか判断する」用。

参照元ファイル:
- [`../02_Initial_Access/Mail_Services.md`](../02_Initial_Access/Mail_Services.md) — SMTP / POP3 / IMAP の攻撃手順（バナー〜ユーザー列挙〜認証スプレー〜既知 CVE）

---

## 1. メール配送の全体像

メールは **複数のサーバを経由して届く**。攻撃面を理解するには、まずこの流れを把握する。

```
[送信者 MUA]
    │ (1) SMTP submission (port 587)
    ▼
[送信側 MTA] ─────── (2) SMTP relay (port 25) ──────▶ [受信側 MTA]
                                                            │ (3) ローカル配送
                                                            ▼
                                                        [MDA] (Dovecot 等)
                                                            │
                                                            ▼
                                                        メールスプール
                                                            │ (4) POP3 / IMAP
                                                            ▼
                                                       [受信者 MUA]
```

| 略称 | 名前 | 役割 |
|---|---|---|
| MUA | Mail User Agent | メールクライアント（Outlook / Thunderbird / Web メール）|
| MSA | Mail Submission Agent | 送信者から最初のメールを受ける（port 587）|
| MTA | Mail Transfer Agent | サーバ間のメール転送（Postfix / Exim / Sendmail / Exchange）|
| MDA | Mail Delivery Agent | ローカルスプールへの配送（Dovecot / procmail）|

**なぜ「Submission ポート（587）」と「Relay ポート（25）」が分離されているか:**

- 1990 年代は 25 番ポートで両方こなしていたが、**spammer がオープンリレーを悪用**して大量送信が起きた
- RFC 4409 (2006) / RFC 6409 (2011) で **Submission ポート（587）を認証必須として分離**
- 25 番ポートは MTA 同士の中継専用に。ISP も多くが outbound 25 をブロックする運用に

**攻撃側の視点:**

- **25 番が外部から到達できる**= MTA 機能の露出。Open Relay / VRFY / Exim CVE-2019-10149 等の攻撃面
- **587 番が外部から到達できる** = 認証 spray のターゲット。AUTH メカニズム経由で cred 試行
- **465 番（SMTPS）** = 465 SSL ラッパ。実は RFC 8314 (2018) で復活した歴史的経緯あり（後述 §5）

---

## 2. SMTP の対話モデル

SMTP は **テキストベースの対話型プロトコル**。クライアントが 1 行コマンドを送り、サーバが **3 桁の応答コード + メッセージ** で返す。

### 応答コードの読み方

| 範囲 | 意味 | 例 |
|---|---|---|
| **2xx** | 成功 | `220 ESMTP ready` / `250 OK` / `221 Bye` |
| **3xx** | 中間応答（次のコマンド待ち） | `354 Start mail input` (DATA の後) |
| **4xx** | 一時的失敗（リトライ可） | `421 Service not available` / `450 Mailbox busy` |
| **5xx** | 永続失敗（リトライ不可） | `500 Syntax error` / `550 User unknown` / `554 Relay denied` |

**第 2 桁の意味（RFC 5321 §4.2）:**

| 第 2 桁 | カテゴリ |
|---|---|
| x0x | 構文 |
| x1x | 情報 |
| x2x | コネクション |
| x5x | メールシステム |

例: `550` = 永続失敗 + メールシステムエラー = 「ユーザーが存在しない・メールボックスが利用不可」

### 主要コマンドの状態遷移

```
[接続成立]
    │ 220 (サーバから)
    ▼
[EHLO / HELO 待ち]
    │ EHLO test → 250-機能リスト
    ▼
[MAIL FROM 待ち]
    │ MAIL FROM:<sender@example.test> → 250 OK
    ▼
[RCPT TO 待ち] ───┐ (複数宛先なら RCPT TO を繰り返す)
    │              │
    │ RCPT TO:<recipient@example.test> → 250 OK
    ▼              │
[DATA 待ち] ◀──────┘
    │ DATA → 354 (本文入力開始)
    ▼
[本文入力中]
    │ (本文を送信、終了は単独行の "." )
    │ . → 250 OK
    ▼
[次のメール送信 or QUIT]
    │ QUIT → 221 Bye
    ▼
[切断]
```

**攻撃者の視点で重要なポイント:**

- **`MAIL FROM` / `RCPT TO` で応答コードが変わる** → これが Open Relay 判定（§4）と RCPT TO バウンス列挙（§3）の根拠
- **EHLO 応答に対応機能リスト** → AUTH メカニズム・PIPELINING・SIZE 制限が分かる
- **`HELP` / `VRFY` / `EXPN` は EHLO 後の任意のタイミングで実行可能**

---

## 3. HELO vs EHLO（ESMTP 拡張）

### HELO（古典 SMTP, RFC 821）

```
HELO test
250 mail.example.test
```

応答は **1 行のみ**。サーバ名以外の情報なし。

### EHLO（ESMTP, RFC 1869 / RFC 5321）

```
EHLO test
250-mail.example.test
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH LOGIN PLAIN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
```

応答は **`250-` を冒頭に連続した複数行 → 最終行は `250 ` (空白)** で機能リストを返す。

| 機能 | 意味 |
|---|---|
| `PIPELINING` | 複数コマンドを一括送信可能（RFC 2920）。スプレー高速化に使われる |
| `SIZE [bytes]` | 受け付ける最大メールサイズ |
| `VRFY` / `EXPN` | ユーザー存在確認・メーリングリスト展開（§4 で詳説）|
| `STARTTLS` | 平文セッションを TLS にアップグレード（§5）|
| `AUTH [mechs]` | サポートする SASL メカニズム（PLAIN / LOGIN / NTLM / GSSAPI 等）|
| `8BITMIME` | 8 ビット文字対応（旧 7 ビット制限の解放）|
| `DSN` | Delivery Status Notification（バウンスメッセージの形式指定）|

**なぜ EHLO が後から追加されたか:**

- 古典 SMTP (RFC 821, 1982) は「動けば良い」設計で、拡張機能を後から追加する仕組みがなかった
- 1995 年に ESMTP (RFC 1869) で「EHLO に対応していないサーバなら HELO にフォールバック」「対応サーバなら拡張機能リストを返す」という後方互換性のある拡張モデルを規定
- 現代のすべての MTA は EHLO 対応。HELO は廃止寄りだが互換性のため残っている

**攻撃側の使い方:**

- **AUTH メカニズム列挙**: `AUTH PLAIN` / `AUTH LOGIN` は平文 cred を Base64 で送る → 認証スプレーで `swaks --auth LOGIN`
- **AUTH NTLM** が広告される → Exchange の可能性大、NTLM スプレー候補
- **STARTTLS の有無** → 平文 cred 抽出可否の判断（§5）

---

## 4. VRFY / EXPN の歴史 — なぜ無効化されたか

### 古典 SMTP では「ユーザー検証」が標準機能だった

RFC 821 (1982) では:
- **VRFY**: 指定したユーザー名がそのサーバに存在するかを返す
- **EXPN**: メーリングリストのメンバーを展開して返す

`finger` と同じく「サーバ管理者間の協力前提」の機能だった。spammer がいなかった時代の設計。

### 1990 年代後半から spammer の悪用が広がる

- メールアドレス収集（harvesting）に VRFY が使われるようになった
- メーリングリストのメンバーを EXPN で抜いてフィッシングメールを送るケースが多発

### 現代の MTA はデフォルトで無効化

| MTA | デフォルト挙動 |
|---|---|
| Postfix | `disable_vrfy_command = yes`（2.x 以降のデフォルト） |
| Exim | `acl_smtp_vrfy` で明示禁止が一般的 |
| Sendmail | `O PrivacyOptions=goaway` で VRFY/EXPN 拒否 |
| Microsoft Exchange | デフォルト無効 |

応答は `252 Cannot VRFY user; try RCPT to attempt delivery` または `502 Command not implemented` に統一される。

### 攻撃側の代替経路: RCPT TO バウンス列挙

VRFY/EXPN が無効化されても、**`RCPT TO:<USER@DOMAIN>` の応答コードでユーザー存在を判定できる**:

| 応答 | 示唆 |
|---|---|
| `250 OK` | ユーザー存在（または catch-all） |
| `550 User unknown` | 不在確定 |
| `451 Try again later` | グレーリスティング・一時遅延（存在判定保留） |
| 全部 `250` で同じ | catch-all 設定・列挙無効 |

**`smtp-user-enum -M RCPT` がこれを自動化**している。

**なぜこの経路を塞ぐのが難しいか:** RCPT TO は本来の配送に必要な機能なので無効化できない。応答を全部 `250` に統一する catch-all 設定が唯一の対策だが、迷惑メールを大量に受けるトレードオフがある。

---

## 5. STARTTLS / SMTPS / Implicit TLS

### TLS が後付けされた経緯

SMTP (1982) は **平文前提のプロトコル**。1990 年代後半に TLS 化が必要になったが、すでに広く使われていた 25 番ポートを TLS 専用にできなかった。

2 つのアプローチが並存:

| 方式 | ポート | 動作 | RFC |
|---|---|---|---|
| **STARTTLS（明示 TLS）** | 25 / 587 / 143 / 110 | 平文で接続 → `STARTTLS` コマンドで TLS にアップグレード | RFC 3207 (2002) |
| **Implicit TLS（暗黙 TLS）** | 465 / 993 / 995 | 接続時点で即 TLS ハンドシェイク | RFC 8314 (2018) で正式復活 |

### 465 番ポートの歴史的混乱

- 1997 年: IANA が 465 を `smtps` として割り当て
- 1998 年: IETF が「STARTTLS の方が良い」として 465 の使用を非推奨化
- 結果: 多くの実装が 465 をサポートし続けた
- 2018 年: RFC 8314 で **465 を Submission over Implicit TLS として正式復活**

**現代の Submission ポート使い分け:**

| ポート | 用途 | 認証 | TLS |
|---|---|---|---|
| 25 | MTA-to-MTA relay | 通常なし | オプション (STARTTLS) |
| 465 | MUA-to-MSA submission | 必須 | 必須 (Implicit) |
| 587 | MUA-to-MSA submission | 必須 | オプション → 必須 (STARTTLS) |

### STARTTLS の弱点: STRIPTLS / Downgrade Attack

STARTTLS は「平文で接続 → TLS にアップグレード」する設計上、**TLS 開始前のトラフィックは平文**。MitM 攻撃者が:

```
クライアント → STARTTLS → サーバ
                ↑
            MitM が改ざん
                ↓
クライアント ← "500 Command not implemented" ← MitM
```

のように STARTTLS 応答を 5xx に書き換えると、クライアントは「TLS 非対応」と判断して **平文セッションで cred を送る** ことがある。

**対策:**

- **MTA-STS (RFC 8461)**: ドメインが TLS 必須を DNS で公開し、クライアントが強制する
- **DANE TLSA (RFC 7672)**: DNSSEC で TLS 証明書を固定
- **Implicit TLS (465/993/995)** に切り替える: TLS 開始前の平文区間が無いので STRIPTLS が成立しない

**攻撃側の視点:** 平文 25 番ポートが外部公開されている環境では、ネットワーク観測ができれば STARTTLS の有無に関わらず認証情報が抜ける可能性がある（受動的盗聴）。

---

## 6. POP3 vs IMAP

両方とも MUA がメールスプールからメールを取得するプロトコルだが、**設計思想が根本的に異なる**。

| 観点 | POP3 (RFC 1939) | IMAP (RFC 3501) |
|---|---|---|
| メールの保管場所 | クライアント側（取得後サーバから削除が原則） | サーバ側（クライアントは「同期」する） |
| 複数デバイスからのアクセス | 困難（最初に取った端末にメールが残る） | 容易（全デバイスが同じ状態を見る）|
| フォルダ概念 | なし（INBOX のみ）| あり（Sent / Trash / カスタムフォルダ）|
| 状態保持 | クライアント側で完結 | サーバ側でフラグ管理（既読 / フラグ / 削除予定）|
| プロトコルの状態数 | 3 状態（AUTH → TRANSACTION → UPDATE）| 4 状態（NotAuthenticated → Authenticated → Selected → Logout）|

### POP3 のコマンド（最小）

```
USER [user]      → +OK
PASS [pass]      → +OK Logged in.
LIST             → 1 octets / 2 octets / ... のメール一覧
RETR 1           → 1 通目を全文取得
DELE 1           → 1 通目を削除予定マーク
QUIT             → コミット（DELE が反映）
```

### IMAP のコマンド（タグ付き）

```
. LOGIN [user] [pass]              → . OK Logged in
. LIST "" "*"                       → フォルダ一覧
. SELECT INBOX                      → フォルダを開く
. FETCH 1 BODY[]                    → 1 通目を全文取得
. STORE 1 +FLAGS (\Deleted)         → 削除フラグ
. EXPUNGE                           → 削除確定
. LOGOUT                            → 終了
```

**先頭の `.` はタグ**。クライアントが任意の識別子を付けて、応答も同じタグで返ってくるので、**並列リクエスト**が可能（POP3 は 1 リクエストずつ）。

### なぜ IMAP が主流になったか

- スマートフォン普及（2007〜）で「複数デバイスから同じメールを見たい」需要が爆発
- POP3 は基本的に 1 端末前提なので、Webmail / モバイル / PC の同期が破綻
- IMAP は同期前提なので Gmail / Outlook.com / 企業 Exchange すべて IMAP / Exchange ActiveSync ベース

**攻撃側の視点:**

- **POP3 認証突破** → 1 端末でメール一括取得して終わり（サーバ側に履歴残らないこともある）
- **IMAP 認証突破** → フォルダ単位で精査可能（Sent / Drafts / カスタム）。**フラグ操作で「未読」を保てる** ので発覚しにくい（`STORE` で `\Seen` を削除）

---

## 7. SPF / DKIM / DMARC — 送信元偽装対策の三層

メールヘッダの **From: は送信者が自由に書ける**（手紙の差出人欄と同じ）。これがフィッシングの根本原因。3 つのメカニズムが順次追加された。

### SPF (Sender Policy Framework, RFC 7208)

**何を検証するか:** 「メールを送信した IP アドレス」がそのドメインの正規送信元か。

```
example.test の SPF レコード（DNS TXT）:
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all
```

- `ip4:203.0.113.0/24` = この IP レンジは OK
- `include:_spf.google.com` = Google の SPF も継承
- `-all` = 上記以外は **hard fail**（拒否推奨）

**問題点:**

- **メール転送（forwarding）で壊れる**: A→B→C と転送すると、C から見ると送信元 IP は B（A の SPF レンジ外）
- **検証対象は SMTP の `MAIL FROM` (envelope from)**。ヘッダの **`From:` は検証しない**ので、`MAIL FROM:<attacker@attacker.com>` + `From: ceo@example.test` で SPF パスしてしまう

### DKIM (DomainKeys Identified Mail, RFC 6376)

**何を検証するか:** 「メール本文 + 一部ヘッダ」が送信側で署名されているか。

送信側 MTA がメールに `DKIM-Signature` ヘッダを追加:

```
DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=default;
    h=from:to:subject; bh=[BODY_HASH]; b=[SIGNATURE]
```

受信側は DNS の `default._domainkey.example.test` から公開鍵を取得して署名検証。

**SPF より強い点:**

- 転送されても署名は維持される（本文・ヘッダが改ざんされない限り）
- ヘッダの `From:` も署名対象に含められる

**問題点:**

- 単独では「署名が無いメール / 失敗したメール」の扱いを決められない
- セレクタ（`default` / `google` / `selector1` 等）の名前は組織依存・予測しにくい

### DMARC (Domain-based Message Authentication, RFC 7489)

**何を統合するか:** SPF と DKIM の結果を集約し、**失敗時の挙動と報告先**をドメイン所有者が指定。

```
example.test の DMARC レコード:
_dmarc.example.test TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.test; adkim=s; aspf=s"
```

| パラメータ | 意味 |
|---|---|
| `p=none` | 監視のみ（拒否しない）|
| `p=quarantine` | スパム判定 |
| `p=reject` | 拒否 |
| `rua=mailto:...` | 集約レポート送信先 |
| `adkim=s` / `aspf=s` | DKIM/SPF の strict alignment（`r` は relaxed） |

**alignment の重要性:**

DMARC は「**ヘッダ `From:` のドメインと、SPF/DKIM が検証したドメインが一致しているか**」をチェック。これにより、`MAIL FROM:<attacker@attacker.com>` で SPF パスしても **DMARC ではヘッダ From: との不一致で拒否**できる。

### 攻撃側の視点

- **SPF が `~all` (soft fail)** / **DMARC が `p=none`** の組織はフィッシング基盤化に脆弱
- **SPF が `-all` + DMARC `p=reject`** の組織でも、**サブドメインに SPF/DMARC が無い** ことがある（`mail.example.test` は厳格でも `support.example.test` は未設定 等）
- **DKIM セレクタ名は推測**: `default` / `selector1` / `selector2` / `google` / `mandrill` / `mailgun` 等が定番

---

## 8. メールヘッダの読み方

メールヘッダには **配送経路の全情報** が記録されている。攻撃側は偽装メール調査・侵入経路の追跡に使う。

### Received: チェーン

```
Received: from mail.attacker.example.invalid (203.0.113.42)
    by mx.recipient.example.test with ESMTPS id ABC123
    for <victim@recipient.example.test>; Mon, 24 May 2026 10:00:00 +0900
Received: from internal-mta.attacker.example.invalid (192.0.2.10)
    by mail.attacker.example.invalid with ESMTP id XYZ789
    for <victim@recipient.example.test>; Mon, 24 May 2026 09:59:55 +0900
```

**ポイント:**

- **逆順で読む**（一番下が最初の経路、一番上が最後）
- 各 Received: は「`from` 元サーバ → `by` 受信サーバ」の経路を記録
- **MTA は受信時に Received: を追加する** ので、改ざんできるのは「自分が追加する 1 行」のみ（既存の Received: は通常変えない）

### From / Sender / Return-Path の違い

| ヘッダ | 意味 |
|---|---|
| `From:` | 表示上の送信者（自由記述・偽装可能） |
| `Sender:` | 実際の送信者（From と異なる場合は表示される） |
| `Return-Path:` | バウンス先（= SMTP の MAIL FROM の値）|
| `Reply-To:` | 返信先（指定があれば From より優先される）|

フィッシングの典型は `From: ceo@example.test` + `Reply-To: attacker@attacker.example.invalid` の組合せ。

### Authentication-Results ヘッダ

DMARC / SPF / DKIM の検証結果が記録される:

```
Authentication-Results: mx.recipient.example.test;
    dkim=pass header.d=example.test header.s=default;
    spf=pass smtp.mailfrom=sender@example.test;
    dmarc=pass action=none header.from=example.test
```

**攻撃調査・防御側で最重要**。`dmarc=fail` ならフィッシングの可能性大。

---

## 9. MIME 構造

メール本文は元々 7 ビット ASCII 前提。日本語・添付ファイル・HTML を扱うため **MIME (Multipurpose Internet Mail Extensions, RFC 2045-2049)** が追加された。

### 基本構造

```
Content-Type: multipart/mixed; boundary="BOUNDARY1"

--BOUNDARY1
Content-Type: multipart/alternative; boundary="BOUNDARY2"

--BOUNDARY2
Content-Type: text/plain; charset=UTF-8

平文本文

--BOUNDARY2
Content-Type: text/html; charset=UTF-8

<html>...</html>
--BOUNDARY2--

--BOUNDARY1
Content-Type: application/pdf; name="document.pdf"
Content-Disposition: attachment; filename="document.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK... (Base64 エンコード済みファイル)

--BOUNDARY1--
```

| Content-Type | 意味 |
|---|---|
| `multipart/mixed` | 本文 + 添付（混合） |
| `multipart/alternative` | 同じ内容の異なる表現（平文版 + HTML 版を MUA が選択）|
| `multipart/related` | HTML + インライン画像（cid: 参照） |
| `text/plain` | 平文 |
| `text/html` | HTML（XSS / リンク偽装の温床）|
| `application/pdf` 等 | 添付ファイル |

### Content-Transfer-Encoding

| 方式 | 用途 |
|---|---|
| `7bit` | 旧 ASCII 範囲のみ（デフォルト） |
| `8bit` | 8 ビット文字（UTF-8 等）。`8BITMIME` 拡張対応サーバ間でのみ可 |
| `quoted-printable` | 多くが ASCII、一部が非 ASCII（日本語メールでよく使われる）|
| `base64` | バイナリ（添付ファイル） |

### 攻撃調査での使い方

- **添付ファイルを抜き出す**: Base64 デコードで元バイナリを復元 → `Binary_Analysis.md` / `Metadata_Analysis.md` 経路
- **HTML パート内のリンク偽装**: `<a href="https://attacker.example.invalid">https://bank.example.test</a>` のような表示テキストと href の不一致
- **インライン画像の cid: 参照**: HTML 内の `<img src="cid:image001.png">` は同じメッセージ内の MIME パートを参照

---

## 10. 認証メカニズム（SASL）

SMTP / IMAP / POP3 の認証は **SASL (Simple Authentication and Security Layer, RFC 4422)** で抽象化されている。EHLO 応答の `AUTH [メカニズム名]` で対応メカニズムが分かる。

| メカニズム | 動作 | セキュリティ |
|---|---|---|
| `PLAIN` | `\0[user]\0[password]` を Base64 で送信 | **TLS 必須**（Base64 は暗号化ではない） |
| `LOGIN` | Base64 で user → Base64 で password の 2 ステップ | **TLS 必須** |
| `CRAM-MD5` | サーバ challenge → HMAC-MD5 で応答 | 平文より強い、現代では弱い |
| `NTLM` | Windows NTLM 認証 | Exchange / Windows 環境 |
| `GSSAPI` | Kerberos | AD 環境・MIT Kerberos |
| `XOAUTH2` | OAuth 2.0 トークン | Google / Microsoft 365 の現代の標準 |
| `EXTERNAL` | TLS クライアント証明書 | mTLS 環境 |

**攻撃側の使い分け:**

- **`AUTH PLAIN` / `AUTH LOGIN` が露出** + **TLS 不要** → 平文 cred 盗聴・スプレー両方の経路
- **`AUTH NTLM` が露出** → Exchange 環境確定・NTLM スプレー対象
- **`AUTH GSSAPI` のみ** → Kerberos 認証必須・スプレー困難（事前に TGT 取得必要）
- **`AUTH XOAUTH2` のみ** → トークン経由・OAuth フィッシング経路が主軸（別カテゴリ）

---

## 11. Open Relay の歴史と現代

### 1990 年代の標準動作

古典 SMTP では **すべての MTA が誰からのメールでも受けて誰へでも転送する** ことが想定されていた。Open Relay こそが「協力的なインターネット」の体現。

### Spamhaus / RBL の登場（1997-1998）

営利目的の spam の爆発に対し、**Open Relay の IP アドレスをブラックリスト化** する Realtime Blackhole List (RBL) が登場:

- Spamhaus (1998-)
- SBL (Spamhaus Block List)
- XBL (Exploits Block List)
- PBL (Policy Block List)

受信側 MTA が SMTP 接続時に送信元 IP を DNS クエリで RBL 照会し、ヒットしたら拒否する設計。

### 現代の Open Relay 状況

- **メジャーな MTA はデフォルトで認証必須・relay 拒否**
- 残存するのは:
  - レガシー機器（10 年以上前のアプライアンス・コピー機の SMTP）
  - 誤設定された自社内 MTA
  - 攻撃者が立てた「踏み台用」MTA

### 攻撃側の視点

- **Open Relay 発見の意義は薄い**: 見つけても送信元 IP がすぐ RBL 入りするので継続的な spam 基盤にはならない
- **finding として記録**するのが主用途。フィッシング 1 通限定での悪用なら可能性あるが、現代の受信側 SPF/DKIM/DMARC で大半は拒否される
- **オープンリレー探索ツール**: `nmap --script smtp-open-relay` は 16 パターンを内部で試行（外部宛・サブドメイン宛・% トリック等の歴史的パターン）

---

## 12. SMTP Smuggling と EOD シーケンス解釈差

Open Relay が事実上死んだ現代において「正規ドメインから詐称メールを送る」手段として **2023 年 12 月に Timo Longin (SEC Consult) が公開した攻撃**。SPF / DKIM / DMARC を完全にバイパスして受信側で `dmarc=pass` を取れる。Portswigger "Top 10 Web Hacking Techniques 2023" 3 位。

### EOD シーケンスとは

SMTP の `DATA` コマンドの本文は **`<CRLF>.<CRLF>`（改行 + 単独ドット行 + 改行）** で終端する (RFC 5321 §4.1.1.4)。受信側はこの 5 バイト列が来るまで本文を読み続ける。

しかし「`<CRLF>.<CRLF>` だけが正しい EOD」というルールは現代の MTA 実装でゆるく解釈されることがある:

| EOD 候補 | RFC 上の扱い | 実装での扱い |
|---|---|---|
| `<CRLF>.<CRLF>` | 標準 (RFC 5321 §4.1.1.4) | 全 MTA で EOD として認識 |
| `<LF>.<LF>` | RFC 5321 §2.4 で「**MUST NOT be treated as equivalent**」と明示禁止 | 多くの MTA が EOD として認識してしまう |
| `<CR>.<CR>` | 標準外 | Cisco Secure Email 等が EOD として認識 |
| `<LF>.<CR><LF>` | 標準外 | Postfix デフォルトが EOD として認識 |

RFC 5321 と RFC 5322 (メッセージフォーマット) の表現に微妙な乖離があり、各実装が「どこまで寛容に受け入れるか」の判断にばらつきが残っている。

### なぜ outbound と inbound で解釈が乖離するか

メール配送は **送信 MTA (outbound) → 受信 MTA (inbound)** の組合せで完結する:

- **outbound**: ユーザーが submission ポート (587) 経由で送るメールを受け取り、SMTP relay (25) 経由で外部 MTA に転送する役割
- **inbound**: 外部 MTA から SMTP relay (25) 経由でメールを受け取り、ローカルメールスプールに配送する役割

送信側 SaaS (GMX / Exchange Online 等) は **「ユーザーが送ったメッセージを sanitize する責任」** を持ち、非標準 EOD は通常 `<CRLF>.<CRLF>` に正規化される **はず**。が、2023 年時点で多くの大手 SaaS が **sanitize を実装していなかった**。

受信側は逆に **「受信したメッセージをローカルに配送する責任」** を持ち、`<CRLF>.<CRLF>` 以外を受け入れるべきではない。が、Cisco / Postfix / Sendmail のデフォルト構成は **`<LF>.<LF>` や `<CR>.<CR>` を EOD として受け入れる** ことが多い。

この **「outbound 側は sanitize せず、inbound 側は寛容に解釈する」** という非対称が SMTP Smuggling 成立の根本原因。

### Smuggling 成立の手順

1. 攻撃者が submission 587 経由で 1 通のメールを outbound MTA に送る
2. 本文中に `<LF>.<CR><LF>` を埋め、その後ろに **第 2 のメッセージ (`MAIL FROM:<spoofed>` 〜 `<CRLF>.<CRLF>`)** を続ける
3. outbound 側は **`<CRLF>.<CRLF>` だけを EOD と見て**、本文全体を 1 通として受け入れる
4. outbound 側が inbound 側に SMTP relay する際、本文をそのまま転送 (sanitize なし)
5. inbound 側 (Postfix / Cisco 等) は **`<LF>.<CR><LF>` を EOD と解釈**して本文を 2 通に分割
6. 第 2 のメッセージは `MAIL FROM:<spoofed@example.test>` で始まるため、**送信元 IP は正規 outbound MTA** のまま、**SMTP envelope の送信者は攻撃者の自由指定**になる

### SPF / DKIM / DMARC バイパスの仕組み

DMARC の alignment 検証は:

- **SPF alignment**: `MAIL FROM:` のドメインが、SPF レコードに記載された IP レンジから送信されているか
- **DKIM alignment**: `DKIM-Signature` ヘッダの `d=` が `From:` ヘッダのドメインと一致するか

Smuggling で生まれた第 2 メッセージは:

- 送信元 IP = 正規 outbound MTA → **SPF は spoofed ドメインの正規送信元として通る**
- DKIM 署名は outbound 側が付与 → spoofed の From: と一致 → **DKIM alignment も通る**
- 結果として **DMARC `p=reject` でも受信される**

§7 で説明した SPF/DKIM/DMARC の "三層防御" が、EOD パース層で生まれた envelope/header の偽装に対しては無力になる。

### BDAT / CHUNKING (RFC 3030) との関係

`BDAT` コマンド (RFC 3030 CHUNKING 拡張) は本文サイズを事前指定して送信する方式で、EOD シーケンスを使わない。BDAT を使う送信は Smuggling の影響を受けない。

ただし:

- **多くの MTA は CHUNKING を広告しない**（Postfix 推定 50% / Sendmail 99% 以上で未対応 / 2023 年時点・要再確認）
- **outbound 側が BDAT を強制できない**（送信側クライアントの実装次第）

`EHLO` 応答に `CHUNKING` が含まれない MTA は Smuggling 成立可能性が高いという判別材料になる。

### 修正方針

- **送信側**: 提出されたメッセージから非標準 EOD シーケンスを除去・正規化
- **受信側**: `<CRLF>.<CRLF>` 以外を EOD として受け入れない・bare `<LF>` を含む行を拒否
- Postfix: `smtpd_forbid_bare_newline = yes`（3.5.23 / 3.6.13 / 3.7.9 / 3.8.4 で追加と記憶・要検証）
- Cisco Secure Email: CR/LF handling の "Clean" 設定を "Allow" または "Reject" に変更

### 攻撃側の視点

- **既存防御 (SPF/DKIM/DMARC `p=reject`) が無力化される**ため、フィッシング目線で価値が高い
- ただし **outbound 側の特定** が必要（どの送信 SaaS が sanitize 未対応か）。2023 年公開当初は GMX / Exchange Online が該当したが現在は修正済
- **2026 年現在は Postfix / Sendmail のデフォルト構成 + sanitize 未対応 outbound** の組合せが残存していそう（未検証）
- 攻撃手順は [`../02_Initial_Access/Mail_Services.md`](../02_Initial_Access/Mail_Services.md) §6 を参照

---

## 関連技術

- 関連:メール系プロトコル攻撃の手順（バナー〜認証突破〜既知 CVE）→ [`../02_Initial_Access/Mail_Services.md`](../02_Initial_Access/Mail_Services.md)
- 関連:STARTTLS / TLS 構成の詳細監査（cipher suite / 名前付き脆弱性）→ [`../01_Reconnaissance/TLS_Audit.md`](../01_Reconnaissance/TLS_Audit.md)
- 関連:SPF / DKIM / DMARC の前段となる DNS レコード取得 → [`../01_Reconnaissance/DNS_Enumeration.md`](../01_Reconnaissance/DNS_Enumeration.md)
- 関連:MIME 添付の解析（OLE2 / PDF / Office メタデータ）→ [`../02_Initial_Access/Binary_Analysis.md`](../02_Initial_Access/Binary_Analysis.md) / [`../01_Reconnaissance/Metadata_Analysis.md`](../01_Reconnaissance/Metadata_Analysis.md)
- 関連:SASL の認証メカニズム共通基盤（NTLM / Kerberos / GSSAPI）→ [`./PAM.md`](./PAM.md) は PAM だが認証アーキの参考
- 関連:外部リファレンス（RFC / OWASP 等の原典）→ [`./External_References.md`](./External_References.md)
