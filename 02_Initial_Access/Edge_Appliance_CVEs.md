# エッジアプライアンス既知 CVE — 初手として照合する一群

## このファイルの位置づけ

インターネット境界に置かれるベンダー製アプライアンス（SSL-VPN ゲートウェイ / 次世代ファイアウォール / ロードバランサー）に対して、
**「製品が判明したらまず照合する既知 CVE」** をベンダー別に集約する。

- ターゲット製品の特定（証明書 Issuer / Server ヘッダー / favicon ハッシュ / ログイン HTML タイトル等）は `01_Reconnaissance/` 配下で済んでいる前提
- CVE 個別の **長文 PoC・ペイロード・バージョン対応の細部** は `../05_Tools_Reference/CVE_Notes.md` 側に置く
- 本ファイル側は **「ベンダー → 該当 CVE 行 → CVE_Notes の該当セクションへ」の遷移表** に徹する
- どれも **「業務停止 / 持続化 / 不可逆設定変更 / SIEM 検知必至」のいずれかに該当する HIGH IMPACT 攻撃** であり、本番では事前合意必須

対象ベンダー（過去 2 〜 3 年で影響が大きかった代表 RCE / 認証バイパスのみを扱う）：

- Citrix（NetScaler ADC / Gateway）
- Fortinet（FortiGate / FortiOS / FortiManager）
- Ivanti（Connect Secure / Pulse Secure / EPM）
- Palo Alto Networks（PAN-OS GlobalProtect）
- F5（BIG-IP TMUI / iControl REST）

---

## エッジアプライアンス CVE 照合の全体像

### 着火条件

以下のいずれかが揃った時点で、辞書攻撃や OS / Web 系 CVE 探索より先にエッジアプライアンス CVE 照合を試す候補にする。

- `TLS_Audit.md` で取得した証明書の **Issuer / Subject CN / SAN に製品名・ベンダー名** が含まれている（`CN=*.fortinet.com` / `Issuer=Citrix` / `O=Palo Alto Networks` 等）
- `Web_Enumeration.md` で **ログインページの HTML タイトル / URL パス / favicon ハッシュ** がベンダー固有のシグネチャと一致した（後述のフィンガープリント表）
- ポートスキャンで **アプライアンスが典型的に使うポート組合せ** が観測された
  - `443/tcp` + `8443/tcp` + `4443/tcp`：NetScaler ADC / FortiGate 管理 GUI
  - `443/tcp` + `10443/tcp`：FortiGate SSL-VPN ポータル
  - `443/tcp` + `8443/tcp` + `4434/tcp`：Ivanti Connect Secure
  - `443/tcp` GlobalProtect Portal：Palo Alto
  - `443/tcp` + `8443/tcp` TMUI：F5 BIG-IP
- `Default_Credentials.md` で当該アプライアンスのデフォルト認証情報が **既に変更されている** ことが判明した（→ 認証回避系 CVE に切り替える）
- バナーや管理 UI に **製品バージョン文字列** が露出している（`Build` / `Version` ヘッダー / メタタグ）

### 環境前提

- 実行環境：テスター端末
- 必要なツール：
  - `curl`（標準搭載。バージョン取得・PoC リクエスト送信の 1 発確認）
  - `nuclei`（別途インストール要、`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`。**`cves/` カテゴリにアプライアンス系 CVE テンプレートが網羅されている**。インターネット遮断 VLAN では事前に `nuclei-templates` リポジトリをクローン同梱）
  - `searchsploit`（ペネトレ用 Linux ディストリ標準。バージョン判明後の CVE と PoC スクリプトの即時検索。詳細は `../05_Tools_Reference/Searchsploit.md`）
  - `git`（標準搭載。GitHub 上の PoC リポジトリ取得）
  - `python3`（標準搭載。GitHub 配布 PoC スクリプトの実行）
  - `openssl`（標準搭載。製品判定用の証明書取得）
  - **外部リソース依存：** Shodan / FOFA / Censys の Web UI / API（製品分布調査・フィンガープリント確認）。**事前合意の対象（オフサイト OSINT）** のため、案件によっては使えない

オフライン代替：
- `nuclei-templates` は事前クローン同梱
- Shodan / FOFA が使えない場合は **オンサイトで取得した証明書 / バナー / HTML 文字列を本ファイルのフィンガープリント表と照合** する手順に切り替える

### 観点・着眼点

**先に確認すること：**

- **そのアプライアンスが「本物の本番境界デバイス」か「ステージング / DMZ 上のテスト機」か**。本番にいる場合、PoC が業務停止を引き起こすと顧客全体に影響する。事前合意で「対象がどの装置か」「業務時間外の試行可否」を必ず取り直す
- **アプライアンス背後のサービス（社内 AD / 業務アプリ）への到達性。** RCE 後の横展開リスクが「装置単体侵害」ではなく「社内ネットワーク侵害」に直結する場合がある
- **同型機器が複数 IP に存在するか。** Shodan / 内部 NMAP の結果で複数台ある場合、1 台で動作確認 → 全台に同一手順を流す前に **個別に事前合意した範囲か** を再確認

**攻撃者の思考トレース：** エッジアプライアンスは **「製品名 + バージョン文字列」が判明した瞬間に既知 CVE への照合が決まる**。汎用辞書攻撃や OS 系 CVE 探索より、**ベンダー固有 CVE の方が「初手」の命中率が圧倒的に高い**。これは以下の構造に由来する：

1. アプライアンスは **管理面が Web で露出している** ため、HTTP リクエスト 1 発で版数判定が可能
2. パッチサイクルが **管理者の手作業に依存する** ため、未パッチが残りやすい
3. 攻撃面が **ベンダーが公開している製品仕様 + 過去脆弱性** に限定されているため、研究者の解析対象として深く掘られている

ただし **同じ理由で SIEM ベンダーと EDR ベンダーも検知シグネチャを作っている**。各 CVE の `nuclei` テンプレート ID を覚えれば、検知側のシグネチャ名も推測しやすい（例：`Suricata rule "ET EXPLOIT Citrix NetScaler CVE-2023-3519"`）。

**製品フィンガープリント早見表（証明書・HTTP・ポートの相関）：**

| ベンダー / 製品 | 証明書（Issuer / SAN） | Server / HTTP ヘッダー | URL / HTML タイトル | favicon ハッシュ（mmh3） | 典型ポート |
|---------------|--------------------|-----------------------|------------------|------------------------|---------|
| Citrix NetScaler ADC / Gateway | `CN=NetScaler` / `O=Citrix` 自己署名 | `Server: NetScaler` / `Last-Modified` ヘッダーが固定値 | `/vpn/index.html` / `<title>NetScaler Gateway` / `/logon/LogonPoint/tmindex.html` | `-1292118216`（NetScaler ログイン） | 443, 4443, 8443 |
| Fortinet FortiGate / FortiOS | `CN=FortiGate` / `O=Fortinet` 自己署名 | `Server: xxxxxxxx-xxxxx`（数字列）/ `Set-Cookie: SVPNCOOKIE` | `/remote/login` / `<title>Please Login` / `/logindisclaimer` | `945408572`（FortiGate SSL-VPN） | 443, 10443, 8443, 541 |
| Ivanti Connect Secure / Pulse Secure | `O=Pulse Secure` / `O=Ivanti` 自己署名 | `Server: PSA` / `Set-Cookie: DSID` | `/dana-na/auth/url_default/welcome.cgi` / `<title>Ivanti Connect Secure` | `-1467691705`（Ivanti ログイン） | 443, 8443 |
| Palo Alto GlobalProtect | `CN=*.[COMPANY]` 公的 CA が多い / `O=Palo Alto Networks` の場合あり | `Server: psgw`（PAN-OS 系） | `/global-protect/login.esp` / `<title>GlobalProtect Portal` | `-1499689981`（GlobalProtect） | 443, 4443 |
| F5 BIG-IP TMUI | `CN=localhost.localdomain` / `O=MyCompany` 自己署名（既定）| `Server: BIG-IP` / `Server: BigIP` / `Set-Cookie: BIGipServer` | `/tmui/login.jsp` / `<title>BIG-IP` / `/mgmt/tm/util/bash`（管理 API）| `-335242539`（BIG-IP TMUI ログイン） | 443, 8443 |

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| 証明書 `CN=NetScaler` または `/logon/LogonPoint/tmindex.html` が 200 | Citrix NetScaler 確定 | バージョン取得 → Citrix セクション照合 → CVE-2023-3519 / CVE-2023-4966 / CVE-2019-19781 を順に照合 |
| 証明書 `O=Fortinet` または `/remote/login` が 200 | FortiGate SSL-VPN 確定 | バージョン取得 → Fortinet セクション照合 → CVE-2024-21762 / CVE-2022-42475 / CVE-2023-27997 を順に照合 |
| `/dana-na/auth/url_default/welcome.cgi` が 200 | Ivanti Connect Secure 確定 | バージョン取得 → Ivanti セクション照合 → CVE-2023-46805 + CVE-2024-21887 チェーン照合 |
| `/global-protect/login.esp` が 200 | Palo Alto GlobalProtect 確定 | バージョン取得 → PAN-OS セクション照合 → CVE-2024-3400 照合 |
| `/tmui/login.jsp` が 200 / `Server: BIG-IP` | F5 BIG-IP 確定 | バージョン取得 → F5 セクション照合 → CVE-2022-1388 / CVE-2023-46747 照合 |
| ベンダー識別はできたがバージョン文字列が一切出ない | バージョン情報を意図的に隠している運用 | nuclei の検出系テンプレートで版数推定（リクエスト差分から推定するテンプレートがある）、または CVE 自体の応答差分で版数推定 |

---

## ベンダー別 CVE 照合表

各行は **「ベンダー」「CVE」「影響バージョン範囲」「フィンガープリント / 確認パス」「nuclei テンプレート ID」「PoC リポジトリ（GitHub）」「成功シグナル」「CVE_Notes へのリンク」** の遷移表として読む。
**実コマンド / ペイロード本文は `../05_Tools_Reference/CVE_Notes.md` 側のリンク先で参照する。**

### Citrix（NetScaler ADC / Gateway）

| CVE | 影響バージョン | 確認パス / フィンガープリント | nuclei テンプレート ID | PoC リポジトリ（GitHub）| 成功シグナル（HTTP レスポンスの特徴） | 詳細 |
|-----|--------------|----------------------------|---------------------|----------------------|------------------------------------|------|
| CVE-2023-3519 | NetScaler ADC / Gateway 13.0 < 13.0-91.13 / 13.1 < 13.1-49.13 / 12.1 EOL | POST `/gwtest/formssso?event=start&target=…` / ログインページ `/logon/LogonPoint/tmindex.html` から版数推定 | `cves/2023/CVE-2023-3519.yaml` | `Mandiant/Citrix-IOC-Scanner` / `lol-fofa/CVE-2023-3519`（コミュニティ PoC は本物の RCE 化は控えめ・到達性確認系が多い） | 認証なしリクエストに対し **`Content-Length:` が想定より大きい / `errorMessage`** などの内部状態フィールドがレスポンスに混入 | `../05_Tools_Reference/CVE_Notes.md#cve-2023-3519` |
| CVE-2023-4966（Citrix Bleed）| NetScaler ADC / Gateway 13.0 < 13.0-92.19 / 13.1 < 13.1-49.15 / 14.1 < 14.1-8.50 | GET `/oauth/idp/.well-known/openid-configuration` をベースに **異常に長い Host ヘッダー** を送信 | `cves/2023/CVE-2023-4966.yaml` | `assetnote/exploits` / `cisagov/CVE-2023-4966-Detection`（CISA 公式チェッカー） | レスポンスボディに **未初期化メモリ由来の文字列**（セッショントークン断片）が混入。`#` `cookie` `NSC_*` などのトークン形式が見える | `../05_Tools_Reference/CVE_Notes.md#cve-2023-4966-citrix-bleed` |
| CVE-2019-19781 | NetScaler ADC / Gateway 10.5 / 11.1 / 12.0 / 12.1 / 13.0 の特定ビルド以下 | GET `/vpn/../vpns/cfg/smb.conf` で **設定ファイルの中身が返る** か | `cves/2019/CVE-2019-19781.yaml` | `projectzeroindia/CVE-2019-19781` / `mpgn/CVE-2019-19781` | `[global]` / `workgroup` などの **smb.conf 内部の文字列がそのまま 200 で返却** される | `../05_Tools_Reference/CVE_Notes.md#cve-2019-19781` |

### Fortinet（FortiGate / FortiOS / FortiManager）

| CVE | 影響バージョン | 確認パス / フィンガープリント | nuclei テンプレート ID | PoC リポジトリ（GitHub） | 成功シグナル | 詳細 |
|-----|--------------|----------------------------|---------------------|------------------------|--------------|------|
| CVE-2024-21762（FortiOS SSL-VPN out-of-bound write）| FortiOS 7.4.0 〜 7.4.2 / 7.2.0 〜 7.2.6 / 7.0.0 〜 7.0.13 / 6.4.0 〜 6.4.14 / 6.2.0 〜 6.2.15 / 6.0 全般 | `/remote/login` 配下の特定リクエストハンドラに対する **不正な Chunked エンコーディング** | `cves/2024/CVE-2024-21762.yaml`（出ている場合）| `BishopFox/CVE-2024-21762-check`（到達性 / 脆弱性検知のみ。完全な RCE PoC は流通限定）| 検知用リクエストで **TCP 接続が異常切断 / 5xx が返らずタイムアウト** する挙動の差分。完全 RCE は再起動・カーネルクラッシュリスクあり | `../05_Tools_Reference/CVE_Notes.md#cve-2024-21762` |
| CVE-2022-42475（FortiOS SSL-VPN heap overflow） | FortiOS 7.2.0 〜 7.2.2 / 7.0.0 〜 7.0.8 / 6.4.0 〜 6.4.10 / 6.2.0 〜 6.2.11 / 6.0 全般 / FortiProxy 7.2.0 / 7.0.0 〜 7.0.6 | `/remote/error` または `/remote/login` の長大 POST ボディ | `cves/2022/CVE-2022-42475.yaml` | `delsploit/CVE-2022-42475`（到達性確認系。実 RCE は流通が限定的・国家攻撃者ペイロードが先行） | `Server:` ヘッダー欠落 / 即時 TCP RST。**装置のクラッシュ・再起動が記録される** | `../05_Tools_Reference/CVE_Notes.md#cve-2022-42475` |
| CVE-2023-27997（FortiOS SSL-VPN pre-auth RCE "XORtigate"） | FortiOS 7.2.0 〜 7.2.4 / 7.0.0 〜 7.0.11 / 6.4.0 〜 6.4.12 / 6.2.0 〜 6.2.14 / 6.0 全般 | `/remote/hostcheck_validate` への特定形式 POST | `cves/2023/CVE-2023-27997.yaml`（限定的） | `lexfo/xortigate-cve-2023-27997`（解析記事のみ。完全 PoC は限定流通） | リクエスト送信後に管理面のレスポンス遅延 / SSL-VPN プロセスの再起動シグナル | `../05_Tools_Reference/CVE_Notes.md#cve-2023-27997` |

### Ivanti（Connect Secure / Pulse Secure / EPM）

| CVE | 影響バージョン | 確認パス / フィンガープリント | nuclei テンプレート ID | PoC リポジトリ（GitHub）| 成功シグナル | 詳細 |
|-----|--------------|----------------------------|---------------------|----------------------|--------------|------|
| CVE-2023-46805 + CVE-2024-21887（**チェーン**：auth bypass + command injection） | Ivanti Connect Secure 9.x / 22.x（22.5R2.2 / 22.6R2.2 等の未パッチ全般） / Ivanti Policy Secure 同等 | `/api/v1/totp/user-backup-code/[PATH]` への traversal + `/api/v1/license/keys-status/[CMD]` | `cves/2024/CVE-2024-21887.yaml` + `cves/2023/CVE-2023-46805.yaml` | `rapid7/metasploit-framework`（公式モジュール `exploit/linux/http/ivanti_connect_secure_rce_cve_2024_21887`）/ `Chocapikk/CVE-2024-21887` / `assetnote/exploits` | 1 段目：認証なしで `/api/v1/` 配下の本来認証必須エンドポイントが 200 を返す / 2 段目：注入したコマンドの出力がレスポンスボディに直接含まれる | `../05_Tools_Reference/CVE_Notes.md#cve-2023-46805--cve-2024-21887-ivanti-connect-secure-chain` |
| CVE-2024-22024（Ivanti Connect Secure XXE）| Ivanti Connect Secure 9.x / 22.x の上記チェーンと同世代 / 一部の `SAML/[component]` エンドポイント | `/dana-ws/saml20.ws` 等の SAML 系エンドポイントへの外部エンティティ含む XML POST | `cves/2024/CVE-2024-22024.yaml` | `Chocapikk/CVE-2024-22024` | 外部エンティティとして指定したテスター制御 URL に **アウトバウンド HTTP リクエスト** が到達 / 内部ファイルパスのレスポンス取得 | `../05_Tools_Reference/CVE_Notes.md#cve-2024-22024` |
| Ivanti EPM 系（CVE-2024-29824 等）| Ivanti EPM 2022 SU5 以前 | EPM 管理 Web `RecordGoodApp.aspx` 等への SQLi | `cves/2024/CVE-2024-29824.yaml` | `horizon3ai/CVE-2024-29824` 等 | SQL エラー差分 / xp_cmdshell が有効化された MSSQL バックエンドでのコマンド実行戻り値 | `../05_Tools_Reference/CVE_Notes.md#cve-2024-29824-ivanti-epm` |

### Palo Alto Networks（PAN-OS GlobalProtect）

| CVE | 影響バージョン | 確認パス / フィンガープリント | nuclei テンプレート ID | PoC リポジトリ（GitHub）| 成功シグナル | 詳細 |
|-----|--------------|----------------------------|---------------------|----------------------|--------------|------|
| CVE-2024-3400（GlobalProtect arbitrary file create → RCE）| PAN-OS 10.2 < 10.2.9-h1 / 11.0 < 11.0.4-h1 / 11.1 < 11.1.2-h3 で **GlobalProtect Gateway / Portal 機能とテレメトリ機能が同時有効** | `/global-protect/login.esp` の **`SESSID` Cookie** に特殊値（`../`含むパス文字列）を設定 | `cves/2024/CVE-2024-3400.yaml` | `h4x0r-dz/CVE-2024-3400` / `W01fh4cker/CVE-2024-3400-RCE-Scanner`（到達性 / 検知系。完全 RCE は流通限定） | テレメトリ機能の cron 起動を待ち、テスター制御パスへの書込ファイルが **後刻別エンドポイントから読み戻せる** / OAST コールバック到達 | `../05_Tools_Reference/CVE_Notes.md#cve-2024-3400-globalprotect-arbitrary-file-create` |

### F5（BIG-IP TMUI / iControl REST）

| CVE | 影響バージョン | 確認パス / フィンガープリント | nuclei テンプレート ID | PoC リポジトリ（GitHub） | 成功シグナル | 詳細 |
|-----|--------------|----------------------------|---------------------|------------------------|--------------|------|
| CVE-2022-1388（iControl REST authentication bypass）| BIG-IP 11.6.x EOL / 12.1.x EOL / 13.1.0 〜 13.1.5 / 14.1.0 〜 14.1.4 / 15.1.0 〜 15.1.5 / 16.1.0 〜 16.1.2 / 17.0.0 | `/mgmt/tm/util/bash` への POST + 特殊な `X-F5-Auth-Token` / `Connection: X-F5-Auth-Token, X-Forwarded-Host` ヘッダー | `cves/2022/CVE-2022-1388.yaml` | `horizon3ai/CVE-2022-1388-Exploit` / `Al1ex/CVE-2022-1388` | レスポンスに **`utilCmdArgs` を解釈したシェルコマンドの実行結果** が JSON で返る（`id` の出力 / `/etc/passwd` の中身） | `../05_Tools_Reference/CVE_Notes.md#cve-2022-1388-big-ip-icontrol-rest-auth-bypass` |
| CVE-2023-46747（TMUI authenticated SSRF → admin creation）| BIG-IP 13.1.x / 14.1.0 〜 14.1.5 / 15.1.0 〜 15.1.10 / 16.1.0 〜 16.1.4 / 17.0.0 〜 17.1.0 | `/tmui/login.jsp` 経由の SSRF + `/mgmt/tm/auth/user/admin` への内部 PUT | `cves/2023/CVE-2023-46747.yaml` | `W01fh4cker/CVE-2023-46747-RCE` / `horizon3ai/CVE-2023-46747` | 攻撃後に **新規 admin 権限ユーザーが作成され、その認証情報で `/mgmt/tm/util/bash` にアクセス可能になる** | `../05_Tools_Reference/CVE_Notes.md#cve-2023-46747-big-ip-tmui-ssrf` |

---

## 手順

### Step 1：製品が判明したらまずバージョン取得

**事前準備（必須）：** `01_Reconnaissance/TLS_Audit.md` および `Web_Enumeration.md` でベンダーは特定済みの状態。本ファイルは「製品判定が済んでいる」前提でバージョン文字列を取りに行く段階から始まる。

```bash
# [Attacker] Citrix：ログインページ HTML 内のビルド表記 / Last-Modified ヘッダー
curl -sk -I https://[TARGET]/logon/LogonPoint/tmindex.html   # [Attacker]
curl -sk https://[TARGET]/logon/themes/Default/css/base.css | head -5   # [Attacker]
# 出力例：/* Build: NS13.0-91.10 */ 等のコメントが残っているケースあり

# [Attacker] Fortinet：ログインフォームの隠しメタタグ / Set-Cookie 形式
curl -sk -I https://[TARGET]/remote/login   # [Attacker]
curl -sk https://[TARGET]/remote/login\?lang=en | grep -iE "version|build"   # [Attacker]

# [Attacker] Ivanti：DSID Cookie 発行リクエスト + welcome.cgi の HTML タイトル
curl -sk https://[TARGET]/dana-na/auth/url_default/welcome.cgi | grep -iE "version|9\.|22\."   # [Attacker]

# [Attacker] Palo Alto：login.esp の隠しビルド情報
curl -sk https://[TARGET]/global-protect/login.esp | grep -iE "version|build"   # [Attacker]
curl -sk https://[TARGET]/global-protect/portal/css/login.css | head -5   # [Attacker]

# [Attacker] F5：TMUI ログインページの ngx_tmui バージョンヘッダー
curl -sk -I https://[TARGET]/tmui/login.jsp   # [Attacker]
```

### Step 2：nuclei で該当ベンダー CVE を一括スキャン

```bash
# [Attacker] ベンダー名でテンプレートを絞る（誤検出 / 巻き込み回避）
nuclei -t cves/ -tags citrix -u https://[TARGET]   # [Attacker]
nuclei -t cves/ -tags fortinet,fortios -u https://[TARGET]   # [Attacker]
nuclei -t cves/ -tags ivanti,pulse -u https://[TARGET]   # [Attacker]
nuclei -t cves/ -tags panos,palo-alto -u https://[TARGET]   # [Attacker]
nuclei -t cves/ -tags f5,bigip -u https://[TARGET]   # [Attacker]

# [Attacker] 特定 CVE だけを単独実行（業務影響を最小化）
nuclei -id CVE-2023-4966 -u https://[TARGET]   # [Attacker]
nuclei -id CVE-2024-21762 -u https://[TARGET]   # [Attacker]
nuclei -id CVE-2024-21887 -u https://[TARGET]   # [Attacker]
nuclei -id CVE-2024-3400 -u https://[TARGET]   # [Attacker]
nuclei -id CVE-2022-1388 -u https://[TARGET]   # [Attacker]
```

`nuclei` テンプレートは **検知系（脆弱性の存在確認まで）と RCE 系（実コマンド実行まで）が混在** している。本番では **検知系のみに絞る** か、`-headless=false -rl 1`（並列度 1、レート制限）で慎重に進める。

### Step 3：照合表のリンクから CVE_Notes の該当セクションへ

ベンダー / バージョンが一致した CVE 行の **「詳細」列のリンク先**（`../05_Tools_Reference/CVE_Notes.md#cve-...`）に飛び、**実ペイロード・成功シグナル・原状回復項目** を取得する。
本ファイルではペイロード本文は持たず、**「どの CVE に進めばよいか」** だけを示す。

### Step 4：PoC リポジトリの選定基準

GitHub に多数のリポジトリが乱立する CVE では、以下の優先順位で選ぶ：

| 優先度 | 選定基準 | 理由 |
|-----|--------|-----|
| 1 | ベンダー直 / CISA / Rapid7 / Mandiant / Horizon3 / Assetnote | 解析品質が高く、悪用ペイロード以外の検知 / 緩和情報も含む |
| 2 | 解析記事を出している研究者の個人リポジトリ（Watchtowr / Bishop Fox / Lexfo 等）| 一次解析が詳細。PoC 自体は到達性確認止まりで安全 |
| 3 | Star 数が多い + 最終コミットが直近 + README に PoC の前提条件が明記されている | 雑にフォークされた壊れた PoC を避けるため |
| 4 | 出所不明 / 投稿者が当該 CVE の解析実績なし | 検知側のハニーリポジトリ / バックドア入りの可能性。**clone 前に Issues / PR / コード差分を必ず読む** |

```bash
# [Attacker] PoC を clone する前に必ず差分確認
git clone https://github.com/[ORG]/[REPO].git   # [Attacker]
cd [REPO]
git log --oneline -20   # [Attacker]    # 最終コミット日 / 著者
git log -p HEAD~5..HEAD   # [Attacker]   # 直近差分
grep -rE "curl|wget|base64|eval|exec" .   # [Attacker]   # 隠しダウンロード / 実行系の有無
```

### Step 5：成功シグナルの確認

各 CVE の「成功シグナル」列に従って、**最小ペイロード（読み取り系・到達性確認系）でまず成立確認** する。完全 RCE は事前合意で承認された段階に進めてから実行する。

| 確認のステージ | 何を確認するか | 例 |
|------------|--------------|-----|
| ステージ 1：到達性 | 該当エンドポイントが想定通り応答するか | `/logon/LogonPoint/tmindex.html` が 200 で返るか |
| ステージ 2：脆弱版数 | バージョン文字列 / レスポンス差分から脆弱性該当か | nuclei 検知系テンプレートのヒット |
| ステージ 3：読み取り系 PoC | ファイル読み出し / トークン漏洩のみで RCE は行わない | CVE-2023-4966 の Cookie 抽出、CVE-2019-19781 の smb.conf 取得 |
| ステージ 4：RCE | 事前合意済みのときのみ。即時切り戻し前提 | OS コマンド 1 個実行（`id` / `hostname`）→ 速やかにセッション破棄 |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| nuclei が「matched 0」で全 CVE スルー | パッチ済み / WAF が前段に居て検査リクエストが書き換えられている | バージョン文字列を改めて取得し直す。WAF 前段なら別の到達経路（管理面ポート / SNI 別 FQDN）を確認 |
| 検知系テンプレートはヒットしたが PoC で 5xx / TCP RST | 装置がクラッシュ寄りの応答 | **業務停止リスク発火直前**。即時中止して事前合意の連絡先に共有 |
| バージョン文字列が `OEM` / 顧客カスタムビルドで一致しない | キャリア / OEM 提供のカスタム FW | 公開バージョン番号と OEM ビルド番号の対応表をベンダーサポートに確認。なければ Step 2 の nuclei 検知系のみで判断 |
| 管理面が公開 IP からアクセスできない | 管理面アクセス制御 ACL が効いている | ユーザー面（SSL-VPN ポータル）に絞って試行。管理面前提の CVE（F5 TMUI 系）は試行不可と記録 |
| 装置側で MFA / クライアント証明書 要求が出る | 強化された認証 | 認証バイパス系 CVE（CVE-2023-4966 / CVE-2023-46805 等）が候補。MFA は **認証段階の前段が無効化される CVE には効かない** ため再確認 |
| 装置が Active/Standby ペアの片肺 | スタンバイ機の応答が本番と異なる | 試行対象が本番系か事前合意済みの保守系か再確認。誤って本番に投げると業務停止 |
| 完全 RCE PoC が動かない / `curl` の応答だけは正常 | PoC のヘッダー順序 / TLS バージョン依存。あるいは PoC 自体が改竄されている | PoC コードを読み、本ファイル / CVE_Notes の **成功シグナル** に従って手動 1 リクエストで再構築 |

---

## 注意点・落とし穴

> **[HIGH IMPACT]** エッジアプライアンス系 CVE の悪用は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（装置クラッシュ・再起動・SSL-VPN セッション全切断）
> - [x] 持続化に該当（Web shell 配置・admin アカウント作成・SSH 鍵植え込み）
> - [x] 不可逆な設定変更を含む（admin 追加・テレメトリ機能改変・カーネルレベルパッチ書換）
> - [x] SIEM/EDR で確実に検知される（**ベンダー / CISA / 主要 SIEM ベンダー全てが個別 CVE のシグネチャを配布済み**。Suricata / Snort ルール、CrowdStrike / Microsoft Defender for Cloud / Palo Alto Cortex / Splunk ES の各検知ルールが存在）
>
> 実施可否は事前合意で明示確認すること。**RCE 系 PoC は実行可否を CVE 単位で個別承認すべき**（一括承認禁止）。演習環境（HTB / OSCP 等）では制約なし。

- **「装置の再起動が業務停止である」ことを忘れない。** SSL-VPN ゲートウェイの再起動は社外勤務全員のセッションを切る。`CVE-2024-21762` / `CVE-2022-42475` / `CVE-2023-27997` は **PoC の副作用としてプロセスクラッシュが起きる** ため、業務時間内の実行は禁止
- **国家攻撃者が先行利用する CVE が多い。** 過去事例として CVE-2024-3400 / CVE-2024-21887 等は **公開 PoC より先に IoC が公開される** ことがある。検査前にベンダー / CISA の最新アドバイザリで「侵害指標が既に出ていないか」を確認し、既に痕跡があれば顧客にエスカレーション
- **検知系のみ実行する場合でも、対象側 WAF / IPS のアラート / 自動ブロックが発火する。** 検査用 IP がブロックされて以降の作業ができなくなる、または顧客 SOC のインシデント対応コストが発生する。事前合意で「SOC への事前通知 / 検査時間枠」を必ず合意
- **PoC リポジトリの一部はバックドア入り。** GitHub に乱立する PoC は、検査側を狙ったマルウェアを混入させたものがある（特に作者プロフィールが新規 / Star 数だけ多い場合）。`Step 4` の選定基準を必ず守る
- **CVE-2024-3400（PAN-OS）はテレメトリ機能経由のため、テレメトリ無効環境では成立しない**。前提条件の確認を Step 1 で実施しない PoC は誤検知を出すので、PoC 出力を盲信しない
- **CVE-2023-4966（Citrix Bleed）は「セッショントークンの再利用」が攻撃の核心であり、ログオフ後も生存している既存セッションを横取りする**。攻撃成立後、**正規ユーザーのセッションが「別 IP からアクセスされた」事象として SIEM に必ず記録される**
- **CVE-2024-21887 + CVE-2023-46805 のチェーンは、`/api/v1/license/keys-status/` 経由のコマンド注入が出力をレスポンスに含む形式のため、検知側ログに実行コマンドがそのまま記録される**。原状回復時に「何を実行したか」のテスター側証跡が必要
- **同型機器が複数台ある場合、1 台で検知系成立 → 全台で同じ振る舞いをすると即決めない**。HA ペア / 同型バックアップで設定が異なる場合があり、本番系のみクラッシュする事故が起こる
- **アプライアンスの装置ログは容量が小さく上書きが速い**。攻撃時の証跡は **テスター側で完全記録** しないと、後日「何を送ったか分からない」状況になる。`tcpdump` / `mitmproxy` で送信側パケット全保存

**原状回復（共通項目）：**

- ✅ 試行で作成された装置上のファイル（Web shell / 一時ファイル / アップロードしたペイロード）の削除確認
- ✅ 攻撃で作成された admin / 一般ユーザーアカウントの削除確認（CVE-2023-46747 等）
- ✅ 攻撃で植え込まれた SSH 公開鍵の削除確認
- ✅ 取得したセッショントークン（Citrix Bleed 等）の破棄 → SIEM 側でセッション無効化を顧客に依頼
- ✅ 試行ログ（テスター側 pcap / curl 履歴）の暗号化保管・案件終了時破棄

```bash
# [Attacker] 案件識別子コメントマーカー方式で作業証跡を識別可能にする
echo "# kedalab-[CASE_ID] CVE-2024-21887 test at $(date -Iseconds)" >> /home/[USER]/cases/[CASE_ID]/edge_appliance_test.log   # [Attacker]
```

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。**RCE 系 PoC は CVE 単位で個別承認**。検知系のみの実行も SOC への事前通知必須。SSL-VPN ゲートウェイのクラッシュ / 再起動は業務停止に直結するため、業務時間外の試行枠を取得する
- **想定される SIEM / EDR 検知**:
  - Suricata / Snort：`ET EXPLOIT Citrix NetScaler CVE-2023-3519` / `ET EXPLOIT Fortinet SSL-VPN CVE-2022-42475` / `ET EXPLOIT Ivanti Connect Secure CVE-2024-21887` 等の公開ルールセットで検知
  - CrowdStrike Falcon：各ベンダー CVE の Custom IOA / IOC が標準提供
  - Microsoft Defender for Cloud / Defender XDR：エッジアプライアンス CVE は「公開された脆弱性に対するエクスプロイト試行」として高優先度アラート
  - Palo Alto Cortex XDR：自社製品 CVE-2024-3400 は確定検知。他社製品は IOC 経由検知
  - Splunk ES：CISA KEV 連携で当該 CVE は要求精度の高い相関ルールが標準
  - 装置側ログ：FortiOS は `eventtime` フィールド付きの SSL-VPN ログ、NetScaler は `/var/log/ns.log`、PAN-OS は `globalprotectd` ログ
- **業務影響リスク**: SSL-VPN ゲートウェイのクラッシュ → 社外勤務全員のセッション切断 / ファイアウォール再起動 → 通信全断 / アプライアンス HA フェイルオーバ発火 → 二次的な業務影響
- **原状回復必須項目**:
  - ✅ 作成された admin / 一般ユーザー / Web shell / SSH 鍵 / アップロードファイルの削除確認
  - ✅ 取得したセッショントークン・認証情報の暗号化保管 → 案件終了時破棄
  - ✅ 装置側ログを顧客に渡して「侵害指標と検査試行の区別」を支援
  - ✅ 試行内容（送信パケット / curl コマンド履歴 / nuclei 出力）の完全記録 → SOC への共有
- **取得情報の取扱**: 抽出した内部設定 / 認証情報 / セッショントークンはすべて暗号化保管。案件終了時に破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい。ただし演習環境ではアプライアンス系 CVE よりカスタム CVE が中心）

---

## 関連技術

- 前：証明書 Issuer / SAN / CN からアプライアンス製品名特定（Step 1 のバージョン取得の前段） → `../01_Reconnaissance/TLS_Audit.md`
- 前：ログイン HTML タイトル / URL パス / favicon ハッシュ / Server ヘッダーからアプライアンス確定 → `../01_Reconnaissance/Web_Enumeration.md`
- 前：典型ポート組合せでアプライアンス候補絞り込み → `../01_Reconnaissance/Network_Scanning.md`
- 前：管理コンソール誤公開でアプライアンス管理面を発見した場合 → `../01_Reconnaissance/Exposed_Files.md`
- 前：デフォルト認証情報が既に変更されている場合の代替経路として本ファイルへ → `./Default_Credentials.md`
- 前：認証バイパス系 CVE は **MFA を迂回するため、ロックアウト確認は不要だが SIEM 側の異常ログイン検知は別軸で発火する** ことの理解 → `./Account_Lockout_Recon.md`
- 後：個別 CVE のペイロード本文・成功シグナル詳細・バージョン対応表 → `../05_Tools_Reference/CVE_Notes.md`
- 後：PoC スクリプトのローカル検索・GitHub PoC 検索フロー → `../05_Tools_Reference/Searchsploit.md`
- 後：侵害成功後の装置内設定ファイル / RADIUS / AAA 設定からの認証情報抽出 → `./Credential_Discovery.md`
- 後：取得した認証情報 / セッショントークンでの SSH / WinRM / 社内サービスへの横展開 → `./Protocol_Exploitation.md`
