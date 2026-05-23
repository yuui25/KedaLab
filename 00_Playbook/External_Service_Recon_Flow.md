# インターネット露出サービス 初手判断フロー

調査対象がインターネットに直接露出しているIP / FQDNとして提供された場合の、製品識別から認証情報試行までの判断フロー。
各ステップの詳細は対応する .md を参照し、このファイル内には技術の説明を書かない。

> **本番の場合**：本フローに入る前にスコープ・実施可否・業務影響について事前合意を確認すること。
> 詳細は [`../README.md`](../README.md) Step 0 と [`../06_Concepts/Pentest_Fundamentals.md`](../06_Concepts/Pentest_Fundamentals.md) を参照。

> **「外部」スコープの用語について**：本フローの「外部」は NIST SP 800-115 §2.4.1 "External and Internal" で定義された業界標準のテスティングビューポイントに対応する（自組織のセキュリティ境界の外側、インターネット側からのテスト）。ガイドライン章マッピング → [`../TECHNIQUES_INDEX_GUIDELINES.md`](../TECHNIQUES_INDEX_GUIDELINES.md)。ガイドライン概要 → [`../06_Concepts/Pentest_Guidelines_Guide.md`](../06_Concepts/Pentest_Guidelines_Guide.md)

---

## このファイルをいつ使うか（着火条件）

以下のいずれかに該当したら本フローを開く：

- 開始時に「インターネット公開IP / FQDN」のみが渡され、認証情報もOSも不明な状態
- 対象がエッジアプライアンス（SSL-VPN ゲートウェイ / 次世代ファイアウォール / ロードバランサー）の疑いがある
- Webアプリケーションが公開URLとして提供されているが、サーバー構成・OS・フレームワークが不明な状態でテストを開始する
- Webサービスが公開されているが製品・フレームワーク不明の状態で調査を始める
- `00_OS_Identification.md` でOS特定に至らず「インターネット境界機器らしい」と判断された

> **Linux / Windows AD 環境と確定している場合は本フローは使わない。**
> → `Linux_Attack_Flow.md` または `Windows_AD_Attack_Flow.md` を参照する。
>
> **対象が通常のWebアプリケーションの場合：** Step 1〜2 のバナー取得・CVE照合後、Web層の脆弱性調査は `Web_Vuln_Flow.md` へ転換する。ペネトレとしてシェル取得を目指す場合は `Linux_Attack_Flow.md` Step 2 を参照。

---

## 開始条件の確認

**このファイルを開いたら最初にここを読む。** 手元にある情報によってスタート位置が変わる。

| 提供されている情報 | 開始位置 |
|------------------|---------|
| IPのみ（製品不明） | Step 1（ポートスキャン・バナー取得）から始める |
| FQDN / 組織名のみ（IP不明） | `../01_Reconnaissance/DNS_Enumeration.md` で WHOIS / DNS 取得 → Step 1へ（公開情報からの組織特定・関連 IP レンジ確認も含む） |
| IPとポートスコープ指定あり（例：443のみ） | 指定ポートの Step 1b（TLS証明書取得）から始める |
| 製品名は判明しているがバージョン不明 | Step 2（Edge CVE照合）へ直接進む |
| 製品名・バージョン判明 + CVE既確認 | Step 3（誤設定・誤公開）または Step 5（cred試行前確認）へ |
| 低権限認証情報が提供済み | Step 5（ロックアウト確認）→ Step 6（cred試行）の「提供済み認証情報での確認」へ |

> **「認証情報が提供済み」でも Step 1〜2 のバナー・CVE確認は一通り済ませる。**
> 製品バージョンに未パッチ CVE が残っている場合、認証情報不要のエクスプロイトの方が影響範囲が大きくなるため。

---

## フロー概要

```
[Step 1] ポートスキャン・バナー取得・製品識別    → 01_Reconnaissance/          【必須】
          ↓
[Step 2] Edge CVE照合（製品確定後の最初の一手）  → 02_Initial_Access/Edge_Appliance_CVEs.md  【必須】
          ↓ CVEなし・パッチ済み・対象外
[Step 3] 誤設定・誤公開ファイル確認              → 01_Reconnaissance/Exposed_Files.md        【条件次第】
          ↓
[Step 4] TLS弱点・証明書情報の確認              → 01_Reconnaissance/TLS_Audit.md            【条件次第】
          ↓
[Step 5] ロックアウトポリシー確認               → 02_Initial_Access/Account_Lockout_Recon.md 【必須：Step 6の前に必ず実施】
          ↓
[Step 6] デフォルト認証情報試行                 → 02_Initial_Access/Default_Credentials.md  【条件次第】
```

各ステップは「前のステップで得た情報」を次の判断に使う。スキップは判断根拠が記録できる場合のみ許容する。

**Step 着手の優先順位**：【必須】のStep（1・2・5）を先に完了させる。
【条件次第】のStep（3・4・6）は以下の着手条件で判定する：

| Step | 着手する条件 | 着手しない（後回し）条件 |
|---|---|---|
| Step 3（誤設定・誤公開） | Step 2 で悪用可能な CVE なし／製品が CVE 対象外／製品名のみ判明でバージョン不明 | Step 2 で悪用可能な CVE が見つかった（先に Step 2 を完遂） |
| Step 4（TLS監査） | 診断スコープに TLS 評価が含まれる、または証明書から組織情報を抜きたい | スコープに TLS 評価がなく、Step 1b で製品識別が済んでいる |
| Step 6（デフォルト認証情報） | Step 5 で「閾値あり・短時間でロック解除」または演習環境と確認できた | Step 5 でロックアウトが厳しい（5回で永久ロック等）／本番で対象組織承認なし |

Step 2 で CVE が見つかった場合はそこに集中し、Step 3〜6 は後回しにしてよい。

---

## Step 1 — ポートスキャン・バナー取得・製品識別

**目的：** 開いているポートと各サービスのバナーを取得し、対象製品・バージョンを特定する。

→ 詳細: `../01_Reconnaissance/Network_Scanning.md`

### Step 1 の判断分岐

| 得られたシグナル | 次のアクション |
|----------------|--------------|
| TLS ポート（443 / 8443 / 10443 等）が開いている | Step 1b（TLS証明書取得）へ → Step 2 |
| `Server:` ヘッダー / HTML タイトルに製品名が見える | Step 2（Edge CVE照合）へ |
| Web が応答するが製品不明 | `../01_Reconnaissance/Web_Enumeration.md` でフィンガープリント追加 |
| ポートスキャン結果が空（全ポートフィルタリング）| `../01_Reconnaissance/Network_Scanning.md` の「フィルタリング環境での追加オプション」セクションを参照 |
| メール系ポート（25 / 465 / 587 / 110 / 995 / 143 / 993）が開いている | `../02_Initial_Access/Protocol_Exploitation.md` の SMTP / POP / IMAP セクションへ（メールサーバー対象。ユーザー列挙・スプレー・オープンリレー確認） |

### Step 1b — TLS証明書から製品識別

TLS ポートが開いている場合は、証明書の `Issuer` / `Subject CN` / `SAN` が製品フィンガープリントの最短ルートになる。

→ 詳細: `../01_Reconnaissance/TLS_Audit.md`（「証明書情報による製品・組織推定」セクション）

| 証明書シグナル | 推定製品 |
|--------------|---------|
| `Issuer: Fortinet` / `O=Fortinet` | FortiGate / FortiOS |
| `CN=*.fortinet.com` | 同上 |
| `Issuer=Citrix` / `CN=*.[組織].com` + Citrix 固有パス | NetScaler ADC / Gateway |
| `O=Palo Alto Networks` | PAN-OS GlobalProtect |
| `CN=Ivanti` / ログイン URL に `/dana-na/` | Ivanti Connect Secure |
| `CN=*.f5.com` / `Issuer=F5` | BIG-IP TMUI |

製品が確定したら Step 2 へ。

---

## Step 2 — Edge CVE 照合

**目的：** 確定した製品・バージョンに対し、認証不要のRCE・認証バイパスCVEが適用できないかを照合する。

→ 詳細: `../02_Initial_Access/Edge_Appliance_CVEs.md`

> [HIGH IMPACT] このステップで発見した CVE は業務停止リスク・SIEM検知必至のものが多い。
> 実施前に本番スコープの事前合意を確認すること。

### Step 2 の判断分岐

| 結果 | 次のアクション |
|------|--------------|
| 適用可能な CVE あり | `../02_Initial_Access/Edge_Appliance_CVEs.md` の該当ベンダーセクション → `../05_Tools_Reference/CVE_Notes.md` でペイロード確認 |
| CVE なし / バージョン不一致 | Step 3（誤設定・誤公開）へ |
| バージョンが取得できない | Step 3 と Step 4 を並行して進め、バージョン特定を継続する |

---

## Step 3 — 誤設定・誤公開ファイル確認

**目的：** バックアップファイル・設定ファイル・管理パス・`.git/` ディレクトリ等の誤公開を確認する。
認証情報・内部情報・APIキーの漏洩が見つかった場合は Step 6 の辞書に加える。

→ 詳細: `../01_Reconnaissance/Exposed_Files.md`

### Step 3 の判断分岐

| 得られた情報 | 次のアクション |
|------------|--------------|
| 設定ファイル・環境変数ファイルから認証情報取得 | Step 6（cred試行）の候補リストに追加し、即時 Step 5 へ |
| `.git/` 露出 → ソースコード復元可能 | ソースコードからハードコード認証情報・内部エンドポイントを確認 → Step 6 または Web_Vuln_Flow.md へ |
| 管理パス（`/admin` / `/manager` 等）が確認できた | Step 5 → Step 6 でそのパスを標的に絞る |
| 何も見つからない | Step 4（TLS弱点）へ |

---

## Step 4 — TLS 弱点・証明書情報の確認

**目的：** 古いプロトコル・弱い暗号スイート・証明書不一致・既知TLS脆弱性（Heartbleed 等）を確認する。
Step 1b で証明書取得を済ませている場合は、弱点確認の追加スキャンのみ行う。

→ 詳細: `../01_Reconnaissance/TLS_Audit.md`

### Step 4 の判断分岐

| 得られたシグナル | 次のアクション |
|----------------|--------------|
| Heartbleed / POODLE / DROWN 等の既知CVE該当 | 報告対象に記録（直接の侵入経路とはならない場合が多い）→ Step 5 へ |
| 証明書の SAN に内部FQDNが記載されている | `../01_Reconnaissance/DNS_Enumeration.md` で内部FQDNへの到達可能性を確認 |
| 証明書有効期限切れ / 自己署名 | 管理不行き届きのシグナルとして記録 → Step 5 へ |
| 特段の問題なし | Step 5 へ |

---

## Step 5 — ロックアウトポリシー確認（cred試行前の必須確認）

**目的：** Step 6 のデフォルト認証情報試行・辞書攻撃の前に、アカウントロックアウト閾値を確認してアカウント停止リスクを排除する。

→ 詳細: `../02_Initial_Access/Account_Lockout_Recon.md`

> **この確認を省略して Step 6 に進まない。** ロックアウト閾値が3回の環境でスプレーを実行すると、
> ターゲット全ユーザーをロックアウトして業務停止を引き起こす。

### Step 5 の判断分岐

| 確認結果 | Step 6 への影響 |
|---------|--------------|
| ロックアウト無効 / 閾値が十分大きい（20回以上） | 通常速度の辞書攻撃が許容できる |
| 閾値3〜5回 / 観察期間あり | 1アカウントあたり最大2回、観察期間ごとに1パスワードのスプレー設計 |
| 閾値不明（取得できない） | 保守的前提（閾値3・観察期間30分）で設計し、`Account_Lockout_Recon.md` の観察試行を実施 |
| Webフォームに独自レート制限（429 / Retry-Afterヘッダー） | `Account_Lockout_Recon.md` のWebフォームロックアウト観察セクションを参照 |

---

## Step 6 — デフォルト認証情報試行

**目的：** 製品出荷時のデフォルト認証情報が変更されずに残っていないかを試行する。
Step 3 で発見した認証情報候補もここで使用する。

→ 詳細: `../02_Initial_Access/Default_Credentials.md`

### Step 6 の判断分岐

| 結果 | 次のアクション |
|------|--------------|
| デフォルト認証情報でログイン成功 | 製品管理画面の権限確認 → `Edge_Appliance_CVEs.md` の認証後攻撃手法を確認 |
| ログイン失敗（デフォルト試行分のみ） | `Default_Credentials.md` の「刺さらなかったとき」セクション → `Web_Vuln_Flow.md` へ転換を検討 |
| Step 3 で取得した認証情報がある | `Default_Credentials.md` の辞書に追加して再試行 |
| 全試行失敗 | `Web_Vuln_Flow.md` で Web アプリ脆弱性の観点に切り替える |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。インターネット露出サービスへの能動的な接触はすべて書面スコープの明示が必要
- **想定される SIEM / EDR 検知**: Step 2 の CVE エクスプロイト試行は境界 IDS / WAF で検知される。Step 6 のcred試行は認証ログ（アプライアンスのローカルログ / SIEM 転送）に記録
- **業務影響リスク**: Step 2 で RCE 系 CVE を実行する場合はサービス停止リスクあり。Step 6 でロックアウトを誘発すると認証サービス停止
- **原状回復必須項目**: ✅ 試行中に作成したセッション・設定変更の削除 / ✅ 取得した認証情報の暗号化保管・テスト完了時破棄
- **取得情報の取扱**: 認証情報・設定ファイル内容・CVE PoC実行ログはすべて暗号化保管し、テスト完了時に破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：`../00_Playbook/00_OS_Identification.md`（OS / 製品種別の判定。「インターネット境界機器らしい」と判断された場合に本フローへ）
- 後（内部 NW への侵入確立）：`Internal_LAN_Pentest_Flow.md`（External 突破後、内部 VLAN に接続可能になった場合に Internal テストへ移行。NIST §2.4.1 では External を先に完遂してから Internal に進む順序が推奨される）
- 後：`../00_Playbook/Web_Vuln_Flow.md`（全ステップ失敗時、または Web アプリ層に脆弱性の手がかりが見つかった場合に転換）
- 後：`../03_Post_Access_Linux/Enumeration_Checklist.md`（Step 6 でシェルを取得した後の Linux 侵入後フロー）
- 後：`../04_Post_Access_Windows_AD/Enumeration_Checklist.md`（アプライアンス経由でWindows環境に踏み込んだ場合）
- 関連：`Linux_Attack_Flow.md` / `Windows_AD_Attack_Flow.md`（対象が境界機器ではなく Linux / Windows AD 環境と確定した場合は本フローを使わずこちらへ）
