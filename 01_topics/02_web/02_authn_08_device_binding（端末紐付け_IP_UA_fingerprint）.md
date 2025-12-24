# 02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）
「端末紐付け（device binding）」を、**どの資産（セッション/トークン）** が **どの端末属性（IP/UA/端末鍵/デバイスID等）** に結び付くか、という"境界モデル"で説明する

---

## 目的（この技術で到達する状態）
- 「端末紐付け（device binding）」を、**どの資産（セッション/トークン）** が **どの端末属性（IP/UA/端末鍵/デバイスID等）** に結び付くか、という“境界モデル”で説明できる。
- ログイン/MFA/Step-up の直後に作られる **端末信頼（trusted device）資産** を観測し、**どの条件で“同一端末扱い”が成立するか** を yes/no/unknown で落とせる。
- セッション再利用（cookieコピー、token再利用）に対して、端末紐付けが **どこで効いているか（RP/IdP/APIゲートウェイ）** を切り分け、次の検証（MFA例外、クライアント保存、認可境界）へ繋げる。

## 前提（対象・範囲・想定）
- 対象：Webアプリ（RP/SP）・IdP（OIDC/SAML）・API（BFF/ゲートウェイ含む）。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 端末紐付けは「セキュリティ機能」ではなく、実装として次のいずれか（または併用）で現れる：端末属性ベース（IP / User-Agent / Accept-Language / TLS指紋 / 位置情報などの"信号"で評価）、端末トークンベース（Remember device / device_token / device_id 等の"資産"で評価）、鍵ベース（mTLS / DPoP / WebAuthn / デバイス鍵（公開鍵登録）で"複製耐性"を持たせる）。
- できること/やらないこと（安全に検証する範囲）：
  - 本ユニットは「端末紐付けの成立点・資産・スコープの観測」が主目的。端末指紋の作り方や回避手法の詳細（攻撃手順の最適化）は扱わない。過度な切替試行は誤検知・ロックを誘発し得るため、検証は最小差分で行う。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`（免除/信頼端末の入口）
  - `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`（端末資産がどこに残るか）
  - `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`（再利用窓/失効境界）
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 端末紐付けの成立点（どの層で効いているか：IdP/RP/API）
    - 端末資産（device trust asset）の存在確認
    - スコープ（どこまで同一端末扱いか）の観測
    - 信号ベース/資産ベース/鍵ベースの境界の違い
    - 端末紐付けと権限境界（Step-upの位置）の関係
  - 扱わない（別ユニットへ接続）：
    - 端末指紋の作り方や回避手法の詳細 → 別ユニット

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) “端末紐付け”がどの層で効いているか（成立点）
端末紐付けは、同じ見た目でも“効いている場所”が違うと検証観点が変わる。
- IdP層：IdPセッション（IdP cookie）が端末信頼に紐づく。RPは結果を受け取るだけ。
- RP層：RPセッションが端末資産に紐づく（ログイン後にRP独自のdevice cookie等が出る）。
- API層：Authorization（Bearer等）が端末属性/端末鍵と結び付く（API側で拒否/Step-up要求）。
観測の固定点
- “どのレスポンス以降”で紐付けが成立したように見えるか（Set-Cookie増加、APIが通る/通らない等）
- “どのリクエストで”拒否されるか（画面遷移ではなくAPIだけ落ちる等）

### 2) 端末資産（device trust asset）の存在を確認する
端末紐付けは「信号だけ」ではなく、たいてい **資産として残る**。まずは“ある/ない”を決める。
- Cookie：`device_*` / `trusted_*` / `remember_*` などの追加Cookie（HttpOnlyの有無も見る）
- Storage：localStorage/sessionStorage/IndexedDB に device_id や refresh に類するもの
- Token内：JWTの claim（例：`device_id`、`amr`、`acr` 等）に端末/強度情報が入る場合（中身の意味は“推定”ではなく観測差分で扱う）
- サーバ側属性：クライアント側に何も残らないが、以後の挙動だけ変わる（unknownになりやすいので証跡を厚くする）

### 3) スコープ（どこまで同一端末扱いか）を観測で確定する
スコープを決める最小差分（手戻りが少ない順）
- 同一ブラウザ（同プロファイル）・同ネットワーク：基準挙動（baseline）
- 同一端末・別ブラウザ（別プロファイル）：端末レベルかブラウザレベルか
- 同一端末・シークレット：ストレージ依存かどうか
- 別端末：本当に端末に紐づくか
観測の結論（例）
- ブラウザ限定（cookie/storage依存）なのか、端末限定（サーバ登録/鍵）なのか、ネットワーク限定（IP評価）なのか

### 4) “信号ベース”か“資産ベース”か（境界の違い）
- 信号ベース（IP/UA等）
  - 目的：異常検知・リスク評価（Risk-based auth）として使われることが多い
  - 観測：UA/IPが変わった瞬間に再認証/Step-up/拒否になるか（ただし“常に”ではなく条件付きが多い）
  - 注意：過度な切替試行は誤検知・ロックを誘発し得るため、検証は最小差分で行う
- 資産ベース（remember device等）
  - 目的：免除・利便性（MFA省略）とセットで現れることが多い
  - 観測：免除ON/OFFで増えるcookie/storageが“端末資産”である可能性が高い
  - 次：資産の失効・回収・スコープを確認する（session_lifecycleと結合）
- 鍵ベース（mTLS/DPoP/WebAuthn等）
  - 目的：複製耐性（盗んだtokenだけでは使えない）を持たせる
  - 観測：同一token/同一cookieでも、別端末・別証明書では通らない（ただし仕様/実装で例外あり）

### 5) 端末紐付けと「権限境界」の関係（Step-upの位置）
端末紐付けは、認証そのものより「重要操作の境界」で効くことが多い。
- 例：ログインは通るが、PII閲覧/送金/権限変更で Step-up が要求される
- 観測：重要操作APIに対して、端末が“信頼済み”なら通るが、未信頼だと再認証/拒否になる
- ここでの結論：端末紐付けが守っているのは「ログイン」か「操作（権限境界）」か

### 6) 証跡（最低限）
- HAR：ログイン→（MFA/remember device）→重要操作（Step-upの有無）
- Proxyログ：Set-Cookie増減、Authorizationヘッダ有無、拒否時のステータス/エラー（値はマスク）
- 差分メモ（yes/no/unknown）
  - 別ブラウザで同じアカウントを使ったときにMFAが再要求されるか
  - 同一cookieで別環境（別プロファイル）に移したときに成立するか（テスト可能な範囲で）
  - UA/IP変更で再認証/拒否になるか（最小試行）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 端末紐付けが **IdP/RP/APIのどこで効いているか**（拒否点・成立点）
  - 端末資産が **存在するか**（cookie/storage/token内/サーバ側）
  - スコープが **ブラウザ単位/端末単位/ネットワーク単位** のどれに近いか（差分）
  - Step-upが端末信頼と結び付いているか（重要操作での差分）
- 何が"推定"できるか（推定の根拠/前提）：
  - 鍵ベースの複製耐性がどの程度あるか（mTLS/DPoP等の存在は観測できるが、厳密な保証は実装依存）
  - リスクベース評価の条件（UA/IP以外の信号はブラックボックスになりやすい）
- 何は"言えない"か（不足情報・観測限界）：
  - 端末指紋の内部アルゴリズム（ベンダ/SDK依存、非公開が多い）
  - "安全/危険"の断定（まずは境界と成立条件を固め、次のユニットで影響を評価する）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：端末資産がブラウザ保存（cookie/storage）で、別端末でも成立しうる → 端末紐付けの"複製耐性"が弱い可能性。クライアント保存（XSS/端末共有/ログ採取）と結合してリスクが増幅し得る
  - パターンB：端末信頼はサーバ側登録で、別ブラウザでは再要求（スコープが狭い） → cookieコピー等だけでは成立しにくい。主戦場は「免除の運用」「再登録（enroll）の境界」「失効/回収」へ移る
  - パターンC：鍵ベース（mTLS/DPoP/WebAuthn）で別端末が成立しない → トークン盗用の影響が抑制される方向。代わりに"回復経路"や"デバイス追加"が最弱リンクになりやすい
  - パターンD：端末紐付けは重要操作のみ（Step-up）で効いている → ログイン突破よりも、AuthZ/API境界が主戦場。重要操作が本当にStep-up必須かを優先確認する

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここでは攻撃手順ではなく、診断の優先順位付け（どこが破られると到達点が変わるか）を行う。
- 状態A：端末資産がブラウザ保存（cookie/storage）で、別端末でも成立しうる
  - 意味：端末紐付けの“複製耐性”が弱い可能性。クライアント保存（XSS/端末共有/ログ採取）と結合してリスクが増幅し得る。
  - 次の仮説：MFA免除トークンやrefreshが盗用されると、Valid Accounts と同等の到達点に繋がる。
- 状態B：端末信頼はサーバ側登録で、別ブラウザでは再要求（スコープが狭い）
  - 意味：cookieコピー等だけでは成立しにくい。主戦場は「免除の運用」「再登録（enroll）の境界」「失効/回収」へ移る。
  - 次の仮説：端末登録フロー（re-enroll）に例外パスがないか、Step-up境界が抜けていないか。
- 状態C：鍵ベース（mTLS/DPoP/WebAuthn）で別端末が成立しない
  - 意味：トークン盗用の影響が抑制される方向。代わりに“回復経路”や“デバイス追加”が最弱リンクになりやすい。
  - 次の仮説：デバイス追加・鍵ローテーション・紛失時回復の境界が弱いと、そこが突破口になる。
- 状態D：端末紐付けは重要操作のみ（Step-up）で効いている
  - 意味：ログイン突破よりも、**AuthZ/API境界** が主戦場。重要操作が本当にStep-up必須かを優先確認する。
  - 次の仮説：BOLA/BFLA（認可）側で到達点が作れるなら、端末紐付けの有無に関係なく危険になる。

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：端末資産がcookie/storageにあり、ブラウザ単位で成立している
- 次に試すこと（安全な最小差分）
  - remember device（免除）ON/OFFで増える資産（cookie/storage）を“名前と数”で記録（値はマスク）
  - ログアウト後にその資産が消えるか（yes/no）
  - 一定時間後に資産が更新されるか（更新通信があるか）
- 期待する到達点
  - 端末資産の所在・寿命・回収境界を、session_lifecycle と結合して説明できる

### 仮説B：UA/IPなど“信号”で条件付きに効いている（Risk-based）
- 次に試すこと（影響を増やさない）
  - UA変更は“1回だけ”行い、再認証/Step-up/拒否の有無を記録（連続試行しない）
  - ネットワーク変更（VPN等）も“1回だけ”で差分を取り、ロック等の副作用がない範囲で確認する
- 期待する到達点
  - “信号が境界を作っているか”を yes/no/unknown で示せる

### 仮説C：鍵ベースの複製耐性がある
- 次に試すこと
  - 証明書（mTLS）やDPoP等の有無を、通信の特徴（TLSクライアント証明書要求、DPoPヘッダ等）から観測する
  - 端末追加/鍵再発行のフローを見つけ、成立点（誰がいつ何を持てば追加できるか）を固定する
- 期待する到達点
  - “強い紐付け”の代わりに弱くなりがちな回復/追加境界へ検証を繋げられる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - HAR：ログイン→（MFA/remember device）→重要操作（Step-upの有無）
  - Proxyログ：Set-Cookie増減、Authorizationヘッダ有無、拒否時のステータス/エラー（値はマスク）
  - 差分メモ（yes/no/unknown）：別ブラウザで同じアカウントを使ったときにMFAが再要求されるか、同一cookieで別環境（別プロファイル）に移したときに成立するか（テスト可能な範囲で）、UA/IP変更で再認証/拒否になるか（最小試行）
- 観測の取り方（どの視点で差分を見るか）：
  - 端末紐付けの成立点（どの層で効いているか）、端末資産の存在、スコープ（どこまで同一端末扱いか）、信号ベース/資産ベース/鍵ベースの境界の違い
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/device_binding 2>/dev/null
    cd ~/keda_evidence/device_binding
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ
      - 過度な切替試行は誤検知・ロックを誘発し得るため、検証は最小差分で行う
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、端末紐付け層（IdP/RP/API）、端末資産の所在（cookie/storage/token内/サーバ側）、スコープ（ブラウザ単位/端末単位/ネットワーク単位）、Step-upとの関係（yes/no/unknown）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：UA差分で"信号ベース"の端末評価が動くかを最小試行で観測する
curl -i "https://rp.example.com/account" -H "User-Agent: UA-CHANGE-TEST" | head
~~~~

- この例で観測していること：
  - 1回だけUAを変えて、再認証/Step-up/拒否の有無を見る（連続試行は禁止）
- 出力のどこを見るか（注目点）：
  - ステータスコード（200/401/403/302）、Set-Cookieヘッダ、エラーメッセージ
- この例が使えないケース（前提が崩れるケース）：
  - JS必須/SSO必須の場合、curlだけでは成立しない（ブラウザ+HAR/Proxyで観測へ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V2（Authentication：再認証/強要件/例外パスの管理）、V3（Session：再利用窓・失効・固定化）、必要に応じてV4（Access Control：Step-upが守る境界）に接続する。
  - 該当要件（可能ならID）：V2（Authentication）、V3（Session Management）、V4（Access Control）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：端末紐付けの成立点・資産・スコープを観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Authentication Testing（MFA/再認証/信頼端末）、Session Management（セッション再利用/失効/固定化）、Client-side（保存先の確認）を"差分観測"として結合する。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：端末紐付けの観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering（成立点/拒否点/資産の特定）→ Vulnerability Analysis（スコープ/再利用窓）→ Exploitation（最小差分でunknownを潰す）→ Reporting（証跡）に接続する。
  - 前後フェーズとの繋がり（1行）：成立点/拒否点/資産の特定→スコープ/再利用窓→最小差分でunknownを潰す→証跡の品質を上げる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Credential Access / Defense Evasion / Valid Accounts
  - 攻撃者の目的（この技術が支える意図）：Credential Access（Web session/cookie/token の盗用）、Defense Evasion（信頼済み端末/セッション再利用）、Valid Accounts（有効アカウント悪用）として位置づける。
  - 参照：https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）、https://attack.mitre.org/tactics/TA0001/（Initial Access - Valid Accounts）

## 参考（必要最小限）
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP OAuth 2.0 Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Security_Cheat_Sheet.html
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- 関連 topics：`01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`
- 関連 topics：`01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_10_password_reset_回復経路（token_失効_多要素）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
