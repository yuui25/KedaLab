# 02_authn_06_mfa_成立点と例外パス（step-up_device_trust）
MFAを「設定項目」ではなく、**成立点（いつ誰が"追加要素を満たした"と判定されるか）** と **例外パス（どんな条件でMFAが省略されるか）** で説明する

---

## 目的（この技術で到達する状態）
- MFAを「設定項目」ではなく、**成立点（いつ誰が“追加要素を満たした”と判定されるか）** と **例外パス（どんな条件でMFAが省略されるか）** で説明できる。
- “MFAを突破する”ではなく、診断として **MFAが効いている境界（資産/信頼/権限）** と **効いていない境界** を、推測ではなく観測差分で示せる（yes/no/unknown で落とす）。
- SSO（OIDC/SAML）とアプリ側セッション（Cookie/Token）の間で、MFAが **どこに紐づくか（IdP側/アプリ側/両方）** を切り分け、次の検証（クライアント保存・端末紐付け・認可）へ繋げる。

## 用語（最小）
- 境界：責任/権限/到達性が切り替わる地点
- 差分観測：1条件だけ変えて比較する観測
- 成立条件：何が揃うと成立/不成立が決まるか

## 前提（対象・範囲・想定）
- 対象：Webアプリ（RP/SP）＋ IdP（OIDC/SAML）＋ MFA要素（TOTP/SMS/Push/WebAuthn等）。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - MFAは以下のいずれか（または併用）で実装される：IdPで完結（IdPが"本人性+MFA"を保証し、RPは結果を受け取る）、RPで完結（RPが独自に追加要素を要求・検証）、Step-up（通常はSSOのみ、特定操作で追加要素を要求）。
- できること/やらないこと（安全に検証する範囲）：
  - 本ユニットは「MFAの成立点と例外パスの確定」が目的。フィッシング耐性/運用設計の評価は、必要なら別ユニットへ分割する。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
  - `01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
  - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
  - `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - MFAの成立点（いつ誰が"追加要素を満たした"と判定されるか）の観測
    - 例外パス（どんな条件でMFAが省略されるか）の観測
    - MFAチャレンジの相関（混線・差し替えを防ぐ設計か）の観測
    - 端末信頼の実体（device_trust / device_binding の入口）の特定
  - 扱わない（別ユニットへ接続）：
    - 端末紐付けの詳細 → `01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`
    - クライアント保存の詳細 → `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`
    - Step-upの詳細 → `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`

## 想定時間
- 目安：20〜40分（環境/SSO有無で前後）

## ツール選定の根拠（代替）
- HAR/Proxy：成立点と差分を最小回数で記録できる
- 代替：ブラウザ開発者ツール/サーバログ/設定画面

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 成立点（MFAの“完了”がどこで確定するか）を固定する
観測の中心は「MFAを完了した瞬間に、どの資産が増えたか（状態変化）」。
- IdP完結型の典型
  - MFA完了後に **IdPセッション**（IdP Cookie）が強化され、以降はSSOが即時に通る
  - RP側は callback 後に **RPセッション**（Set-Cookie）が発行される（MFA結果は“間接的”）
- RP完結型の典型
  - ログイン（パスワード）後に、RP内でチャレンジ画面へ遷移
  - MFA完了後に **RPセッションが“昇格”** する（Cookie再発行、セッション属性変更、権限フラグ付与など）
- Step-upの典型
  - 通常のログインは成立するが、特定の操作（送金/権限変更/PII閲覧等）で追加要素が要求される
  - “昇格された操作だけが通る”状態変化（権限境界の切替）を観測する

### 2) 例外パス（MFAが省略される条件）を“仕様”ではなく“条件分岐”として列挙する
MFAの例外は、たいてい **「信頼を置く根拠」** が資産として実装される（ここが攻撃面）。
- よくある例外条件
  - “この端末を信頼する（Remember device / Keep me signed in）”
  - “このネットワーク/このIPは信頼する（企業LAN/VPN等）”
  - “直近X時間は再要求しない（Step-upのTTL）”
  - “特定クライアント（モバイルアプリ/管理端末）は免除”
  - “リカバリ（メールリンク/バックアップコード/サポート解除）”
- 観測の着眼点（資産）
  - 免除に使われる **Cookie/LocalStorage/端末トークン** が存在するか
  - 免除の根拠が **サーバ側（セッション属性）** か **クライアント側（トークン）** か
  - 免除のスコープ（同ブラウザのみ / 同端末広域 / 同サブドメイン / 同ユーザー全体）

### 3) MFAチャレンジの“相関”を観測する（混線・差し替えを防ぐ設計か）
MFAは「途中状態」が発生するため、相関キー（トランザクションID）が設計の要。
- 観測したいもの
  - チャレンジ開始リクエストの相関ID（例：`challenge_id` / `transaction_id`）
  - OTP送信・検証の相関（誰の、どのセッションの、どの要求に対するOTPか）
  - Push/WebAuthnの場合のチャレンジ（nonce/challenge）と受理の結び付き
- 境界
  - IdP↔Factor Provider（SMS/Push等）で“第三者境界”が増える場合、どこで最終判定が出るかを切り分ける

### 4) “端末信頼”の実体を特定する（device_trust / device_binding の入口）
Remember device は、次のいずれかの形を取る（観測で決め打つ）。
- クライアント保存型：ブラウザに免除トークン（Cookie/Storage）を置く
- サーバ保存型：端末指紋や端末公開鍵をサーバが登録し、次回の評価に使う
- ハイブリッド：トークン＋サーバ側の照合（回収/失効が可能）
観測の結論は「免除トークンが盗める/複製できる設計か」「失効/回収が効く設計か」を左右する。

### 5) 証跡として残す最小セット（差分が説明できる形）
- ブラウザHAR：ログイン→MFAチャレンジ→完了→アプリ到達 まで
- Proxyログ：Location/Set-Cookie/Cookie/POST body（秘匿値はマスク）
- 状態メモ（固定）
  - MFAが要求された画面/URL（成立点の前後）
  - MFA完了前後で増えた資産（Cookie名/セッションIDの変化/権限APIの通過可否）
  - 免除条件をON/OFFしたときの差分（同端末・別端末・別ブラウザ）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - MFAが **IdP側で完結** しているか、**RP側で完結** しているか、**Step-up** か（成立点の分類）
  - 免除（Remember device / Step-up TTL）が **存在するか**（yes/no）
  - 免除の"根拠資産"が **どこにあるか**（Cookie/Storage/サーバ側属性）
  - MFA完了が **セッション昇格** として表現されるか（Cookie再発行/別セッション/権限フラグ等）
- 何が"推定"できるか（推定の根拠/前提）：
  - 相関検証が強いか（トランザクション混線を起こす変更が拒否されるか）
  - 免除トークンが複製耐性を持つか（端末要素と結びつくか、失効が効くか）
- 何は"言えない"か（不足情報・観測限界）：
  - リスクエンジン（Risk-based MFA）の内部ロジック（どの信号で分岐しているか）
  - 運用（ヘルプデスク解除/例外申請）がどこまで安全か（必要なら別ユニットで扱う）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：免除は"端末信頼トークン"で実現されている → 同一端末・同一ブラウザで「免除ON/OFF」を切り替え、MFA要求の有無を確認（差分の記録）
  - パターンB：Step-upは"操作単位のTTL"で実現されている → 重要操作を特定し、Step-up前後で通るAPI/画面を列挙（境界の固定）
  - パターンC：相関が弱く、チャレンジ混線の余地が疑われる → チャレンジ開始→検証までのリクエストを観測し、相関IDの有無を確認

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
### 優先度（どこから攻め筋を組むか）
1) **免除資産（Remember device / TTL）の所在**：盗める・複製できる・失効できない設計は、MFAを“実質バイパス可能”にする方向へ寄る。  
2) **Step-upの境界**：重要操作が本当にStep-up必須か（権限境界が守られているか）。  
3) **相関の強さ**：チャレンジ混線（別セッションに結果を注入）を疑えるかどうかは、相関IDと検証点で決まる。  
4) **回復経路**：バックアップコード/メール/サポート解除が“最弱リンク”になりやすい（ただし本ユニットは入口観測まで）。  

### 状態→攻め筋の分岐（例）
- 状態A：IdP完結＋免除トークンがブラウザにある  
  - 次の仮説：免除トークンは **Cookie境界/クライアント保存/XSS連鎖** の影響を受ける。次は `02_authn_07_client_storage` と結合して評価する。  
- 状態B：Step-upがあるが、重要操作がStep-up無しで通る  
  - 次の仮説：MFAは“ログイン”には効いているが、“権限境界”には効いていない。AuthZ（IDOR/BOLA/BFLA）側へ優先度を振る。  
- 状態C：MFA完了でCookieが再発行されず、同セッションのまま権限だけ上がる  
  - 次の仮説：セッション固定化/中間状態の扱いが弱い可能性。`02_authn_02_session_lifecycle` と結合し、昇格前後の保護点を確認する。  

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：免除は“端末信頼トークン”で実現されている
- 次に試すこと（安全な範囲での差分）
  - 同一端末・同一ブラウザで「免除ON/OFF」を切り替え、MFA要求の有無を確認（差分の記録）
  - 同一端末・別ブラウザで免除が効くか（スコープの特定）
  - Cookie/Storageの増減を比較し、免除資産候補をリスト化（値はマスク）
- 期待する観測
  - 免除資産の所在（Cookie/Storage/サーバ）とスコープ（どこまで効くか）が確定する

### 仮説B：Step-upは“操作単位のTTL”で実現されている
- 次に試すこと
  - 重要操作を特定し、Step-up前後で通るAPI/画面を列挙（境界の固定）
  - Step-up後のTTL（何分/何操作で切れるか）を観測で把握（時間を置く/ログアウトする）
- 期待する観測
  - “どの権限境界でMFAが要求されるか”がyes/noで言える

### 仮説C：相関が弱く、チャレンジ混線の余地が疑われる
- 次に試すこと（最小差分・低負荷）
  - チャレンジ開始→検証までのリクエストを観測し、相関IDの有無を確認
  - 1点だけ変更（相関ID/セッション識別子の片方）した場合に拒否されるかを確認し、unknown を潰す
- 期待する観測
  - “検証が効いている/いない/不明”を推測でなく差分で説明できる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - ブラウザHAR：ログイン→MFAチャレンジ→完了→アプリ到達 まで
  - Proxyログ：Location/Set-Cookie/Cookie/POST body（秘匿値はマスク）
  - 状態メモ（固定）：MFAが要求された画面/URL（成立点の前後）、MFA完了前後で増えた資産（Cookie名/セッションIDの変化/権限APIの通過可否）、免除条件をON/OFFしたときの差分（同端末・別端末・別ブラウザ）
- 観測の取り方（どの視点で差分を見るか）：
  - MFAの成立点（完了前後の状態変化）、例外パス（免除条件の有無と根拠資産）、MFAチャレンジの相関（相関IDの有無）、端末信頼の実体
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/mfa 2>/dev/null
    cd ~/keda_evidence/mfa
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ
      - 秘匿値（Cookie/トークン/OTP等）はマスク。
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、MFA状態（未完了/完了/免除）、免除条件（端末信頼/ネットワーク/IP/TTL/クライアント/リカバリ）、相関ID（チャレンジID/トランザクションID）、セッション変化（Cookie再発行/セッション属性変更/権限フラグ付与）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：MFA完了前後の Set-Cookie 差分を取る（成立点が"セッション再発行"かを判断する材料）
curl -i "https://rp.example.com/account" | sed -n 's/^Set-Cookie: //p'
~~~~

- この例で観測していること：
  - ログイン直後（MFA未完了）と、MFA完了直後で cookie 名/数が変わるかを比較する
- 出力のどこを見るか（注目点）：
  - Set-Cookieヘッダ（Cookie名/数/属性の変化）、セッションIDの変化、権限フラグの有無
- この例が使えないケース（前提が崩れるケース）：
  - JS必須/SSO必須の場合、curlだけでは成立しない（ブラウザ+HAR/Proxyで観測へ）

## 観測が失敗した場合
- 変数を1つに絞り、差分が出る条件を再設定する
- HARが取れない場合は、画面遷移とレスポンスのスクショで代替する
- ログ/設定が見られるなら、挙動の根拠として添える

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V2（Authentication：MFA/再認証/要素の管理）、V3（Session：昇格・失効・再利用）、必要に応じてV4（Access Control：Step-upが守る境界）に接続する。
  - 該当要件（可能ならID）：V2（Authentication）、V3（Session Management）、V4（Access Control）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：MFAの成立点と例外パスを観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Authentication Testing（MFA/2FA）、Session Management（昇格・免除・再認証の扱い）、Identity Management（SSO/MFA境界）として、観測差分（成立点/例外/資産）に紐づけて扱う。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：MFAの成立点と例外パスの観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis（成立点と例外パスの切り分け）→ Exploitation（最小差分でunknownを潰す）→ Reporting（証跡）に接続する。
  - 前後フェーズとの繋がり（1行）：成立点と例外パスの切り分け→最小差分でunknownを潰す→証跡の品質を上げる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Credential Access / Defense Evasion / Valid Accounts
  - 攻撃者の目的（この技術が支える意図）：Credential Access（MFA回避の目的）、Defense Evasion（信頼済み端末/セッション悪用）、Valid Accounts（有効アカウントでの突破）に位置づける。
  - 参照：https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）、https://attack.mitre.org/tactics/TA0001/（Initial Access - Valid Accounts）

## 参考（必要最小限）
- OWASP Multi-Factor Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
- 関連 topics：`01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
- 関連 topics：`01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
- `01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
- `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`
- `01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
