# 02_authn_10_password_reset_回復経路（token_失効_多要素）
パスワードリセットを「便利機能」ではなく、**回復経路（Recovery Channel）** と **回復資産（Reset Token / Code）** と **失効境界（Session/Token/Trusted Device）** の3点で説明する

---

## 目的（この技術で到達する状態）
- パスワードリセットを「便利機能」ではなく、**回復経路（Recovery Channel）** と **回復資産（Reset Token / Code）** と **失効境界（Session/Token/Trusted Device）** の3点で説明できる。
- 回復フローの各点について、推測ではなく観測差分で **yes/no/unknown** を落とせる（例：トークン単回性、TTL、既存セッション失効、MFA要求、端末信頼の回収）。
- 認証（02_authn）から認可（03_authz）へ進む前に、「最も守りが薄くなりがちな入口」を固定し、優先度と次の検証（XSS/IDOR/CSRF/運用回復）へ繋げる。

## 前提（対象・範囲・想定）
- 対象：Webアプリのパスワードリセット（メールリンク、コード入力、SMS、アプリ内通知、管理者/サポート代行を含む）。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 回復は多くの場合、ログインより「弱い本人確認」になりやすく、MFA/端末信頼が強いほど回復側が相対的に弱点化しやすい（設計の力学）。
- できること/やらないこと（安全に検証する範囲）：
  - 本ユニットは「回復経路の成立条件と境界の観測」に集中する。ソーシャルエンジニアリング手順の最適化は扱わない。過剰試行でロックを誘発しない。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`（回復が例外パスになり得る）
  - `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`（回復後に残る資産/消える資産）
  - `01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`（trusted device の回収/追加境界）
  - `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`（失効・再利用窓）
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 回復フローの状態遷移（入口→資産発行→検証→更新→失効）の観測
    - 回復資産（Reset Token / Code）の"形"と"露出面"の確定
    - 成立点（どこで本人確認が完了した扱いになるか）の固定
    - MFA/Step-up/端末信頼との結合点の観測
    - 失効境界（セッション/トークン/端末信頼の回収）の確認
    - アカウント列挙（存在有無の漏えい）を境界として扱う
  - 扱わない（別ユニットへ接続）：
    - ソーシャルエンジニアリング手順の最適化 → 別ユニット
    - メール/SMS基盤の内部（配送遅延・中継ログ等） → 必要ならASM/OSINT・SaaS側で扱う
    - ヘルプデスク運用の実態（手順・教育・監査） → 必要なら別ユニット

## 観測ポイント（何を見ているか：フロー/資産/境界）
### 1) 回復フローを“状態遷移”として分解する（入口→資産発行→検証→更新→失効）
最低限、次の5段を「どのリクエスト/レスポンスが境界か」で固定する。
- 入口：`/forgot` 等（識別子入力、Captcha、Rate limit、案内メッセージ）
- 資産発行：トークン/コード生成（サーバ側のみ・クライアント露出あり等）
- 資産検証：リンク遷移 or コード入力（検証成功で“次状態”へ進む）
- 更新：新パスワード設定（CSRF/再認証/強度ポリシー）
- 失効：既存セッション/Refresh/Trusted device の回収・ログアウト

観測の要点は「どの瞬間に何が“増えた/消えた”か」。
- Set-Cookie の増減（回復専用セッション/フラグ）
- Location/302 の遷移（token が URL に残るか）
- APIの成功/失敗の差分（回復前後で通る操作が増えるか）

### 2) 回復資産（Reset Token / Code）の“形”と“露出面”を確定する
トークンの置き場所は、漏えい経路と監査可能性を決める。
- URL：クエリ/パス/フラグメント（ログ・Referer・共有の影響を受けやすい）
- Body：POST（比較的ログに残りにくいが、アプリ/プロキシの保存方針次第）
- Cookie：回復フロー専用Cookie（HttpOnly/SameSite等の意味が大きい）
- コード：短い数字/英数字（総当たり耐性とRate limitが鍵）

ここでの結論は「どこに出るか」だけでなく、次の性質を yes/no/unknown に落とす。
- 単回性（同一トークンを2回使えるか）
- TTL（有効期限）
- 紐付け（ユーザーだけに結び付くか／回復セッションに結び付くか）
- 失敗時の挙動（同一tokenで何回まで試せるか、ロックアウトの有無）

### 3) “成立点”を固定する（どこで本人確認が完了した扱いになるか）
回復は「途中状態」が必ず発生するため、成立点を誤ると評価がブレる。
- 成立点の典型
  - トークン検証に成功した瞬間（以降はパスワード更新が可能）
  - パスワード更新が完了した瞬間（ここで初めて本人確認完了扱い）
- 観測の固定点
  - 成功直後に発行される資産（回復専用セッション、CSRF、通常セッション）
  - “次の画面へ進める条件”が何か（tokenだけ / token+追加要素）

### 4) MFA/Step-up/端末信頼との結合点を観測する（回復が例外になっていないか）
MFAや端末信頼が強くても、回復が弱いと全体が崩れる。
観測したい分岐（yes/no/unknown）
- 回復後の初回ログインでMFAが再要求されるか
- 回復フロー自体に追加要素（Step-up/再認証/確認）が要求されるか
- “信頼端末”が回復で自動復活するか（回復＝信頼再付与になっていないか）

### 5) 失効境界（セッション/トークン/端末信頼の回収）を確認する
回復は「本人が乗っ取られたときに取り戻す手段」でもあるため、回復完了時の回収が弱いと意味が薄れる。
観測の対象（資産一覧は 02_authn_07 を前提にする）
- 既存セッション：ログイン済みのブラウザが生き続けるか
- Refresh/長期token：回復後も更新できるか
- trusted device / remember device：回復後も免除が効くか
- APIトークン/キー（ある場合）：回復で無効化される設計か、別管理か

観測は「既存セッションで特定APIが通る/通らない」など、1点差分で行う（過剰試行でロックを誘発しない）。

### 6) アカウント列挙（存在有無の漏えい）を境界として扱う
回復入口は、攻撃者のDiscovery起点になりやすい。
- 観測：同一メッセージ/同一応答時間/同一ステータスで“存在有無”が隠蔽されているか
- 注意：この観測は最小回数で行い、連続試行や大量判定はしない（業務影響と検知を誘発）。

### 7) 証跡として残す最小セット（差分が説明できる形）
- ブラウザHAR：入口→送信→検証→更新→完了まで（token値は必ずマスク）
- Proxyログ：Set-Cookie/Location/主要POST（秘匿値はマスク）
- 状態メモ（固定）
  - 回復成立点（どのレスポンス以降か）
  - 回復資産の露出面（URL/Body/Cookie/Code）
  - 回復後の回収結果（セッション/refresh/trusted device：yes/no/unknown）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 回復資産の露出面（どこに現れ、どこに残るか）
  - 単回性/TTL/紐付けの有無（少なくとも"挙動として"）
  - 回復後に既存セッション/長期資産が回収されるか（yes/no/unknown）
  - 回復がMFA/端末信頼の例外になっているか（例外パスの存在）
- 何が"推定"できるか（推定の根拠/前提）：
  - 列挙耐性（メッセージだけでなく時間差/副作用まで）
  - サポート代行等の運用回復がどれだけ強いか（別ユニットで深掘り推奨）
- 何は"言えない"か（不足情報・観測限界）：
  - メール/SMS基盤の内部（配送遅延・中継ログ等）※必要ならASM/OSINT・SaaS側で扱う
  - ヘルプデスク運用の実態（手順・教育・監査）※必要なら別ユニット
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：回復資産は単回・短TTL・強い紐付けで守られている → token検証成功後に、同一tokenで再度検証を試みた場合の挙動（拒否/無効化）を1回だけ確認（yes/no）
  - パターンB：回復後の失効が弱く、既存セッション/長期資産が残る → 回復完了前から存在するログイン状態（別ブラウザ/別タブ/別端末が可能なら最小で）で、回復後に重要APIが通るかを確認
  - パターンC：回復がMFA/端末信頼の例外として機能している → 回復後の初回ログイン（または重要操作）でMFAが再要求されるかを観測（yes/no）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここでは“手順”ではなく、診断としての優先順位付けを行う。
優先度が上がる状態（例）
- 回復資産がURLに露出し、ログ/Referer/共有で漏れやすい
- 単回性が弱い、TTLが長い、試行回数制限が弱い
- 回復後に既存セッション/refresh/trusted device が回収されない
- 回復がMFAの例外として機能している（回復＝MFAバイパス経路）
- 入口がアカウント列挙の起点になっている

状態→次の接続（例）
- 状態A：回復後も既存セッションが生存
  - 次：`02_authn_02_session_lifecycle` に戻り、失効境界（サーバ側無効化）の欠落を原因分解する。
- 状態B：回復成立でtrusted device が復活/維持
  - 次：`02_authn_08_device_binding` と結合し、端末信頼の回収・追加境界を深掘りする。
- 状態C：回復資産がクライアント側に残る/保存される
  - 次：`02_authn_07_client_storage` と結合し、保存先・再利用窓・消し方を固める。

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：回復資産は単回・短TTL・強い紐付けで守られている
- 次に試すこと（最小差分）
  - token検証成功後に、同一tokenで再度検証を試みた場合の挙動（拒否/無効化）を1回だけ確認（yes/no）
  - 時間を置いたときの有効性（TTL）を“最小回数”で観測（unknown→yes/no）
- 期待する到達点
  - “回復資産は強い”と結論付け、次は失効境界（回収）の評価へ重点を移せる

### 仮説B：回復後の失効が弱く、既存セッション/長期資産が残る
- 次に試すこと
  - 回復完了前から存在するログイン状態（別ブラウザ/別タブ/別端末が可能なら最小で）で、回復後に重要APIが通るかを確認
  - refresh/remember device の挙動を観測（新規発行/回収/維持：yes/no/unknown）
- 期待する到達点
  - “回復できても乗っ取りが継続する”状態かどうかを証跡付きで説明できる

### 仮説C：回復がMFA/端末信頼の例外として機能している
- 次に試すこと
  - 回復後の初回ログイン（または重要操作）でMFAが再要求されるかを観測（yes/no）
  - trusted device が回復で再付与される挙動がある場合、どの資産（cookie/storage/サーバ属性）で成立しているかを特定（値はマスク）
- 期待する到達点
  - “MFAはログインでは効くが回復で崩れる”という境界評価を確定し、改善提案（回復にもStep-up等）へ繋げられる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - ブラウザHAR：入口→送信→検証→更新→完了まで（token値は必ずマスク）
  - Proxyログ：Set-Cookie/Location/主要POST（秘匿値はマスク）
  - 状態メモ（固定）：回復成立点（どのレスポンス以降か）、回復資産の露出面（URL/Body/Cookie/Code）、回復後の回収結果（セッション/refresh/trusted device：yes/no/unknown）
- 観測の取り方（どの視点で差分を見るか）：
  - 回復フローの状態遷移、回復資産の露出面、成立点、MFA/Step-up/端末信頼との結合点、失効境界、アカウント列挙
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/password_reset 2>/dev/null
    cd ~/keda_evidence/password_reset
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ
      - 過剰試行でロックを誘発しない
      - token値は必ずマスク
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、回復フロー段階（入口/資産発行/検証/更新/失効）、回復資産の露出面（URL/Body/Cookie/Code）、単回性/TTL/紐付け（yes/no/unknown）、回復後の回収（セッション/refresh/trusted device：yes/no/unknown）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：回復成立点の前後で Set-Cookie / Location の差分を取り、資産の増減を観測する（値は保存しない）
curl -i "https://rp.example.com/forgot" | sed -n -e 's/^Set-Cookie: //p' -e 's/^Location: //p'

# 例：回復完了後に"既存セッションが回収されるか"の差分を取る（同一アカウントの別ブラウザ等で最小回数）
curl -i "https://rp.example.com/account" -H "Cookie: session=REDACTED" | head
~~~~

- この例で観測していること：
  - 回復フローの各リクエストで、Set-Cookie と Location だけを確認する、既存セッションCookieを保持した状態で、回復後に同じエンドポイントが通るかを見る（結果のみ比較）
- 出力のどこを見るか（注目点）：
  - Set-Cookieヘッダ（回復専用セッション/フラグ）、Locationヘッダ（token が URL に残るか）、ステータスコード（200/401/403/302）
- この例が使えないケース（前提が崩れるケース）：
  - JS必須/SSO必須の場合、curlだけでは成立しない（ブラウザ+HAR/Proxyで観測へ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V2（Authentication）：パスワード回復/リセットの本人確認、回復コード/トークンの強度、列挙耐性、Rate limit、回復後の再認証（必要なら）に接続する。V3（Session Management）：回復完了時のセッション失効、長期トークンの回収、trusted device の扱い（免除の回収）に接続する。
  - 該当要件（可能ならID）：V2（Authentication）、V3（Session Management）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：回復経路の成立条件と境界を観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Authentication Testing：Password Reset / Account Recovery のテスト観点（列挙・トークン単回性・TTL・本人確認）として扱う。Session Management：回復後のセッション回収・失効・再利用窓の観測として扱う。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：回復経路の観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering（回復経路と資産形態の把握）→ Vulnerability Analysis（単回性/TTL/列挙/失効の評価）→ Exploitation（最小差分で影響確認）→ Reporting（証跡と改善提案）へ接続。
  - 前後フェーズとの繋がり（1行）：回復経路と資産形態の把握→単回性/TTL/列挙/失効の評価→最小差分で影響確認→証跡と改善提案の品質を上げる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Credential Access / Valid Accounts / Defense Evasion
  - 攻撃者の目的（この技術が支える意図）：Credential Access（アカウント回復/リセット経路の悪用で"認証資産"を再取得する目的）、Valid Accounts（回復により有効アカウント状態を奪う/維持する目的）、Defense Evasion（回復後も既存セッションが残る場合、検知回避・持続に寄与する前提）に接続。
  - 参照：https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0001/（Initial Access - Valid Accounts）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）

## 参考（必要最小限）
- OWASP Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- 関連 topics：`01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`
- 関連 topics：`01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`
- `01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`
- `01_topics/02_web/02_authn_09_password_policy（強度_漏えい照合_禁止語）.md`
- `01_topics/02_web/02_authn_11_account_recovery_本人確認（サポート代行_回復コード）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
