# 03_authz_09_admin_console_運用UIの境界
運用UI（管理コンソール）を「単なる画面」ではなく、(1)管理者の種類（system/tenant/support）、(2)分離（別ドメイン/別IdP/別セッション）、(3)裏APIの実体（admin API/internal API）、(4)重要操作（06）と例外運用、(5)監査・否認防止、としてモデル化し、短時間で"致命的な境界崩壊"を発見する

---

## 目的（この技術で到達する状態）
- 運用UI（管理コンソール）を「単なる画面」ではなく、(1)管理者の種類（system/tenant/support）、(2)分離（別ドメイン/別IdP/別セッション）、(3)裏APIの実体（admin API/internal API）、(4)重要操作（06）と例外運用、(5)監査・否認防止、としてモデル化し、短時間で“致命的な境界崩壊”を発見できる
- admin UI が存在するだけで危険という誤解を避け、危険なのは「境界の曖昧さ」「例外パス」「監査の弱さ」として具体的に説明できる
- エンジニアへ「どこを分離し、どこで強制し、何をログに残すか」を運用・実装両面で提案できる
- 03（multi-tenant）、04（RBAC/ABAC）、06（重要操作）、08（ファイル）、10（状態遷移）の交点として、最短でImpactが最大化する突破口を評価できる

## 前提（対象・範囲・想定）
- 対象：運用UI（管理コンソール、サポートツール、管理API、バックオフィス）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 管理者の種類（ここを曖昧にしない）：system admin（全テナント横断で操作できる（最強権限））、tenant admin（自テナント内で運用操作できる）、support/ops（サポート代行・復旧・調査のための権限（しばしば例外が多い））、read-only auditor（監査閲覧のみ）
  - 運用UIは「権限が強い」「例外パスが多い」「実装が別系統」で、AuthZの最大破綻点になりやすい。ここが抜けると単発バグが"全顧客影響"に拡大する。
- できること/やらないこと（安全に検証する範囲）：
  - できること：管理機能は影響が大きいため、テスト環境/権限付与された検証アカウント前提で最小差分検証する、本番での検証は「閲覧可能性の確認」「拒否の一貫性」「監査の有無」中心に留める
  - やらないこと：重要操作（権限付与/復元/削除/輸出/一括操作）は06の枠組みで扱う
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
  - `01_topics/02_web/03_authz_04_rbac_abac_判定点（policy_engine）.md`
  - `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 運用UI（管理コンソール）を「単なる画面」ではなく、(1)管理者の種類（system/tenant/support）、(2)分離（別ドメイン/別IdP/別セッション）、(3)裏APIの実体（admin API/internal API）、(4)重要操作（06）と例外運用、(5)監査・否認防止、としてモデル化し、短時間で"致命的な境界崩壊"を発見する
    - admin UI が存在するだけで危険という誤解を避け、危険なのは「境界の曖昧さ」「例外パス」「監査の弱さ」として具体的に説明する
    - エンジニアへ「どこを分離し、どこで強制し、何をログに残すか」を運用・実装両面で提案する
  - 扱わない（別ユニットへ接続）：
    - "内部API"の全数（外部から見えない場合）。ただしUI観測とエラー/JSから相当数は推定できる → 別ユニット

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) “管理面”の境界設計：まず分離があるか（分離は最強の防御）
管理コンソールの強度は、分離（isolation）で大きく決まる。
- 分離の軸（強い順の一般論）
  - 専用ドメイン/サブドメイン（admin.example.com）＋別IdP
  - 同一IdPでも専用クライアント/専用ポリシー（MFA必須等）
  - 同一ドメインだがパス分離（/admin）
  - APIだけ分離（/admin-api、/internal）
- 観測で確定したい点
  - admin UIが一般ユーザ向けと同じセッション/同じCookie領域で動いていないか
  - admin UIのAuthNが強化されているか（MFA/step-up/短いセッション）
  - “同一ブラウザで一般ユーザ→管理者”がスムーズに切り替わる設計か（混在リスク）

### 2) 管理者種別（system/tenant/support）とテナント境界（03）の整合
最大事故は「tenant admin が system admin 相当の範囲を触れる」。
- 観測の軸
  - tenant admin が参照できる範囲：自テナントのみに束縛されているか
  - system admin の操作：全テナント横断が許されるが、監査・追加ガードがあるか
  - support/ops：代行操作がある場合、テナント指定がクライアント入力になっていないか
- 典型の破綻
  - 管理画面で org_id/tenant_id をURL/ヘッダ指定し、それが無検証で採用される（03）
  - “検索/一覧”が横断で動き、結果から詳細操作へ到達できる（03の検索問題が最悪形で出る）
  - 管理者ロールがUI上だけで、APIではチェックが抜ける（04）

### 3) 裏API（admin API / internal API）：UIよりAPIが本体
運用UIの脆弱性は、多くが裏APIの露出・認可不備にある。
- 典型構成
  - UI：adminフロント（SPA）
  - API：/admin-api /internal-api /ops-api など
- 観測で確定したい点
  - 裏APIが一般ユーザのセッションでも到達できないか（最重要）
  - APIの認可が“画面遷移”に依存していないか（直接叩ける）
  - admin APIが同一ホスト/同一CORS/同一Cookieで動いていないか（境界混在）
- 典型の破綻パターン
  - 管理UIは隠されているが、APIはインターネットから到達可能
  - UIでボタンが出ないだけで、APIに直接投げると実行できる（PEPがUI）
  - /internal が“社内想定”でAuthZが無い（公開されると致命的）

### 4) 重要操作（06）との結合：運用UIは“強い操作が集約”される
運用UIにある典型の重要操作を列挙し、追加ガードと監査があるかを見る。
- 代表的な運用操作（高Impact）
  - ユーザ/ロール管理（付与/剥奪/一括）
  - アカウント復旧/ロック解除/2FAリセット（AuthN 11/19と接続）
  - 支払/請求の確定・返金（送金系）
  - データ削除/復元（論理削除含む）
  - エクスポート/一括ダウンロード（ファイル：08）
  - 監査ログ閲覧・証跡ダウンロード（証拠の改ざん/秘匿にも繋がる）
- 観測で確定したい点
  - 重要操作が通常更新で成立していないか（05/06）
  - step-up（AuthN 16）や二人承認が必要な操作が定義されているか
  - “一括操作”がレート/上限/承認無しで無制限になっていないか

### 5) 監査・否認防止：adminは「操作ログが本体」
管理面は、脆弱性が無くても監査が弱いと事故になる。
- 監査に必要な最小フィールド（推奨）
  - admin_actor_id（管理者ID）
  - admin_role（system/tenant/support）
  - tenant_id（対象）
  - action（lock解除/role付与/export/削除等）
  - target（user_id/object_id）
  - reason（サポート理由、チケット番号）
  - channel（UI/API/job）
  - request_id（相関）
  - decision（allow/deny）と拒否理由
- 観測で確定したい点
  - denyもログに残るか（攻撃・誤操作の検知）
  - “代行操作”の理由（reason）が必須か（後追いで説明できるか）
  - 監査ログ自体の閲覧権限が適切か（機微情報・全テナント横断）

### 6) セッションと運用安全：管理セッションは“別物”として扱うべき
- 強い設計の兆候
  - 管理セッションの寿命が短い（短時間）
  - MFA/step-up必須
  - 端末制限/IP制限（必要なら）
  - 重要操作は再認証要求
  - CSRF対策・SameSite等（AuthN 13/14と接続）
- 危険な兆候
  - 一般ユーザのセッションCookieでそのまま管理APIにアクセスできる
  - “ログアウト”や“権限剥奪”が管理セッションに即時反映されない（15/17の概念にも波及）

### 7) admin_console_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：admin_console_key_boundary
  - admin_console_key_boundary = <isolation>(separate_domain|subdomain|path_only|api_only|none|unknown) + <authn_strength>(mfa_required|stepup_required|weak|unknown) + <admin_types>(system|tenant|support|mixed|unknown) + <tenant_scope_enforced>(yes/no/partial/unknown) + <admin_api_exposure>(public|internal_only|unknown) + <pep_location>(api|ui_only|mixed|unknown) + <audit_strength>(strong|partial|weak|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - admin_host/path（分離の根拠）
  - admin_cookie/session（別物か）
  - admin_api_endpoints（代表3〜10本）
  - tenant指定の仕組み（URL/ヘッダ/選択UI/トークン）
  - 重要操作一覧（06と接続）
  - evidence（HAR、拒否/許可差分、設定断片、監査ログ断片）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 管理面がどの程度分離されているか（ドメイン/IdP/セッション）
  - 管理者種別ごとのテナント範囲が強制されているか（03）
  - 裏APIの露出と、PEPがUIではなくAPIにあるか（04）
  - 重要操作に追加ガード（MFA/step-up/承認/上限）と監査があるか（06）
- 何が"推定"できるか（推定の根拠/前提）：
  - 分離が弱く、admin APIが公開で、PEPが混在している場合、致命的な突破口になりやすい
  - 監査が弱い場合、脆弱性がなくても運用事故やインシデント調査不能という重大リスク
- 何は"言えない"か（不足情報・観測限界）：
  - "内部API"の全数（外部から見えない場合）。ただしUI観測とエラー/JSから相当数は推定できる。
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：一般ユーザ権限で admin API が到達・実行できる（UI非表示でも） → 管理UIを「入口（UI）」「裏API」「内部API」「役割境界（system/tenant/support）」に分解し、例外パスと権限過剰を差分で確定する
  - パターンB：tenant admin が他テナントを検索/操作できる（03の崩壊） → 管理者種別ごとのテナント範囲が強制されているか（03）を観測
  - パターンC：support/ops 代行が tenant指定をクライアント入力で決めている（越境の温床） → support/ops 代行が tenant指定をクライアント入力で決めている兆候を観測
  - パターンD：admin操作に追加ガードや監査が無い（否認防止不可） → 重要操作に追加ガード（MFA/step-up/承認/上限）と監査があるか（06）を観測

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 一般ユーザ権限で admin API が到達・実行できる（UI非表示でも）
    - tenant admin が他テナントを検索/操作できる（03の崩壊）
    - support/ops 代行が tenant指定をクライアント入力で決めている（越境の温床）
    - admin操作に追加ガードや監査が無い（否認防止不可）
    - エクスポート/一括DL/ファイル管理が無制限で実行できる（08）
  - P1：
    - 分離が弱い（同一Cookie/同一IdPで管理に入れる）
    - 重要操作の一部だけガード/監査が薄い（運用事故リスク）
  - P2：
    - 設計は堅牢だが複雑で、例外運用（復旧/サポート）に穴が開きやすい（11と接続）
- “成立条件”としての整理（技術者が直すべき対象）
  - 管理面を分離（可能なら別ドメイン/別IdP/別セッション）
  - admin API は必ずAPI側で認可（UI依存を排除）、例外パス（/internal）を公開しない
  - system/tenant/support の権限範囲を明確化し、tenantスコープを強制
  - 重要操作は追加ガード（step-up/二人承認/上限）＋監査（reason必須）をセットで実装する

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：admin API が一般セッションで到達可能
  - 次の検証（最小差分）：
    - admin UI の操作で観測した裏APIを、一般ユーザで同条件で叩いたときに拒否されるか差分観測
  - 判断：
    - 実行/データ取得が成立：P0
- 仮説B：tenantスコープが弱い（横断検索・操作）
  - 次の検証：
    - tenant admin で「検索/一覧/詳細/エクスポート」の各入口が自テナントに束縛されているか差分観測
  - 判断：
    - 他テナント混入：P0
- 仮説C：PEPがUI側（ボタン非表示）に寄っている
  - 次の検証：
    - 画面遷移で隠されている操作が、API直叩きで拒否されるかを観測（04のPEP観点）
  - 判断：
    - APIで拒否されない：P0
- 仮説D：監査・reasonが無い
  - 次の検証：
    - 操作後に監査履歴が残るか、また拒否も残るか（可能なら）
  - 判断：
    - 追跡不能：P1（運用上は重大）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/09_admin_console_boundary/`
    - 構成案：
      - admin types：system/tenant/support を用意（テナント2つ）
      - 分離：別ドメイン/同一ドメイン（パス分離）を切替
      - admin API：公開/内部想定を切替し、誤公開の影響を再現
      - 重要操作：role付与、2FAリセット、エクスポート、削除/復元、ファイル一括DL
      - ガード：MFA/step-up/二人承認/上限を切替
      - 監査：reason必須/任意、denyログ有/無を切替
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：admin UI操作の裏API、一般ユーザでの差分
  - 設定断片：CORS、Cookie属性、IdP設定（可能なら）
  - ログ：admin decision、tenant scope、reason、request_id
  - 監査：操作履歴（否認防止）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 管理UI裏API（擬似）
GET  /admin-api/users/search?q=...
POST /admin-api/users/123/grant-role
POST /admin-api/users/123/reset-2fa
GET  /admin-api/export/users.csv
POST /admin-api/files/bulk-download

# 観測すること（擬似）
- 一般ユーザのセッションで admin-api が拒否されるか（到達できないか）
- tenant admin が他テナントに触れないか（scope強制）
- 重要操作に step-up/監査（reason）があるか
~~~~
- この例で観測していること：
  - PEPがUIではなくAPIにあり、かつテナント境界と追加ガードが成立していること
- 出力のどこを見るか（注目点）：
  - admin_api_exposure、pep_location、tenant_scope_enforced、authn_strength、audit_strength
- この例が使えないケース（前提が崩れるケース）：
  - 管理機能が完全に外部SaaS（Zendesk等）で運用（→連携トークン/代行権限/監査の境界として別途扱う）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V4（認証・セッション管理）、V5（アクセス制御）、V7（ログとモニタリング）
  - 該当要件（可能ならID）：V4.2（セッション管理）、V5.1（一般的なアクセス制御設計）、V7.1（ログ要件）
  - このファイルの内容が「満たす/破れる」ポイント：管理機能の分離（ドメイン/IdP/セッション）、管理者種別ごとのテナント範囲の強制、裏APIの露出とPEPの位置、重要操作への追加ガードと監査
- WSTG：
  - 該当カテゴリ/テスト観点：AUTHZ-01（Authorization Testing：Admin interfaces）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：管理UIを「入口（UI）」「裏API」「内部API」「役割境界（system/tenant/support）」に分解し、例外パスと権限過剰を差分で確定する
- PTES：
  - 該当フェーズ：Post-Exploitation（権限昇格・横展開）
  - 前後フェーズとの繋がり（1行）：運用面の入口列挙→差分観測→成立条件確定
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：TA0004（Privilege Escalation）、TA0040（Impact）
  - 攻撃者の目的（この技術が支える意図）：管理面は最短経路で権限昇格・横展開・影響拡大を実現できる

## 参考（必要最小限）
- OWASP ASVS（管理機能の保護、監査、セッション）
- OWASP WSTG（Authorization Testing：Admin interfaces）
- PTES（運用面の入口列挙→差分観測→成立条件確定）
- MITRE ATT&CK（Privilege Escalation/Impact：管理面は最短経路）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/03_authz_08_file_access_ダウンロード認可（署名URL）.md`

---

## 深掘りリンク（最大8）
- 関連 topics：
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `01_topics/02_web/03_authz_01_境界モデル（オブジェクト_ロール_テナント）.md`
  - `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
  - `01_topics/02_web/03_authz_04_rbac_abac_判定点（policy_engine）.md`
  - `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
  - `01_topics/02_web/03_authz_10_object_state_状態遷移と権限（draft_approved）.md`
- 関連 labs / cases：
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
