# 15_token_lifetime_更新と失効（SaaS側）

## ガイドライン対応
- ASVS：V2（認証）/V3（セッション管理）/V4（アクセス制御）/V10（エラーとログ）/V14（設定）  
  - このファイルでは「トークン寿命・更新・失効・再利用検知」が、セッション管理と認可強度の“実装境界”としてどこで破れるかを扱う
- WSTG：WSTG-ATHN（認証）/WSTG-SESS（セッション管理）/WSTG-AUTHZ（認可）/WSTG-CONF（設定・運用）  
  - 特に「ログアウト/失効の実効性」「更新トークンのローテーション」「APIトークンの取り扱い」を観測テストとして接続する
- PTES：Intelligence Gathering（構成把握）→ Vulnerability Analysis（寿命・失効の弱点同定）→ Exploitation（再利用可能性の検証：安全範囲）→ Post-Exploitation（持続性/検知可能性の評価）→ Reporting（境界と改善案）
- MITRE ATT&CK：Credential Access / Persistence / Defense Evasion / Lateral Movement（SaaS間連携）/ Discovery（監査ログ・同意画面・トークン種別把握）

## 目的（この技術で到達する状態）
SaaS における「トークン（セッション/Access/Refresh/APIキー等）がいつまで有効で、何を契機に失効し、更新はどこで行われ、再利用は検知されるか」を、観測から“状態”として言語化できるようにする。  
その上で、ペンテスト実務として以下を判断できる状態になる。

- 失効が「見かけ上のログアウト」なのか「実効的な失効」なのかを切り分けられる
- Access Token の短命化でカバーしているのか、Refresh Token/セッションが実質長命なのかを説明できる
- 失効・更新・ローテーションの境界（IdP / SaaS / クライアント / 中継）を特定し、次の検証手順を選べる
- “奪取済みトークンの再利用が成立する条件/成立しない条件”を、A/B 分岐で提示できる

## 前提（対象・範囲・想定）
- 対象：SaaS（例：M365/Entra、Okta、Google Workspace、Slack、GitHub、Atlassian 等）における認証後の「継続アクセスの仕組み」
- 範囲：トークン寿命（exp/TTL）、更新（refresh/reauth）、失効（logout/revoke/disable）、再利用検知（reuse・device binding 相当）、監査ログ（誰が何をいつ）
- 想定するトークン種別（SaaSにより呼称は異なる）
  - ブラウザセッション：Cookie（SaaSドメイン/IdPドメイン）＋バックエンドセッションストア
  - API 呼び出し：Bearer Access Token（JWT/opaque）、API Token（PAT等）、App Token（アプリ連携）
  - 更新用：Refresh Token（回転/静的、グレース期間、失効連鎖）
- 実施環境：  
  - 観測：ブラウザ開発者ツール、プロキシ（HTTPログ/har）、必要に応じて pcap  
  - 変更は最小限（トークン文字列の差し替え・再送・時刻経過）で、「DoS/大量試行」は行わない
- 注意：本ファイルは“成立条件の観測と判断”が主目的。特定SaaSの管理画面操作手順の丸写しはしない（運用差分が大きく陳腐化しやすいため）。

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 「どのトークンが、どの境界で発行されているか」
同じ “ログイン済み” でも、以下が混在する。まず「発行主体」と「提示先」を分離して観測する。

- IdP → SaaS（SSO境界）
  - Authorization Code / PKCE / state/nonce（入口）
  - Token Endpoint 応答（access_token / refresh_token / expires_in / scope）
  - Id Token（OIDC）の exp / iat / aud / iss（認証の証拠）
- SaaS 内部（SaaSセッション境界）
  - SaaSドメインのセッションCookie（属性・更新頻度）
  - “Remember me”/永続Cookie の有無
  - API を叩くフロントが Bearer を持つか（SPA型）/Cookie依存か（従来型）

観測の最小セット（HTTPで見るもの）
- Set-Cookie：Domain/Path/Secure/HttpOnly/SameSite/Expires/Max-Age
- Authorization: Bearer ...（あるか、どこに送っているか）
- Token 返却ペイロード：expires_in / refresh_token の有無
- レスポンス：401/403 の違い（認証切れ vs 認可不足）、WWW-Authenticate ヘッダ有無

~~~~
# JWTかどうかの“判定”はデコードできるかではなく「構造」と「検証方式」で見る
# 1) "."で区切れて3部/5部ならJWT/JWEの可能性が高い
# 2) exp/iat がある → “期限は主張できる”が “失効できる”とは限らない（後述）
# 3) SaaSが introspection（問い合わせ）をしているか → 失効の即時性に直結
~~~~

### 2) 「寿命（lifetime）= どの時刻が効いているか」
“期限”には種類がある。混同すると判断を誤る。

- Access Token の exp（短命化の代表）
- Refresh Token の有効期限（固定期限 or “未使用で失効”）
- セッションの idle timeout（操作がなければ失効）
- セッションの absolute timeout（操作があっても期限で失効）
- 条件付き再認証（ステップアップ、CA、リスクベース）で “途中で失効したように見える” ケース

観測方法（実務で最短に切り分ける）
- 時刻経過テスト：短い間隔（例：10分/30分/2時間/半日）で再送して変化点を探す
- “更新イベント”の有無：操作したタイミングで cookie/token が更新されるか（rollingか固定か）
- “別端末/別IP” の差分：同一トークンを別条件で提示して挙動が変わるか（binding相当）

### 3) 「失効（revocation）はどこまで効くか」
失効は “操作” と “実効性” を分けて見る。

- ユーザ側の操作：ログアウト、アプリ連携解除、パスワード変更、MFA再設定
- 管理者側の操作：アカウント無効化、セッション強制サインアウト、トークン取り消し、CA変更
- 実効性の論点
  - 既存Access Tokenが即死するか（JWT短命化で“放置”の設計も多い）
  - Refresh Tokenが無効化されるか（再発行されないか）
  - 既存セッションCookieが無効化されるか（サーバ側セッションストアが切られるか）
  - 失効が “特定クライアントのみ” か “全端末/全アプリ” か

観測の最小セット（HTTPで見るもの）
- ログアウト後の再送：200継続 / 401 / 302で再ログイン誘導 のいずれか
- “同意解除”後の再送：Accessは生きるがRefreshが死ぬ、などの分離が起きるか
- “失効の遅延”：直後は通るが数分後に落ちる（キャッシュ/分散の遅延を疑う）

### 4) 「更新（refresh/reauth）はどこで起きるか」
更新は “自動” と “明示” がある。

- 明示：Token Endpoint に refresh_token grant で更新（OAuth標準）
- 自動：バックグラウンドで silent refresh（iframe/redirect）、Cookie更新、SDKが更新
- 例外：更新せずに“再認証”を要求（SSOへ戻す、ステップアップ要求）

観測のコツ
- 通信ログを “時間軸” で見る（操作していないのに token endpoint が叩かれているか）
- 403/401直前に “更新系リクエスト” が走っていないか
- “更新に必要な追加材料”（client_secret、DPoP、mTLS、device key 等）があるか

### 5) 「再利用（reuse）の検知・抑止があるか」
ここが「長命トークンが長命でも被害が限定される設計」かどうかの分岐点。

観測対象（例）
- Refresh Token Rotation（回転）と reuse 検知
  - 同じ refresh_token を2回使うとどうなるか（新旧どちらが生きるか、全セッションが切られるか）
  - グレース期間（数十秒〜数分）で旧トークンが一時有効か
- “端末紐付け相当” のシグナル
  - device_id 的なクッキー/ヘッダ、mTLS、DPoP、連携アプリの署名キー
  - IP/UA 変化で再認証になるか（=厳密なbindingではなく“リスク評価”の可能性もある）

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 状態1：Access Token短命だがRefresh/セッションが長命（実質「継続アクセス」強い）
- 言えること
  - 盗まれた access_token の単発再利用リスクは限定される可能性
  - ただし refresh_token / セッションCookie が盗まれると、長期アクセスに転ぶ
- 言えないこと
  - “ログアウトすれば安全” とは言えない（失効が refresh/セッションに効かない設計がありうる）

判断の軸
- 更新が発生する主体：クライアントが refresh を持つ（特にSPA/モバイル）なら “持ち出し面” が増える
- 失効のトリガ：アカ無効化・同意解除・強制サインアウトで refresh/セッションが落ちるか

### 状態2：JWT Access Tokenで即時失効しない（=短命化でカバーする設計）
- 言えること
  - “今この瞬間に取り消す” が難しい設計の可能性（署名検証のみで問い合わせしない）
  - 失効要件は「expを短くする」「refreshを取り消す」「次回更新を止める」に寄る
- 言えないこと
  - JWTであること自体が脆弱とは言えない（設計選択）。問題は「寿命・更新・漏えい時の制御」

### 状態3：Refresh Token Rotation + reuse検知がある（継続アクセスの“境界が強い”）
- 言えること
  - “奪取後の継続” を成立させにくい（使った瞬間に旧が死ぬ、異常検知で切れる等）
  - ペンテストでは「再利用が成立する条件」をA/Bで明確化できる
- 言えないこと
  - 侵害が起きないとは言えない（初回利用で被害は起きうる）。ただし横展開/永続化が難しくなる

### 状態4：API Token / PAT が長命・失効が運用依存（典型的に“人”の運用境界）
- 言えること
  - “人が回収しない限り生きる” という運用リスクが発生しやすい
  - 監査ログと棚卸し（発行者/最終利用/スコープ）が重要になる
- 言えないこと
  - 一律に短命化できるとは限らない（SaaS機能制約）。代替策（スコープ最小化・IP制限・利用検知）が必要

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
ここは “手口” ではなく “成立条件の読み替え” を扱う（観測→判断が主）。

### 優先度が上がる状態（攻撃者が“得をする”設計）
- 長命Refresh/長命セッションがあり、失効が遅い/弱い
- “同意（consent）” を取り消しても既存トークンが一定時間通る
- API Token/PAT が期限なし or 棚卸しされていない（最終利用が追えない）
- 監査ログが取れていない/相関できない（誰が何をいつ、が追えない）

### 次の仮説（例）
- 仮説：Accessは短命でも Refresh が静的で、漏えいすると長期アクセスになりうる  
  → 更新フローの存在/ローテーション/失効連鎖を観測する
- 仮説：ログアウトはUI上だけで、サーバ側セッションが切れていない  
  → ログアウト前後で同一Cookie/同一API呼び出しの挙動を比較する
- 仮説：条件付きアクセス/リスク評価が「途中失効」を作っている  
  → IP/UA/端末条件を変えたときの再認証要求の差分を見る（“binding”と誤認しない）

## 次に試すこと（仮説A/Bの分岐と検証）
以下は「安全な範囲で、最小の再送と時間差」で境界を確定させる手順。

### ステップ0：トークン資産の棚卸し（観測の土台）
- A：ブラウザセッション中心（Cookieで成立、Authorizationヘッダは見えない）  
  → 以降は cookie 更新/サーバ側セッション失効 が主戦場
- B：Bearer中心（Authorization: Bearer が安定して見える）  
  → access/refresh の寿命と更新点（token endpoint）を主戦場にする

~~~~
# 観測メモ（テンプレ）
# - どのホストに何を提示しているか（SaaS / IdP / API gateway）
# - 認証素材：Cookie / Bearer / API Token / mTLS/DPoP 等
# - 更新素材：refresh_token / silent refresh / session rolling
# - 失効操作：logout / revoke / admin sign-out / disable
# - ログ：SaaS監査ログ / IdPログ / アプリログ（相関キー）
~~~~

### ステップ1：寿命の実測（exp/idle/absolute の切り分け）
- 実測の基本：同一リクエストを「時間を置いて」1回ずつ再送し、変化点を探す
- 例の分岐
  - A：放置で切れる（idle）  
    → 一定時間無操作後に 401/302。操作すると延命する（rolling）
  - B：一定時刻で切れる（absolute）  
    → 操作しても同じ時刻で 401/302。更新が止まる
  - C：切れないが途中で再認証要求（条件付き）  
    → 特定操作/重要APIで 403/step-up 相当。単純な寿命問題ではない

最小の再送例（“例”として）
~~~~
# 例：同一APIを時間差で再送（Cookie/Bearerどちらでも）
# curlは例示。実務はプロキシのrepeaterでも良い（証跡が残るため）
curl -i 'https://target.example/api/me' -H 'Authorization: Bearer <token>'
~~~~

### ステップ2：ログアウト/失効の実効性（「見かけ」vs「本当に死んだ」）
- A：ログアウト直後に旧トークン/旧Cookieが即 401 になる  
  → サーバ側で失効できている（少なくとも当該経路では）
- B：ログアウト後も一定時間通る  
  → 以下を追加観測
  - キャッシュ/分散遅延か（数分で落ちる）
  - accessだけ生きていて refresh が死んでいるか（更新できずに自然死）
  - “logoutはSaaSだけ” で IdPセッションが生きており即再ログインになるか（SSO境界）

### ステップ3：Refresh/更新の境界（回転・静的・グレース）
- A：Refresh Token Rotation（回転）している  
  → 同じ refresh_token を再利用した時の挙動を「安全に」観測（2回目の更新要求でエラー/失効連鎖）
- B：Refresh Token が静的（同値のまま）  
  → 長期漏えいリスクが増える。次の一手は “失効トリガ” の強さ（同意解除/管理者操作/未使用失効）を実測

※観測の要点：  
- 回転しているかどうかは “refresh_token の値が変わるか” だけでは不十分（Okta等は条件で新refreshを返さないことがある）。  
- 「再利用時に何が起きるか（セッション全断/当該クライアントのみ/単に失敗）」が設計の核心。

### ステップ4：API Token/PAT 系（SaaS運用境界の強弱）
- A：有効期限・最終利用・スコープが可視化され、失効が容易  
  → “漏えい時の被害時間” を短縮できる設計。監査ログと相関できるかを確認
- B：期限なし/最終利用不明/棚卸し困難  
  → 技術的対策（短命化）が難しい場合、運用対策（発行制限・最小権限・検知/アラート）に寄せる必要がある

### ステップ5：検知・相関（「いつ誰が何を」で語れるか）
- 相関キー設計（現場で効くもの）
  - user/principal id
  - app/client id（同意/アプリ登録の単位）
  - token id / jti / session id（取れる範囲で）
  - ip / user-agent / device id（“binding相当”の説明に必要）
  - request id / trace id（SaaS側が提供する場合）

観測結果のまとめ方（報告でブレない）
- “失効の対象範囲” を明記：当該トークンのみ / 当該アプリ / 全端末 / 全アプリ
- “失効までの時間” を明記：即時 / 数分遅延 / 次回更新まで / expまで
- “再利用検知” の有無：reuseで遮断/通知/全断/何も起きない

## 参考（必要最小限）
- OpenID Connect Core 1.0（ID Token/トークン寿命の考え方）  
  https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7009 OAuth 2.0 Token Revocation（失効エンドポイントの標準）  
  https://www.rfc-editor.org/rfc/rfc7009.html
- RFC 7662 OAuth 2.0 Token Introspection（トークンの“有効か”問い合わせ）  
  https://www.rfc-editor.org/rfc/rfc7662.html
- Google OAuth 2.0 Policies（refresh token の失効/期限に関する前提）  
  https://developers.google.com/identity/protocols/oauth2/policies
- Google（例：YouTube Data API）Token revoke endpoint（oauth2.googleapis.com/revoke の例）  
  https://developers.google.com/youtube/v3/guides/auth/server-side-web-apps
- Okta Refresh Token rotation（回転/グレース/寿命の考え方）  
  https://developer.okta.com/docs/guides/refresh-tokens/main/
- Okta Token revocation（失効の扱い）  
  https://developer.okta.com/docs/guides/revoke-tokens/-/main/
- Slack Token rotation（SaaS側で“無期限→期限あり”に変える例）  
  https://docs.slack.dev/authentication/using-token-rotation/
- Slack Verifying requests（トークン以外の“継続アクセス”境界：署名検証）  
  https://api.slack.com/docs/verifying-requests-from-slack

