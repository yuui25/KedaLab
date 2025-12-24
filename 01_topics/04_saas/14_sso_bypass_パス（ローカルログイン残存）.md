# SSOバイパス：ローカルログイン残存（SaaSの境界・観測・分岐）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：V2（認証）、V3（セッション管理）、V4（アクセス制御）、V14（設定・運用/監査）を、このファイルの「SSO強制が“境界”になっているか/代替経路が残っているか」の観点で使用
- WSTG：WSTG-ATHN（認証テスト：バイパス/代替経路）、WSTG-SESS（セッション：SSO後の継続/再認証）、WSTG-INFO（情報収集：ログイン経路の列挙）を、このファイルの観測と検証に対応付け
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis（SaaS設定）→ Exploitation（成立確認）→ Reporting（再現性と影響の境界）
- MITRE ATT&CK：Valid Accounts、Account Manipulation、Use Alternate Authentication Material、External Remote Services（SaaSログイン/トークン）に位置付け

## 目的（この技術で到達する状態）
SaaSにおいて「SSOが強制されている」という主張を、ログイン経路（UI/API/クライアント）ごとに分解し、
- どの経路がSSO（IdP）境界を跨ぐか
- どの経路が“ローカル認証（SaaS内蔵）”として残存しているか
- 残存が設計上の意図（ブレークグラス/ゲスト例外）か、設定ミス/運用抜けか
を観測で判定し、次の攻め筋（または是正提案）に繋げられる状態にする。

## 前提（対象・範囲・想定）
- 対象：SaaS（例：Slack / GitHub / Atlassian 等）＋連携IdP（Microsoft Entra ID / Okta / Google Workspace 等）
- 境界の種類
  - 資産境界：SaaSの“組織/テナント/ワークスペース/Org”と、個人アカウント領域（Personal）・外部ゲスト領域の切れ目
  - 信頼境界：SaaS（SP）とIdPの責任分界（SAML/OIDCの成否、フェイルオープン/フェイルクローズ）
  - 権限境界：Owner/Admin/Break-glass/Service Account/Guest の例外経路
- 想定する“SSOバイパス”の定義
  - 「SSO必須」の想定にもかかわらず、IdPを経由せずにSaaSへ認証済みセッション/アクセストークン等を得られる経路が存在すること
  - ただし、設計上のブレークグラス（Ownerのみ・強固な2FA・監査強化）として許容されるケースもあるため、“仕様”と“境界逸脱”を切り分ける

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) ログイン経路の“面”を先に分解する（UIだけ見ない）
SSO強制の破り方は「UIの別ボタン」よりも「別クライアント/別プロトコル/別リソース種別」に潜む。

- UI（ブラウザ）：
  - 通常ログイン（email+password）
  - SSOボタン（SAML/OIDCリダイレクト）
  - “Sign in with email/password” のバイパスリンク（Owner/Admin向けが典型）
  - パスワードリセット/マジックリンク（ローカル認証が前提の回復経路）
- API / CLI（非対話）：
  - PAT / API Token / SSH key / App password（“Alternate Auth Material”）
  - OAuth App / GitHub Apps / Slack App 等のトークン
- ゲスト・外部ユーザ系：
  - “SSO対象外”として残るサインイン（Guestや外部ドメイン）
  - ドメイン未検証/未管理アカウント（Managed vs Unmanagedの境界）
- “例外設計”：
  - Break-glass（緊急管理者、Ownerのローカルログイン）
  - ライセンス/ポリシー適用範囲の穴（特定ユーザがSSO強制対象外）

### 2) 具体的に取る証跡（後で差分比較できる形）
- HAR（ブラウザ）：
  - SSO開始URL（/sso, /saml, /oauth/authorize 等）
  - ローカルログインURL（/login, /signin, /session, /password 等）
  - 302チェーン（SSO強制なら“必ずIdPへ飛ぶ”はずの地点）
  - Cookie発行の瞬間（Set-Cookieの有無、SSO前後の差分）
- リクエスト/レスポンス：
  - SAML：SAMLRequest / RelayState / ACS URL、署名要否（SignedResponse/Assertion）
  - OIDC：client_id / redirect_uri / state / nonce / code_challenge（PKCE）
  - ローカル認証：username/email + password、reset token、magic link token
- SaaS管理画面側（設定の“適用範囲”の観測）：
  - “SSO required / optional / partially required” のような3値（強制/任意/部分）
  - “適用対象グループ/ユーザ” の範囲（全員に当たっているか）
  - “ゲスト除外”の仕様（外部協力者がローカルログイン可能等）
- 監査ログ（重要）：
  - SSOログ（IdP側）と、SaaS側のサインインイベントの相関（同一ユーザがIdPログ無しでSaaSサインインできていないか）

### 3) “強制されている”と言える観測条件（判定ルール）
次のどちらを満たすかで、SSO強制の実態を切り分ける。

- 強い強制（フェイルクローズ寄り）：
  - 組織リソースへアクセス時、未SSO状態では必ずIdPへ誘導される
  - ローカルログイン経路がUI上・URL直叩きでも成立しない（強制リダイレクト、または認証拒否）
  - 非対話トークンも“SSO承認（authorize/attest）”や“組織紐付け”を要求し、未承認は使えない/スコープが制限される
- 弱い強制（穴が残りやすい）：
  - “SSOボタンがある”だけで、email+passwordが通常通り動く
  - 強制対象が“特定グループのみ”で、未所属はローカルログイン可能
  - ゲスト/外部ユーザがローカルログイン可能で、境界が曖昧
  - 管理者/Ownerのバイパスが存在し、監査や2FAが弱い

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 状態A：ローカルログイン経路が完全に閉じられている
- 言えること：
  - UI経路における認証境界はIdPに集約されている
  - “IdPのMFA/条件付きアクセス/リスク判定”が、少なくともブラウザログインには作用する
- 言えないこと：
  - API/CLIの代替認証（PAT/トークン/SSH）が同等に縛られているとは限らない
  - 例外アカウント（break-glass）が存在しないとは限らない（存在して良いが管理が要る）

### 状態B：ローカルログインが“例外として”残っている（Owner/Admin/Break-glass/Guest）
- 言えること：
  - 権限境界（Owner/Admin/Guest）が“認証経路の境界”にもなっている
  - IdPが落ちた際の可用性確保（ブレークグラス）という設計意図の可能性が高い
- リスクの焦点：
  - 例外が“想定より広い”（Owner以外も使える、Guestが重要資産に到達できる等）
  - 例外経路が弱い（2FAが弱い/無い、パスワードが運用で回りがち、監査が薄い）

### 状態C：SSOはUIのみ強制で、非対話トークン/別プロトコルが“素通り”する
- 言えること：
  - “SSO強制＝全アクセス制御”ではない。代替認証素材が別の境界になっている
- 典型的な影響：
  - フィッシングや漏えいで入手したトークンが、IdPのMFA/条件付きアクセスを迂回して継続利用され得る
  - “失効設計（token revocation/rotation）”と“監査相関”が主戦場になる

### 状態D：SSO強制の“適用範囲”が欠けている（グループ/ポリシー/ライセンス/未管理アカウント）
- 言えること：
  - 組織内の一部ユーザだけがSSO対象外で、ローカルログインで入れる“穴”がある
- 典型的な観測：
  - 「SSOログインエラー」や「別の認証方法を試せ」の類が、実は“そのユーザがSSO強制対象外”を示すことがある（＝適用範囲のズレ）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここでは“攻撃者が狙う理由”を、ペンテストの優先度決定に使う。

### 優先度を上げる条件（すぐ検証すべき）
- 「SSO必須」と説明されているのに、email+password で通常ログインが成立する
- “SSO bypass link（email/passwordでログイン）”がOwner/Admin以外で使える
- Guest/外部ユーザがSSO対象外で、重要データへ到達できる（資産境界が壊れている）
- APIトークン/PAT/SSH等が、IdPの制約を受けず長期有効（失効・監査が弱い）

### 優先度を分ける条件（仕様として許容される可能性）
- Owner/Adminのみのバイパスで、強制2FA・監査強化・利用制限がある（ブレークグラス設計）
- 非対話トークンが“組織単位でSSO承認/紐付け”を要求し、未承認では使えない（代替認証の境界が保たれている）

### 代表的な攻め筋（検証で確かめたい仮説）
- 仮説1：ローカルログインのURLが残っていて、SSO強制リダイレクトされない
- 仮説2：SSO強制が“全員”ではなく、グループ/ポリシー適用漏れがある
- 仮説3：ゲスト/外部コラボレータがSSO対象外で、組織資産へ到達できる
- 仮説4：API/CLIの代替認証素材が“SSO境界の外”で、MFA/CAを迂回して使える

## 次に試すこと（仮説A/Bの分岐と検証）
以下は「やること」ではなく「観測→判断→次の一手」の順に固定する。
（実施は必ず許可された範囲・テストアカウントで行い、影響を最小化する）

### 検証セット0：ログイン経路の棚卸し（最短で全体像を掴む）
1) SaaSのログイン画面で、選択肢を“列挙”する
- SSOボタン以外に「メールでログイン」「パスワードでログイン」「管理者用ログイン」等がないか
- ログイン画面のフッタやヘルプに「SSOをバイパス」リンクがないか
2) URLの候補を“観測ベース”で列挙する（推測よりHAR/リンク抽出優先）
- ブラウザのネットワークログから、/login, /signin, /password, /session, /sso, /saml, /oauth 等の実アクセスを抽出
3) 組織資産URLへ直接アクセスした時の挙動を見る
- “未認証で組織資産へアクセス→IdPへ飛ぶ”が成立しているか
- どの時点で強制されるか（トップ/特定パス/管理画面のみ 等）

判断：
- 強制リダイレクトが常に働く → 検証セット1へ（例外/非対話を疑う）
- ローカルログイン画面が表示される/成立しそう → 検証セット2へ（バイパス成立の確認）

### 検証セット1：例外経路（Owner/Admin/Break-glass/Guest）の境界を確定する
目的：仕様としての例外か、境界逸脱かを切る。

- 仮説A（許容例外）：Owner/Adminだけがバイパス可能で、強制2FA・監査強化がある
- 仮説B（逸脱）：Owner/Admin以外でもバイパス可能、またはGuest/外部が重要資産へ到達できる

観測と手順（具体）：
1) ロール別アカウント（Owner/Admin/Member/Guest）で同じログイン手順を踏み、差分を取る
- “同じURL”にアクセスして、ロールで挙動が変わるか（SSO要求/ローカル許可）
2) “ゲスト/外部”のSSO要求条件を観測する
- SaaSが「ゲストはSSO対象外」を許す設計の場合、到達できる資産範囲（チャンネル/リポジトリ/スペース等）を境界として固定する
3) パスワード回復/マジックリンクの有無を観測する（ローカル認証の残存確認）
- SSO強制でも回復フローが残ることがある（=ローカル認証の温存）

判断：
- 例外がOwner/Adminに限定され、強制2FA・監査強化がある → “ブレークグラス運用”の妥当性評価へ
- 例外が広い/重要資産へ到達する → “SSO境界の破綻”として報告対象へ

### 検証セット2：ローカルログイン残存の“成立点”を確定する（実務で再現可能に）
目的：報告で揉めないよう「どの条件で成立するか」を条件式に落とす。

- 仮説A：SSO有効だが強制されていない（任意SSO）
- 仮説B：SSOは強制のはずだが、適用範囲が漏れている（ポリシー/グループ/未管理）
- 仮説C：IdP障害時のフェイルオープン（SP側がローカルへ逃がす）

観測と手順（具体）：
1) “同一ユーザ”で2種類の入口を比較する
- 入口1：組織資産URL → 302でIdPへ飛ぶか
- 入口2：ローカルログインURL → 302でIdPへ飛ぶか / ローカル認証画面が出るか
2) 302チェーンと、セッション確立点を固定する
- どのレスポンスでSet-Cookieが出たか
- IdPを経由したか（IdPドメインへの通信有無）
3) “適用範囲”を管理画面で確認し、挙動と突き合わせる
- SSO強制の対象が全員か/特定グループか
- ゲストが除外される設定か
- ドメイン検証（Managed domain）前提の仕組みがあるか（＝未管理メールは対象外になり得る）

判断：
- 入口2でローカル認証が成立し、IdPを経由しない → SSOバイパス成立（影響範囲評価へ）
- 入口2は成立しないが、ゲストだけ成立 → 資産境界（ゲスト権限）と合わせて評価へ
- 入口2は成立しないが、API/CLIが成立 → 検証セット3へ

### 検証セット3：非対話の代替認証（トークン/鍵）が“SSO境界の外”かを評価する
目的：UIは守れていても、運用上の侵入口はここに残りがち。

- 仮説A（制御あり）：トークン/鍵は“SSO承認（authorize）”や“組織紐付け”が必要で、未承認は使えない
- 仮説B（制御弱い）：トークンがあればIdPログイン無しで長期利用できる

観測観点：
1) トークン利用時の監査ログが、IdPログインと相関できるか
- IdPログが無いのにSaaS API操作が成立するなら、境界は“トークン失効/ローテーション/検知”に移る
2) トークンのスコープが“組織資産”に到達するか
- 個人領域だけなら影響が限定されることもあるが、組織資産に到達するなら優先度は上がる
3) トークンの失効/回転/再承認が管理者側で即時にできるか

判断：
- トークンがSSO承認なしで組織資産へ到達できる → “Alternate Auth Material”として強いリスク（是正はトークン設計/監査へ）
- トークンがSSO承認必須 → “SSO境界が非対話にも波及している”として評価（ただし監査/失効運用は要確認）

### 仕上げ：報告として成立させるための“結論フォーマット”（短く・再現可能に）
- 結論（例）：
  - 「SSO強制の想定に反し、◯◯条件でローカルログインが成立し、IdPを経由せずに組織資産へ到達できる」
- 成立条件（条件式）：
  - 対象ロール：Owner/Admin/Member/Guest
  - 入口URL：/login（ローカル） vs 組織資産URL（強制）
  - 適用範囲：SSO強制ポリシーの対象/対象外
- 証跡：
  - 302チェーン、IdPドメイン通信の有無、Set-Cookieの地点、監査ログの対応関係

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS
  - V2 認証：SSO強制の“例外”が仕様として管理されているか（例外ロール/回復経路/ローカル認証の無効化）
  - V3 セッション：SSO後セッションが長期化しないか、再認証境界が保たれているか（重要操作/管理操作）
  - V4 アクセス制御：ゲスト/外部ユーザの資産境界が破綻していないか（“SSO対象外＝権限弱い”が担保されているか）
  - V14 設定/運用：監査ログ相関、緊急アカウント運用、例外の棚卸し（継続運用で担保）
- WSTG
  - WSTG-ATHN：認証バイパス（別経路ログイン/回復フロー/例外ロール）
  - WSTG-SESS：セッション継続・再認証・トークンの失効/更新（SSOの外側にあるセッション）
  - WSTG-INFO：ログイン面の列挙（UI以外の入口、サブドメイン/別ポータル）
- PTES
  - Intelligence Gathering：ログイン面の列挙（UI/API/プロトコル）
  - Threat Modeling：境界（資産/信頼/権限）と例外（break-glass/guest）を脅威として整理
  - Vulnerability Analysis：SSO強制の実態検証（適用範囲/例外/フェイル挙動）
  - Exploitation：許可された範囲で成立点の再現（証跡取得）
  - Reporting：成立条件の条件式化、影響範囲（組織資産到達）と是正案（例外の縮小/監査）
- MITRE ATT&CK（代表）
  - TA0001 Initial Access：Valid Accounts（T1078）
  - TA0003 Persistence：Account Manipulation（T1098）、（SaaS側の例外設定維持が永続化に寄与し得る）
  - TA0006 Credential Access：盗んだトークン/パスワードの再利用（Use Alternate Authentication Material：T1550）
  - TA0005 Defense Evasion：IdP側制御（MFA/CA）を回避する経路として機能する場合がある
  - TA0008 Lateral Movement：SaaS内部の共有・外部連携を踏み台に横展開（組織資産の境界破り）

## 参考（必要最小限）
- Slack：SAML SSOの設定と、Owner/Org OwnerがSSOをバイパスできる旨（可用性のための設計例）
  - https://slack.com/help/articles/203772216-SAML-single-sign-on-SAML-single-sign-on
- Slack：SSO環境でOwner/Adminがemail+passwordでバイパスし得る/ゲスト例外があり得る旨（例外境界の典型）
  - https://slack.com/help/articles/212221668-Mandatory-workspace-two-factor-authentication
- GitHub：組織に対するSAML SSO強制（強制の意味と、前提としての“紐付け”）
  - https://docs.github.com/en/free-pro-team%40latest/github/setting-up-and-managing-organizations-and-teams/enforcing-saml-single-sign-on-for-your-organization
- GitHub：SSO環境でAPI/Git利用にPAT/SSHが関与し、承認（authorize）が必要になる旨（非対話の境界の例）
  - https://docs.github.com/enterprise-cloud%40latest/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on
  - https://docs.github.com/github/authenticating-to-github/authorizing-an-ssh-key-for-use-with-saml-single-sign-on
- Atlassian：Guardライセンス/認証ポリシー適用範囲により、SSOが効かない（＝別認証方法が求められる）ことがある旨（適用範囲ズレの典型）
  - https://support.atlassian.com/atlassian-cloud/kb/saml-sso-login-error-related-to-guard-licensing-or-user-entitlement-issues/
- Microsoft Entra：緊急アクセス（break-glass）アカウントを条件付きアクセスから除外する推奨（例外設計の考え方）
  - https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access
  - https://learn.microsoft.com/hi-in/azure/active-directory/conditional-access/howto-conditional-access-policy-block-access
