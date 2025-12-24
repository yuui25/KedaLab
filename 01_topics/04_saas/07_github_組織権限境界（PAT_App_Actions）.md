# GitHub 組織権限境界（PAT_App_Actions）

## ガイドライン対応
- ASVS：V2（認証）/ V3（セッション）/ V4（アクセス制御）/ V10（ログ）/ V14（構成）を、このファイルでは「GitHub上の“トークン種別・付与権限・承認/レビュー/失効・監査ログ”としてどう実装・運用されるか」に接続して扱う
- WSTG：WSTG-ATHN / WSTG-ATHZ / WSTG-SESS / WSTG-CONF を「SaaS上の認証情報（トークン）と権限境界の観測・検証」として接続（アプリそのものではなく“運用面の境界”として扱う）
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis（設定・権限差分の発見）→ Post-Exploitation（侵害後の横展開/永続化の入口）に接続
- MITRE ATT&CK：Discovery / Credential Access / Persistence / Privilege Escalation / Lateral Movement（SaaS内・開発基盤内）/ Defense Evasion を主に想定

## 目的（この技術で到達する状態）
GitHub 組織において、以下3系統の“プログラム的アクセス”が作る権限境界を、観測→解釈→意思決定（次の一手）まで落とし込める状態になる。

- PAT（classic / fine-grained）：人に紐づく長期トークン（運用で最も漏えいしやすい）
- GitHub App：インストール単位でリポジトリを絞れる（原則、最小権限の中心に据えたい）
- GitHub Actions：`GITHUB_TOKEN`（実体はGitHub Appのインストールトークン）＋ワークフロー `permissions:` で“実行時の権限”が変わる

最終的に、組織として「どのトークンを許容し、どこで承認し、どこで固定（ブランチ保護）し、どのログで追えるか」を説明できることをゴールにする。

## 前提（対象・範囲・想定）
- 対象
  - GitHub.com（GitHub Enterprise Cloud 含む）での Organization / Repository / Actions を前提
  - GitHub Enterprise Server（GHES）は“同様の概念があるが、設定UI・既定値・監査粒度が異なり得る”前提で差分確認する
- 想定する守るべき資産（Asset）
  - リポジトリのソース・ワークフロー（`.github/workflows/*`）・リリース・パッケージ
  - Secrets / Variables / Environments（デプロイ鍵・クラウド権限・署名鍵）
  - 組織設定（メンバー/チーム/権限、PATポリシー、Actionsポリシー、サードパーティ連携）
  - 監査ログ（誰が何をしたか、トークン/アプリ起因を追えるか）
- “境界”として特に見るポイント
  - 権限境界：組織ロール（Owner等）・リポジトリ権限（Admin/Write等）・トークン権限（scope/permission）・実行時権限（workflow permissions）
  - 信頼境界：外部のOAuth App / GitHub App / Actions（Marketplace含む）・Self-hosted Runner（社内/外部）・CI/CD外部連携
  - 資産境界：Org配下のどのリポジトリ/環境/パッケージまで到達できるか（“All repositories”が出た瞬間に境界が崩れる）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) トークン種別の境界（PAT / OAuth App / GitHub App / Actions）
- PAT（classic）
  - “scope” で広く付与されがち（`repo` 等）
  - 組織側での統制が弱くなりやすい（例：承認フローが効かないケースが残る）
- PAT（fine-grained）
  - 組織/リポジトリを指定して発行（到達範囲が明示的）
  - 権限は「細粒度の permissions（read / read&write / none）」として付与
  - 組織側で承認・失効・寿命制限などの統制を掛けやすい（ただし“運用して初めて効く”）
- OAuth App
  - “scope” ベース（広いスコープを要求しやすい）
  - 「ユーザとして振る舞う」前提なので、ユーザが見えるものに引っ張られる
- GitHub App
  - インストール単位でリポジトリ選択（境界を作りやすい）
  - permission が細粒度で、トークンは短命化しやすい
- GitHub Actions（`GITHUB_TOKEN`）
  - 仕組みとしては GitHub App のインストールトークン
  - “既定の権限”と、ワークフロー `permissions:` の “上書き” の2層で境界が決まる
  - 設定やPR保護が弱いと「ワークフロー編集＝実行時権限の再定義」になり、境界が崩れる

### 2) 組織ロールと「誰が承認・設定できるか」
- 組織ロール（Owner / Member / Security manager / Billing manager 等）ごとの操作可能範囲
  - “トークンを発行できる”と、“組織設定で許可/承認/ブロックできる”は別物
  - 重要なのは「承認権限を持つ主体」と「監査をレビューする主体」が誰か（責務分離）

### 3) 組織ポリシー（PATの許可・承認・寿命）
観測する設定（Organization Settings）
- PATアクセス可否（classic / fine-grained）
- fine-grained PAT の承認要否（Owner承認が既定になりやすい）
- 最大有効期限（寿命）ポリシー
- （環境によって）SAML SSO 前提時の classic PAT の扱い差分

ここでの“境界”は：
- 「ユーザがトークンを作れる」≠「組織資産に使える」
- “使える”にする最終ゲートが「組織側の承認/許可」になっているか

### 4) リポジトリ/Actions 設定（実行時権限の境界）
観測する設定（Repository Settings → Actions → General）
- Workflow permissions（`GITHUB_TOKEN` の既定権限）
  - read-only か、read-write か
  - “作成/承認PRを許す”の可否（許すとCIが自己承認できる境界崩壊になり得る）
- その上で、ワークフローYAML側の `permissions:` で最小化できているか
  - 例：`contents: read` / `issues: write` のように“用途に合わせて狭める”

ここでの“境界”は：
- Actions の権限は「設定（既定）」×「コード（workflow）」×「誰が書き換え可能か（ブランチ保護）」で決まる

### 5) API応答ヘッダによる“必要権限”の観測（差分の確定）
- OAuth token の scopes
  - `X-OAuth-Scopes` / `X-Accepted-OAuth-Scopes` を I（HEAD）で観測して「足りない/過剰」を判定する
- fine-grained PAT / GitHub App の permissions
  - REST API 応答の `X-Accepted-GitHub-Permissions` を観測して「そのエンドポイントの要求権限」を確定する

（観測の狙い）
- “この操作をしたいからこの権限が要る”を、推測ではなく **APIが要求する権限** で固定する  
- 結果として「最小権限の設計」「過剰権限の検出」「権限不足で失敗したときの分岐」を作れる

### 6) 監査ログ（Audit log）で“誰が・何の資格で・何をしたか”を追えるか
観測したいログの要素
- トークン種別（PAT / OAuth / App / Actions）を識別できるか
- `token_id` 等で“特定トークン起因の操作”を絞り込めるか
- “承認された/拒否された/失効した” という管理イベントが残るか

この観測は、侵害時の“巻き戻し（どこまで影響したか）”に直結する。

## 結果の意味（その出力が示す状態：何が言える/言えない）
### A) PAT（classic）を許可している
言えること
- “人に紐づく長期トークン” が組織資産へ到達しうる（漏えい時のブレイクが大きい）
- scope が広い運用だと「意図せず管理系APIまで届く」リスクが残る

言えないこと（不足情報）
- 実際に誰がどれだけの scope の PAT を持っているか（棚卸し/監査の仕組みが別途必要）
- SAML SSO・組織ポリシー等で制約されているか（環境差分がある）

### B) fine-grained PAT を“承認必須”にしている
言えること
- “発行できる”と“組織資産に使える”が分離される（権限境界が強くなる）
- 監査・失効・寿命制限の運用が成立しやすい（運用に落とせる）

言えないこと（不足情報）
- 承認プロセスが形骸化していないか（Ownerが全部承認していないか）
- “All repositories” 設定や過剰 permission を承認していないか（レビュー品質）

### C) GitHub App を導入し、リポジトリ選択＋最小権限にしている
言えること
- “どのリポジトリまで到達できるか” をインストール境界で固定できる
- 人の離職/権限変更で突然壊れる種類の自動化（OAuth/PAT）より堅牢になりやすい

言えないこと（不足情報）
- Appの秘密鍵/設定が漏えいしていないか（別の運用・鍵管理の論点）
- Appが受け取るWebhook等が外部公開され、別の攻撃面になっていないか

### D) Actions の `GITHUB_TOKEN` を read-only にし、workflow `permissions:` を最小化している
言えること
- CIが“書き込みで永続化/改ざん”しにくい境界になっている（特に contents への write が抑えられる）
- “ワークフロー実行＝高権限” になりにくい

言えないこと（不足情報）
- そもそも `.github/workflows/*` を誰が改変できるか（ブランチ保護/レビュー強制の有無）
- Self-hosted runner が混在していないか（実行環境が別境界）

### E) 監査ログで token_id 等が取れている
言えること
- “何が漏れたか分からない”を減らせる（追跡可能性が上がる）
- 失効判断や影響範囲の切り分けが早くなる

言えないこと（不足情報）
- 監査ログの保存期間・外部転送・SIEM相関が整っているか（運用設計）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここは「手口の手順」ではなく、侵害時に“境界がどこで崩れるか”の意思決定に限定して記述する。

### 1) 優先度：まず“長期トークン”がどこまで届くか
- classic PAT が許可され、広い scope 運用が見えるなら、侵害時の被害半径は大きい（組織横断の到達性が出やすい）
- fine-grained PAT が承認制なら、攻撃側は “承認を通す（=人の操作が必要）” か “別経路（Actions/App）” に寄る判断になる

### 2) 次の仮説：CI（Actions）を“権限ブリッジ”にできるか
- `GITHUB_TOKEN` が write を持ち、かつ workflow を改変できる（レビュー/保護が弱い）なら、
  - “CI実行”が継続的な到達点になりやすい（境界がコードに埋め込まれる）
- 逆に `GITHUB_TOKEN` がread-only で、workflowが保護されているなら、
  - CIは“観測点”にはなるが、“権限拡大点”にはなりにくい（攻め筋が変わる）

### 3) GitHub App が広範囲にインストールされているか
- App が “All repositories” で入っていると、Appの資格情報に依存する攻撃面の被害半径が拡大する
- 逆に “特定リポジトリのみ” なら、侵害の横展開は “別の統制（別App/PAT/権限昇格）” が必要になる

### 4) 監査ログで追えるか（攻撃者のリスク）
- token_id 等で追跡でき、即時失効・検知が回る組織では、
  - 攻撃側の行動は短期化しやすい（＝検知回避・最短での成果に寄る）
- 追跡できない/棚卸しできない場合は、
  - “どのトークンが漏れたか”を確定できず、回復コストが爆発する（守る側の致命点）

## 次に試すこと（仮説A/Bの分岐と検証）
ここは「組織の現状を短時間で確定し、改善の優先度を決める」ための実務手順に落とす。

### 仮説A：組織の境界が“人の長期トークン（PAT/OAuth）”に依存していて広い
狙い：被害半径を最短で下げる（最小権限化＋承認＋寿命）

1) 組織の PAT ポリシーを確認（Owner権限で）
- PAT（classic / fine-grained）の許可/禁止
- fine-grained の承認要否
- 最大有効期限（寿命）  
→ “許可”かつ“期限なし”は、まずここが境界崩壊点になりやすい

2) fine-grained PAT を棚卸し（Active tokens）
- どの Org / Repo に到達できる設定か（All repositories か、特定のみか）
- permission が “Contents write / Workflows write / Administration” 等になっていないか  
→ “到達範囲”と“書き込み権限”が同時に広いものを最優先で是正（失効/再発行）

3) OAuth App の承認状況（利用状況）を棚卸し
- scope が `repo` のように広いもの
- “誰が承認したか” と “組織ポリシー上の扱い”  
→ 可能なら GitHub App へ寄せる（リポジトリ選択＋短命トークン＋細粒度権限）

4) APIヘッダ観測で“必要権限”を固定（最小権限設計に落とす）
- OAuth：`X-OAuth-Scopes` / `X-Accepted-OAuth-Scopes`
- fine-grained：`X-Accepted-GitHub-Permissions`  
→ “この自動化に必要な最小権限セット”を文章化できる状態にする

（最小例：OAuth scope の観測イメージ）
~~~~
curl -I -H "Authorization: Bearer <token>" https://api.github.com/user
# レスポンスヘッダの X-OAuth-Scopes / X-Accepted-OAuth-Scopes を確認
~~~~

### 仮説B：境界の主戦場は Actions（CI）で、workflowが“権限スイッチ”になっている
狙い：`GITHUB_TOKEN` と workflow 改変権限を分離し、CIを“低権限実行”に固定する

1) Repository の Workflow permissions を確認
- 既定で `GITHUB_TOKEN` が read-only（contents/packages read）になっているか
- “ActionsがPRを作成/承認”が有効になっていないか  
→ 有効だと、CIが自己承認・自己改変に近づく

2) workflow YAML の `permissions:` を確認（最小権限化）
- “何も指定しない”は避ける（既定が何かは組織作成時期/設定継承で揺れる）
- job単位で必要なものだけ付与（`contents: read` 等）

（最小例：permissions を明示するイメージ）
~~~~
permissions:
  contents: read
  issues: write
~~~~

3) `.github/workflows/*` を“誰が改変できるか”を固定（ここが本当の境界）
- ブランチ保護：必須レビュー、CODEOWNERS、直push禁止、管理者例外の扱い
- “workflow変更”を特別扱いする運用（少なくとも所有者レビューが必要）  
→ CIの権限を絞っても、workflow自体が書き換えられるなら境界は崩れる

4) `GITHUB_TOKEN` で起こるイベント連鎖の抑止を理解する
- `GITHUB_TOKEN` による push が“新しい workflow 実行を連鎖させにくい”仕様がある  
→ ただし “改ざんが起きない” とは別（コードは変えられる）。抑止の意味を過信しない

### 仮説C：App中心運用に寄せたい（PAT/Secretsを減らす）
狙い：長期トークンを減らし、インストール境界＋短命トークンへ移行する

1) “PATを使っている自動化”を洗い出し、GitHub Appに置換できるか判定
- リポジトリ限定で良いものはApp向き
- ユーザとしての操作が必須なものはOAuth/PATの余地が残る（ただし最小化）

2) GitHub App のインストール範囲を絞る
- “All repositories” を避け、必要リポジトリのみ  
→ 組織全体の被害半径を縮める

3) 監査ログで “App操作” を追跡できる設計にする
- インストール変更・権限変更・トークン利用の追跡キーを決め、SIEM等へ相関する

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
### ASVS（接続の仕方）
- V2（認証）：長期資格情報（PAT/OAuth）を最小化し、承認・寿命・失効・棚卸しを運用に組み込む
- V3（セッション）：`GITHUB_TOKEN` など短命トークンの“ライフサイクル（期限/失効）”を前提にし、長期トークンをSecretsに置かない設計へ寄せる
- V4（アクセス制御）：Org/Repoロール＋トークン権限＋Actions permissions を“多層のアクセス制御”として分離し、境界を固定（特にworkflow改変者を制限）
- V10（ログ）：監査ログで token/app 起因を追える（token_id等）・失効イベントを追える・相関できる
- V14（構成）：組織ポリシー（PAT/Actions）を“標準設定”として強制し、例外を最小にする

### WSTG（接続の仕方）
- WSTG-ATHN：SaaS（GitHub）上のトークン認証を“認証情報”として取り扱い、発行・保護・失効の検証観点に落とす
- WSTG-ATHZ：組織/リポジトリのロール、トークンの権限、workflow permissions の差分が“認可”そのもの
- WSTG-SESS：短命トークン（GITHUB_TOKEN/App token）と長期トークン（PAT）の違いをセッション/資格情報管理として扱う
- WSTG-CONF：設定（Org/Repo/Actions）起因の権限境界崩壊を構成レビューとして扱う

### PTES（どのフェーズか）
- Intelligence Gathering：組織設定・リポジトリ設定・連携（PAT/App/Actions）の全体像を収集
- Threat Modeling：侵害シナリオを “長期トークン” と “CI実行権限” の2軸でモデル化
- Vulnerability Analysis：設定差分（承認なしPAT / workflow改変可能 / GITHUB_TOKEN広すぎ）を弱点として特定
- Post-Exploitation：侵害後の横展開（追加repo/チーム到達、CI経由の権限ブリッジ、永続化）を“成立条件”として評価
- Reporting：改善優先度を「被害半径（到達範囲）×書き込み権限×追跡可能性」で説明

### MITRE ATT&CK（戦術としての位置づけ）
- Discovery：Org/Repo構造、権限、Actions設定、Appインストールの把握
- Credential Access：PAT/OAuth/Secrets/Runner上の資格情報への到達可能性評価
- Persistence：Appインストール、workflow改変、長期トークンの残存による継続到達
- Privilege Escalation：Owner権限や管理系API（admin相当）への到達条件
- Lateral Movement：組織内の他リポジトリ・他チームへの到達（All repositories / 広権限トークン）
- Defense Evasion：監査ログを回避しやすい運用（棚卸しなし、token_id相関なし）を成立条件として評価

## 参考（必要最小限）
- GitHub Docs: Setting a personal access token policy for your organization  
  https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization
- GitHub Docs: Reviewing and revoking personal access tokens in your organization  
  https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization
- GitHub Docs: GITHUB_TOKEN（概念と制約）  
  https://docs.github.com/actions/concepts/security/github_token
- GitHub Docs: Use GITHUB_TOKEN for authentication in workflows（permissions最小化）  
  https://docs.github.com/actions/security-guides/automatic-token-authentication
- GitHub Docs: Managing GitHub Actions settings for a repository（Workflow permissions）  
  https://docs.github.com/ja/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
- GitHub Docs: Scopes for OAuth apps（scopeの広さと観測ヘッダ）  
  https://docs.github.com/en/developers/apps/scopes-for-oauth-apps
- GitHub Docs: Authorizing OAuth apps（scopeの意味と“ユーザ権限以上は出ない”）  
  https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/authorizing-oauth-apps
- GitHub Docs: Permissions required for fine-grained personal access tokens（X-Accepted-GitHub-Permissions）  
  https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens
- GitHub Blog（Changelog）: Fine-grained PATs are now generally available（token_id等の監査性）  
  https://github.blog/changelog/2025-03-18-fine-grained-pats-are-now-generally-available/
- GitHub Blog: Introducing fine-grained personal access tokens（設計意図）  
  https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/
- GitHub Docs: Roles in an organization（ロール差分）  
  https://docs.github.com/ja/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization
