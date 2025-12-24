# 00_index.md

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：認証（AuthN）・認可（AuthZ）・API・入力境界・設定/運用を「境界（資産/信頼/権限）」として整理し、管理策が“どこで満たされ/破られるか”に落とす
- WSTG：Information Gathering を入口に、Auth/Authorization/API/Client-side/Config 等へ観測点と検証分岐を供給する
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis → Exploitation に繋がる“検証設計”を、Web領域の共通言語で固定する
- MITRE ATT&CK：Discovery/Collection/Credential Access/Privilege Escalation 等を「Webで起きる境界崩壊」として説明補助に使う（戦術名の貼り付けはしない）

## 目的（このフォルダで到達する状態）
- Webペネトレで必要な技術を、ツール操作ではなく「意味→判断→次の一手」で回せる状態にする。
- Webの攻撃面を、次の5つの“境界”で説明できるようにする。
  1) 入口（Web Recon）：どこから入るか／どこまでが対象か（資産境界）
  2) 認証（AuthN）：本人性がどこで成立するか（信頼境界・材料）
  3) 認可（AuthZ）：誰が何をできるか（権限境界・伝播）
  4) API：権限がどこで決まるか／バックエンド連携（権限伝播・信頼境界）
  5) 入力/設定：どこで解釈・実行されるか／運用で崩れるか（実行境界・運用境界）

## 前提（対象・範囲・想定）
- 対象は許可されたスコープに限定する。
- ここで作るファイルは「総合インデックス（入口）」を維持し、深掘りは論点別の分割ファイルで拡張する（肥大化防止）。  
  ※この方針は認証だけでなくWeb領域全体に適用する。

## 観測ポイント（Web領域の共通言語：何を見ているか）
- 資産境界：サブドメイン/アプリ/機能の切れ目、外部依存（CDN/IdP/SaaS等）
- 信頼境界：第三者連携、SSO/委任、ブラウザ↔サーバ↔別サービスの越境点
- 権限境界：主体（ユーザー/ロール/テナント/所有）と操作（read/write/admin）の切れ目
- 実行境界：入力がどこで解釈され、どこで実行・参照されるか（テンプレ/パーサ/デシリアライズ等）
- 運用境界：設定・ヘッダ・CORS・Secrets・ログ/監査など、実装以外で崩れる地点

## 次に試すこと（推奨の読み順：迷わない導線）
1) `01_web_recon_入口・境界・攻め筋の確定.md`  
   - 入口と境界が曖昧なままAuth/APIに進むと、検証が外れるため最優先
2) `02_authn_認証・セッション・トークン.md`  
   - 本人性の成立点（材料と拒否点）を固める
3) `03_authz_認可（IDOR/BOLA/BFLA）境界モデル化.md`  
   - “境界変数（owner/tenant/role/scope）”を確定し、差分観測へ
4) `04_api_権限伝播・入力・バックエンド連携.md`  
   - UI制限とAPI実態のズレ、サービス間の判定ズレを扱う
5) `05_input_入力→実行境界（テンプレ/デシリアライズ等）.md`  
   - 入力がどこで解釈・実行されるかを観測で固める
6) `06_config_設定・運用境界（CORS/ヘッダ/Secrets）.md`  
   - “実装は正しいが運用で崩れる”を潰す

## Playbooks / Labs との連動（手を動かす前提）
- Web側の導線（検証の回し方）
  - `02_playbooks/02_web_recon_入口→境界→検証方針.md`
  - `02_playbooks/03_authn_観測ポイント（SSO/MFA前提）.md`
  - `02_playbooks/04_authz_境界モデル→検証観点チェック.md`
  - `02_playbooks/05_api_権限伝播→検証観点チェック.md`
- 観測の基盤（証跡を揃える）
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## このフォルダのファイル一覧（入口）
- 01: `01_web_recon_入口・境界・攻め筋の確定.md`
- 02: `02_authn_認証・セッション・トークン.md`
- 03: `03_authz_認可（IDOR/BOLA/BFLA）境界モデル化.md`
- 04: `04_api_権限伝播・入力・バックエンド連携.md`
- 05: `05_input_入力→実行境界（テンプレ/デシリアライズ等）.md`
- 06: `06_config_設定・運用境界（CORS/ヘッダ/Secrets）.md`

## 深掘りリンク（必要時に追加するファイル：最大8件）
- （例）`02_authn_01_cookie属性と境界（Domain Path SameSite Secure HttpOnly）.md`
- （例）`02_authn_02_token設計（Bearer JWT refresh rotation）.md`
- （例）`03_authz_01_tenant境界（組織切替と参照漏洩）.md`
- （例）`04_api_01_bola差分観測（主体 所有 テナント）.md`
- （例）`05_input_01_template境界（サーバ側レンダリングと注入面）.md`
- （例）`06_config_01_cors境界（許可元 資格情報 プリフライト）.md`
- （例）`06_config_02_secrets露出（クライアント配布 設定 CIログ）.md`
- （例）`01_web_recon_01_waf前段の拒否点（到達性と観測）.md`
