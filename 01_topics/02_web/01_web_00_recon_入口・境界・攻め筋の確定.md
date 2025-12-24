# 01_web_00_recon_入口・境界・攻め筋の確定
Webアプリの「入口・境界・攻め筋」を、ツール操作ではなく **観測→解釈→優先度付け** で確定する

---

## 目的（この技術で到達する状態）
- Webアプリの「入口・境界・攻め筋」を、ツール操作ではなく **観測→解釈→優先度付け** で確定できる。
- ASM/OSINT（DNS/TLS/HTTP）で得た外形情報を、Webペネトレで使える形（認証/認可/API/入力/設定の検証計画）に落とし込める。
- “何となく触る”をやめ、**どこを深掘りすべきか** を自分で説明できる（再現条件・境界モデル付き）。

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/ドメイン/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - SSO/MFA、CDN/WAF、SPA+API、マイクロサービス、SaaS連携（IdP/ログ基盤/通知/決済等）が一般的。
- できること/やらないこと（安全に検証する範囲）：
  - やらないこと：大量アクセスや無差別列挙を前提にしない（最小観測で意思決定する）。
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 入口一覧（分類付き）：公開（未ログインで到達） / 認証入口（SSO/ログイン） / 管理入口 / API入口 / ファイル配信 / Webhook等
    - 境界モデル（最低限）：認証境界、認可境界、信頼境界の観測とモデル化
    - 攻め筋候補（優先度付き）：認証/セッション、認可（IDOR/BOLA/BFLA）、API入力、設定/外部連携、キャッシュ/ヘッダ条件差 など
    - 観測の最小証跡：HAR + Proxyログ + 検証メモ（視点/条件/差分）
  - 扱わない（別ユニットへ接続）：
    - 認証の詳細検証 → `01_topics/02_web/02_authn_認証・セッション・トークン.md`
    - 認可の詳細検証 → `01_topics/02_web/03_authz_認可（IDOR/BOLA/BFLA）境界モデル化.md`
    - APIの詳細検証 → `01_topics/02_web/04_api_権限伝播・入力・バックエンド連携.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 入口（Entry）の観測
- 画面入口：ルーティング（SPA含む）、初期ロード、ログイン誘導、エラー画面
- API入口：ホスト分離（api. 等）、パス規則（/api/v1 等）、Content-Type、エラーの型
- 付随入口：ファイル配信、画像/JS、WebSocket、Webhook受信、外部リダイレクト

### 2) 認証境界（AuthN）の観測
- どこでログインが成立するか（IdP/アプリ、Cookie/トークンの発行点）
- SSOの流れ（リダイレクト先ドメイン、state/nonce等の存在、セッション開始点）
- セッション属性（Secure/HttpOnly/SameSite、ドメイン/パス、更新/失効）

### 3) 認可境界（AuthZ）の観測（この段階では“モデル化”が主）
- テナント境界：URL/ヘッダ/トークン/サブドメインのどれで切り替わるか
- ロール境界：UI表示差だけでなく、API応答差（401/403/200）で境界を観測
- オブジェクト境界：ID（uuid/連番）がどこで渡り、どこで判定されるか（推定）

### 4) 外部依存と終端（CDN/WAF/SaaS等）の観測
- DNS/TLS/HTTPから見える終端の可能性（断定せず突合）
- 依存の越境点（別ドメイン、別Cookieスコープ、別認証主体、別ログ基盤等）

### 5) 条件差（“同じURLでも結果が変わる条件”）の観測
- 未ログイン/ログイン、ロール差、テナント差
- User-Agent/Accept/Origin/Referer差
- キャッシュ差（ETag/Vary/Age等）
- ネットワーク視点差（必要時：別経路で差分が出るか）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 入口の分類（公開/認証/管理/API等）と、入口の経路（どのドメイン/パスで成立するか）
  - 認証の"開始点/成立点"の候補（どこでCookie/トークンが発行されるか）
  - APIの存在と分離形態（同一ドメイン/別ドメイン、CORSの有無など）
  - 入口一覧（分類付き）：公開（未ログインで到達） / 認証入口（SSO/ログイン） / 管理入口 / API入口 / ファイル配信 / Webhook等
  - 境界モデル（最低限）：認証境界（どこで本人性が決まるか）、認可境界（どこで権限が判定されるか：テナント/ロール/オブジェクト）、信頼境界（CDN/WAF/IdP/SaaS/外部APIなどの越境点）
  - 攻め筋候補（優先度付き）：認証/セッション、認可（IDOR/BOLA/BFLA）、API入力、設定/外部連携、キャッシュ/ヘッダ条件差 など
- 何が"推定"できるか（推定の根拠/前提）：
  - 認可境界の実装位置（フロント/ゲートウェイ/サービス内）と境界の種類（テナント/ロール/オブジェクト）
  - 外部依存の比率と越境点の多さ（運用複雑性の指標）
- 何は"言えない"か（不足情報・観測限界）：
  - "脆弱"の断定（特に認可は、検証が必要）
  - オリジンの断定（CDN/WAF配下ではHTTP観測だけで決めない）
  - 未ログイン観測だけでの結論（認証後観測が必要な領域が多い）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：SSO中心で認証境界が外部（IdP）にある → 認証フローの成立条件を観測し、Cookie/トークン発行点を特定する
  - パターンB：SPA+APIで認可境界がAPI側にありそう → 代表機能のAPIを選び、未ログイン/ログイン/ロール差で応答差を観測する
  - パターンC：CDN/WAF配下で観測が視点依存（同じ操作でも結果が変わる） → DNS/TLS/HTTPの突合で終端境界を整理し、観測点を固定する

## 攻撃者視点での利用（意思決定：優先度・攻め筋）
- 入口の分類から、最初の深掘り順を決める
  - 例：認証入口→セッション成立→主要機能のAPI→オブジェクト境界→設定/外部連携
- 境界モデルから、検証が“効く”仮説を作る
  - テナント境界がURL/ヘッダ/トークンのどれで決まるか
  - ロール境界がUIだけか、APIで強制されているか
  - オブジェクトIDがどこで渡り、どこで参照されているか
- 条件差観測で、検証の変数を最小化する（環境差で迷子にならない）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：入口がSSO中心で、認証境界が外部（IdP）にある
  - 次の検証：
    - 認証フローの成立条件を観測（リダイレクト、Cookie/トークン発行点、SameSite等）
    - 認証後に見えるAPI呼び出しをProxyでトレースし、境界モデルを更新する
  - 期待する観測：
    - “どこで本人性が決まるか”が説明でき、次の `authn` / `authz` 検証に繋がる
- 仮説B：SPA+APIで、認可境界がAPI側にありそう
  - 次の検証：
    - 代表機能のAPIを1つ選び、未ログイン/ログイン/ロール差で応答差を観測する
    - オブジェクトIDの受け渡し箇所（URL/Body/GraphQL等）を特定する
  - 期待する観測：
    - “どの境界で守られているか”の仮説が立ち、IDOR/BOLA検証が最短距離になる
- 仮説C：CDN/WAF配下で、観測が視点依存（同じ操作でも結果が変わる）
  - 次の検証：
    - DNS/TLS/HTTPの突合で終端境界を整理し、観測点（Proxy/HAR）を固定する
    - 条件差（UA/ヘッダ/Cookie）を最小セットで試し、差分が出る条件を特定する
  - 期待する観測：
    - “どの条件で変わるか”が説明でき、無駄な試行錯誤が減る

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - HAR + Proxyログ + 検証メモ（視点/条件/差分）
  - 入口1つ（例：トップ/ログイン）について HAR + Proxyログ + メモ を取得
  - 条件差1セット（未ログイン→ログイン後）で同じ操作を再取得
- 観測の取り方（どの視点で差分を見るか）：
  - メモに「視点（端末/経路/条件）」を必ず残す
  - 条件差（UA/ヘッダ/Cookie）を最小セットで試し、差分が出る条件を特定する
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/web_recon 2>/dev/null
    cd ~/keda_evidence/web_recon
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - 最小観測で意思決定する（大量アクセスや無差別列挙を前提にしない）
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、Destination、Volume、Identifier 等
    - 入口の種類（公開/認証/管理/API）、認証状態（未ログイン/ログイン/ロール差）、条件（UA/ヘッダ/Cookie）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：入口の外形（ステータス/リダイレクト）を最小観測
curl -i https://example.com/
curl -i -L https://example.com/login

# 例：API入口の兆候（CORS/Content-Type）を最小観測
curl -i https://api.example.com/
curl -i -H "Origin: https://example.com" https://api.example.com/endpoint
~~~~

- この例で観測していること：
  - 入口の種類（公開/認証誘導/API）と、境界の手掛かり（リダイレクト/CORS）
- 出力のどこを見るか（注目点）：
  - ステータス/Location：認証境界の入口
  - Content-Type：APIらしさ（JSON等）
  - Access-Control-*：ブラウザ利用前提のAPI境界
- この例が使えないケース（前提が崩れるケース）：
  - JS必須でcurlだけでは入口が再現できない（その場合はブラウザ+HAR/Proxyへ切替）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：入口と境界（認証/セッション、認可、API、設定/外部依存）を整理し、以後の検証を"当てる"ための前提づくり。
  - 該当要件（可能ならID）：情報収集と境界特定の段階
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：入口と境界（認証/セッション、認可、API、設定/外部依存）を整理し、以後の検証を"当てる"ための前提づくり。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Information Gathering をWebペネトレ実務に変換する段（入口確定→認証→認可→APIへ繋ぐ）。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：入口確定→認証→認可→APIへ繋ぐための前提情報の整理
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering の成果を、Vulnerability Analysis の優先度付けに直結させる（攻め筋の合理化）。
  - 前後フェーズとの繋がり（1行）：Intelligence Gathering の成果を、Vulnerability Analysis の優先度付けに直結させる（攻め筋の合理化）。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance / Discovery
  - 攻撃者の目的（この技術が支える意図）：Reconnaissance / Discovery の観点を、検証側の意思決定（入口・境界・依存の把握）に落とす。
  - 参照：https://attack.mitre.org/tactics/TA0043/（Reconnaissance）、https://attack.mitre.org/tactics/TA0007/（Discovery）

## 参考（必要最小限）
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 関連 topics：`01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_認証・セッション・トークン.md`
- `01_topics/02_web/03_authz_認可（IDOR/BOLA/BFLA）境界モデル化.md`
- `01_topics/02_web/04_api_権限伝播・入力・バックエンド連携.md`
- `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
- `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---
