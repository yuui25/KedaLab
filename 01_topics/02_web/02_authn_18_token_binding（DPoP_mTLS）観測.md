## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：アクセストークンの盗用耐性（Token Binding / sender-constrained tokens）、クライアント認証（mTLS / private_key_jwt 等）、トークン利用時の検証（RS側の強制）、例外パス（特定APIのみ未強制）、鍵管理/ローテーション
  - 支える前提：17で rotation / reuse検知 を入れても、「盗まれたアクセストークンがそのまま使える」設計だと被害は残る。token binding は“盗用しても使えない”方向の制御。
- WSTG：
  - 該当テスト観点：Authentication Testing / Session Management（Token-based auth、OAuth/OIDC設計、Client authentication）
  - どの観測に対応するか：token endpoint の応答、Authorizationヘッダ、DPoPヘッダ、mTLSハンドシェイク/証明書、Resource Server（API）側の検証強制を観測して成立条件を切る
- PTES：
  - 該当フェーズ：Vulnerability Analysis（トークン盗用の現実性評価、制御の一貫性）、Post-Exploitation（盗用後の持続性抑止）
  - 前後フェーズとの繋がり（1行）：17（refresh rotation/reuse）で長期盗用を抑え、18（token binding）で“アクセストークン盗用”の即時悪用を抑える。16（step-up）と併用して重要操作の耐性を底上げする。
- MITRE ATT&CK：
  - 戦術：Credential Access / Defense Evasion / Persistence
  - 目的：Bearer token の奪取・再利用（Token theft）を成立させる／逆に防御側は sender-constrained にして再利用を封じる（※ここでは手順ではなく成立条件の判断）

## タイトル
token_binding（DPoP_mTLS）観測

## 目的（この技術で到達する状態）
- “Bearerトークン（盗まれたら使える）” と “sender-constrainedトークン（持ち主以外では使えない）” の違いを、DPoP/mTLS という実装形態で具体的に評価できる
- DPoP と mTLS を「見た目のヘッダ/設定」ではなく、(1) token発行時の拘束、(2) API利用時の強制、(3) 例外パスの有無、まで含めて観測・判断できる
- エンジニアが実装/設定でやるべきことを「どのコンポーネント（AS/RS/Client）で何を強制するか」まで落とし込める
- 17（rotation/reuse検知）と組み合わせた“盗用耐性の完成形”に向け、次の設計判断（18→17/16/15/14への戻り）を決められる

## 前提（対象・範囲・想定）
- 対象：
  - Authorization Server（AS）：token endpoint（/oauth/token 等）、発行する access token の種別（DPoP-bound / mTLS-bound / bearer）
  - Resource Server（RS）：API群（/api/*）での token 利用検証（DPoPヘッダ検証、mTLS必須化、cnf確認 等）
  - Client：SPA / モバイル / サーバ（confidential client）で鍵を保持できるか
- 想定する境界：
  - “トークン発行（AS）” と “トークン利用（RS）” が分離（最も破綻しやすい：ASは拘束してるつもり、RSが強制していない）
  - 複数API（microservices）で一部だけ強制＝例外パスになりやすい
- 安全な範囲（最小検証の基本方針）：
  - 実際に盗用（他者・第三者）するのではなく、テストアカウントと観測で「拘束が効いている設計か」を切り分ける
  - mTLSは環境依存が強いので、証跡（クライアント証明書要求/ハンドシェイク、設定断片、エラー挙動）を重視する
  - DPoPはヘッダ/クレームの“整合性”と、RS側の検証強制有無を重視する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) token binding の目的を固定する（何を防ぎたいか）
- 防ぎたい事象（ペネトレでの実務的な“盗用”）
  - Bearer access token の再利用（ログ/ブラウザ/プロキシ/端末から漏れたトークンを別環境で使う）
  - refresh rotation があっても、短命アクセストークンの“即時悪用”が成立する
- token binding の狙い
  - access token を「特定の鍵/証明書の所持」に結びつけ、盗まれても“鍵がないと使えない”状態にする

### 2) まず分類する：Bearer / DPoP / mTLS のどれか（混在もある）
- Bearer：
  - Authorization: Bearer <token> だけで成立（拘束なし）
- DPoP（公開鍵ベース）：
  - DPoPヘッダ（署名JWT）を要求し、トークンが特定公開鍵（jwk）に拘束される（DPoP-bound access token）
- mTLS（証明書ベース）：
  - TLSクライアント証明書の提示（mutual TLS）が必要で、トークンが証明書（thumbprint等）に拘束される（mTLS-bound access token）

観測の最初は「どれが要求されているか」を、AS（発行）とRS（利用）の両方で確認する。

### 3) AS側（token endpoint）での観測：拘束“しているつもり”を確定する
- DPoPの場合：token endpoint が DPoP を受け付け/要求する兆候
  - リクエストに DPoP ヘッダが存在する（または無いとエラー）
  - レスポンスの token_type が DPoP になる/DPoP関連のエラーになる等の兆候
  - access token に “cnf” 相当の拘束情報が入る（形式による：JWTならクレーム観測、opaqueなら不可＝ログ/設定断片で裏取り）
- mTLSの場合：token endpoint が mTLS client auth を要求する兆候
  - TLSハンドシェイクでクライアント証明書を要求（要求しないなら mTLS ではない）
  - 証明書なしで token endpoint が通らない/特定エラーになる
  - AS側設定（client auth method）が mTLS と一致（設定断片が取れるなら証跡化）

重要：AS側だけ拘束しても、RS側が強制しないと“使える”ことがある（特にRSがBearerとして扱う実装）。

### 4) RS側（API側）での観測：強制されているか（ここが本丸）
- DPoP強制の観測焦点
  - Authorization: Bearer だけでは通らない（DPoPヘッダ必須の兆候）
  - DPoPヘッダがある場合のみ通る、または DPoP形式不正で明確に失敗する（検証している兆候）
  - htu（URL）/ htm（HTTP method）/ iat / jti（再利用防止）等の検証がある兆候
- mTLS強制の観測焦点
  - APIへのTLS接続でクライアント証明書が要求される（証明書なしで接続/HTTP到達できない、または401/403になる）
  - “同一トークンでも、証明書が無いと通らない” を観測できる（テスト環境前提）
- 例外パス検出（最重要）
  - API A は DPoP/mTLS 必須だが、API B は Bearer で通る（機能差・ゲート差）
  - GraphQL / バッチ / 管理API だけ例外（よくある）
  - CDN/WAFの前段は見えているが、内部APIは未強制（境界分裂）

### 5) DPoP の “成立条件” を構造で押さえる（何を照合するべきか）
- DPoPヘッダ（署名JWT）の主要構成（観測で意味がある部分）
  - jwk：公開鍵（この鍵に拘束される）
  - htm：HTTPメソッド（GET/POST等）
  - htu：URL（正規化される点が罠：スキーム/ホスト/パスの扱い）
  - iat：発行時刻（古すぎる/未来すぎるの拒否）
  - jti：一意ID（再利用検知の鍵）
  - （環境により）ath：アクセストークンハッシュ（トークンとDPoPの結びつき）
- RS側の検証が弱いと起きること（判断材料）
  - DPoPヘッダは存在するが、htm/htu/jtiを厳密に見ていない（＝再利用や取り違えに弱い）
  - あるいは “DPoPヘッダがあれば通る” 程度（名ばかり）

※ここでは改ざん手順を扱わず、「何を検証すべきで、検証している兆候は何か」を観測で固める。

### 6) mTLS の “成立条件” を構造で押さえる（何を拘束しているか）
- mTLSで拘束する対象
  - クライアント証明書（証明書の公開鍵/拇印）とトークンを結びつける
- 観測で確定したい点
  - token endpoint と resource server の両方で mTLS が要求されるか（片方だけは破綻しやすい）
  - 証明書ローテーション/失効（CRL/OCSP等）は運用論点（深掘りは labs/cases に回す）
- 破綻パターン（例外パス）
  - token endpoint だけ mTLS、APIはBearer（拘束が活きない）
  - 逆にAPIだけ mTLS、tokenはBearer（設計意図が不明瞭になりやすい）

### 7) DPoP/mTLS と 17（rotation/reuse）との接続：守る場所が違う
- 17（rotation/reuse）：
  - “refresh盗用” を主に抑止・検知する（長期持続性の対策）
- 18（token binding）：
  - “access token盗用” の即時悪用を抑止する（Bearerの弱点を潰す）
- 実務判断（どちらを優先するか）
  - SPAでrefreshを持つなら 17 の優先度が上がる（持続性が大きい）
  - APIが高権限で、アクセストークンが広く露出するなら 18 の優先度が上がる（即時悪用の抑止）

### 8) binding_key_posture（後工程に渡す正規化キー）
- 推奨キー：binding_key_posture
  - binding_key_posture = <mode>(bearer|dpop|mtls|mixed|unknown) + <as_enforced>(yes/no/unknown) + <rs_enforced>(yes/no/partial/unknown) + <coverage>(all_api|partial_api|unknown) + <replay_protection>(jti_yes|jti_no|unknown) + <client_fit>(spa|mobile|server|mixed|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - token_endpoint / api_endpoints（代表3〜5）
  - mode（DPoP/mTLS/bearer）
  - as_required（token発行時に必須か）
  - rs_required（API利用時に必須か）
  - coverage（どのAPIで必須か）
  - evidence（HAR、TLSハンドシェイク情報、エラー挙動、設定断片、監査ログ）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - bearer / DPoP / mTLS のどれで、ASとRSの両方が強制しているか（片側だけか）
  - 強制範囲（全APIか一部か）と例外パス（抜け道）の有無
  - DPoPの最低限の検証（DPoP必須、形式不正で失敗する等）の兆候
  - mTLSの実施有無（証明書要求があるか）の証跡
- 推定（根拠付きで言える）：
  - RS側強制が無い/部分的な場合、盗用耐性は“局所的”で、Bearer相当の入口が残る可能性が高い
  - クライアント種別（SPA/モバイル/サーバ）と鍵保護の現実性が合っていないと、運用回避（例外パス）を生みやすい
- 言えない（この段階では断定しない）：
  - 実際の盗用経路（XSS/ログ漏洩/端末侵害）。ここでは“盗用されても使えるか”の設計耐性に絞る

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 重要APIが Bearer のまま（拘束なし）で、トークン盗用時に即時悪用が成立し得る
    - “DPoP/mTLSを採用している” と言いつつ、RS側で強制されていない/一部APIが例外（抜け道）
  - P1：
    - DPoP/mTLSは強制だが、カバレッジが部分的（特定APIだけ）で、権限の高い例外パスが残る
    - DPoPは必須だが、再利用防止（jti等）の扱いが弱い兆候（設計として盗用耐性が低下）
  - P2：
    - 設計は堅牢だが、監査/運用（鍵ローテ、証明書失効、障害時のフォールバック）が不明瞭
- “成立条件”としての整理（技術者が直すべき対象）
  - RS側で “必須チェック” を強制し、例外パスを消す（ASだけでは不十分）
  - DPoPなら htm/htu/jti/iat（最低限）を検証し、リプレイ耐性を担保する
  - mTLSなら token endpoint と API の両方で要求し、拘束の整合を取る
  - 17（rotation/reuse）と併用し、長期・短期の盗用耐性を両方閉じる

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：Bearerのまま（拘束なし）
  - 次の検証（低アクティブ）：
    - token発行とAPI利用の代表フローをHARで取り、DPoP/mTLSに相当する要素（DPoPヘッダ、mTLS要求）が一切無いことを確定
    - 重要API（権限が高い/データが重い）を優先して同様に確認し、例外パスではなく“全体方針”かを切る
  - 判断：
    - Bearer全体：18は未実装。17/16/15の強化（遮断・再認証・検知）優先を提案
- 仮説B：DPoPを使っているが、AS/RSのどちらかが強制していない（名ばかり）
  - 次の検証：
    - token endpoint：DPoPヘッダが必須か（欠落時のエラー挙動）
    - API：DPoPヘッダが必須か（欠落/不整合で失敗する兆候）
    - API群のカバレッジ比較（代表3〜5本で十分に差が見えることが多い）
  - 判断：
    - RSで未強制/部分：P0〜P1（例外パス修正が最優先）
- 仮説C：mTLSを使っているが、token endpoint/APIで整合が取れていない
  - 次の検証：
    - TLSハンドシェイクでの証明書要求がどこにあるか（token endpointのみ/APIのみ/両方）
    - 証明書が無い場合の挙動（接続レベルで落ちるか、HTTPで拒否するか）
  - 判断：
    - 片側のみ：P1（設計意図と実効性の乖離。責任分界を含め修正提案）
- 仮説D：DPoP/mTLSは強制だが、例外パス（特定API/特定クライアント）が存在する
  - 次の検証：
    - web/mobile/api client_id 別に代表APIの必須条件を比較（差が出るなら例外パス）
  - 判断：
    - 例外あり：P1（権限の高い例外ならP0寄り）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/02_authn/18_token_binding_dpop_mtls/`
    - 構成案：
      - AS：token endpoint（bearer/DPoP/mTLS を切替可能）
      - RS：API（DPoP検証ON/OFF、mTLS必須ON/OFF、例外APIを意図的に作る）
      - クライアント：SPA擬似（DPoP鍵保持）、サーバ擬似（mTLS証明書保持）
      - 監査ログ：token_issued(mode)、api_access(mode)、dpop_invalid、mtls_missing、binding_mismatch を必ず出す
- 取得する証跡（深く探れる前提：HTTP＋周辺ログ）
  - HTTP：HAR（token発行、API呼び出し、DPoPヘッダの有無）
  - TLS：クライアント証明書要求の有無（接続情報/エラー）、API到達可否
  - アプリ/ゲートウェイログ：DPoP検証失敗理由、mTLS必須違反、例外パスの判定ログ
  - 設定断片：DPoP必須/任意、mTLS client auth method、APIごとのポリシー
- 観測の設計（例外パス検出）
  - “代表API 3〜5本” を権限の高い順に選び、必須条件（DPoP/mTLS）が一貫しているかを比較する
  - 17/15と併用し、全端末logoutやrefresh失効後に “APIがまだ通る” ような残存がないかを確認（境界整合）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：DPoP付きのAPI呼び出し（擬似）
GET /api/resource
Authorization: Bearer ACCESS_TOKEN
DPoP: <signed_jwt_with_jwk_htm_htu_iat_jti>

# 例：mTLSが必要な場合の観測（擬似）
- TLSハンドシェイクで client certificate を要求される
- 証明書なし：接続失敗または 401/403（実装による）
- 証明書あり：Authorization等の条件を満たすと成功

# 観測すること（擬似）
- token endpoint と API の両方で DPoP/mTLS が “必須” になっているか
- APIごとに例外パスがないか
~~~~
- この例で観測していること：
  - sender-constrained が実効性を持っているか（AS/RS整合、必須強制、例外パス無し）
- 出力のどこを見るか（注目点）：
  - DPoPヘッダ必須の有無、エラー時の挙動、TLS証明書要求、APIごとのポリシー差分
- この例が使えないケース（前提が崩れるケース）：
  - opaqueトークンでcnf等が観測できない（→RS側強制と監査ログ/設定断片を証跡にする）

## 参考（必要最小限）
- OWASP ASVS（トークン管理、クライアント認証、盗用耐性）
- OWASP WSTG（OAuth/OIDC、Token-based auth、Client authentication）
- OAuth 2.0 / OIDC における sender-constrained tokens（DPoP / mTLS）の設計意図（“ASとRSの整合”が本質）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/02_authn_17_refresh_token_rotation_盗用検知（reuse）.md`
- `01_topics/02_web/02_authn_15_session_concurrency（多端末_同時ログイン制御）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
