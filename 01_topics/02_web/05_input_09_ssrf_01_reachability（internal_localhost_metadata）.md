## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 位置づけ：SSRFは「入力された参照先（URL等）が、サーバ側のネットワーク到達性・信頼関係に接続される」典型の Input→Execution 境界。到達性（internal/localhost/link-local/metadata）を境界としてモデル化し、allowlist・分離・egress制御・検知で封じる。:contentReference[oaicite:0]{index=0}
- WSTG
  - テスト目的：SSRF注入点の特定、悪用可否、影響（特に“バックエンドへの信頼関係”）の評価。内部到達性（非公開アドレス/限定ホスト）とクラウドメタデータ到達が重要論点。:contentReference[oaicite:1]{index=1}
- PTES
  - 位置づけ：Vulnerability Analysis（注入点と到達性の分類）→ Exploitation（成立根拠の証拠化）→ Reporting（入口の削除と多層防御）。本ファイルは“到達性の現実”を観測→解釈→次の一手に落とす。:contentReference[oaicite:2]{index=2}
- MITRE ATT&CK
  - 初期侵入の入口：T1190（公開アプリの脆弱性悪用）:contentReference[oaicite:3]{index=3}
  - 到達性の利用（内部探索）：T1046（Network Service Discovery）:contentReference[oaicite:4]{index=4}
  - クラウドでの重大化：T1552.005（Cloud Instance Metadata API）:contentReference[oaicite:5]{index=5}
  - 以降の行動：T1526（Cloud Service Discovery）などへ接続しうる:contentReference[oaicite:6]{index=6}

---

## タイトル
SSRF到達性（internal / localhost / metadata）境界モデル：サーバの“見えている世界”を借りる

---

## 目的（このファイルで到達する状態）
- SSRFを「URLにアクセスされる」一般論で終わらせず、**到達性（Reachability）**を中心に、
  - どこに到達できると何が起きるか（影響）
  - 到達できたことをどう“証拠化”するか（成立根拠）
  - 入口を閉じる／残余リスクを多層で削る設計（防御）
  を、実務の判断単位に落とす。:contentReference[oaicite:7]{index=7}
- 内部/localhost/メタデータ（169.254.169.254 等）を「到達性の類型」として整理し、次ファイル（URLトリック、プロトコル、SaaS機能）へ地続きで接続する。:contentReference[oaicite:8]{index=8}

---

## SSRFの定義を“到達性”に寄せて言い換える
- SSRFは、攻撃者が与えた参照先により、**サーバが本来ユーザから到達できない内部資源へアクセスしてしまう**問題。WSTGが強調する通り、重要なのは「バックエンドとの信頼関係（非公開IP/限定到達）」が借用される点。:contentReference[oaicite:9]{index=9}
- したがって評価単位は「この注入点は、どの到達性クラスへ到達できるか（internal/localhost/link-local/metadata）」である。:contentReference[oaicite:10]{index=10}

---

## 境界モデル：SSRFを成立させる“到達性パイプライン”
SSRFの到達性は、1つのURL文字列ではなく、下記の境界の合成で決まる。

### 1) 入力→URL解釈（パーサ）境界
- URLの解釈（scheme/host/port/path/userinfo等）が、言語・ライブラリ・設定で揺れる
- “入力検証”は、文字列の正規表現より **正規化後の構造（parsed URL）** を基準にしないと破綻しやすい（詳細は次ファイルで深掘り）

### 2) URL→名前解決（DNS）境界
- host名→IPへの解決が「どのDNS（内部/外部/固定）」で行われるか
- split-horizon（内部DNSだけで解決される内部名）を引けると、外部からは存在を知らない内部資産へ到達しうる

### 3) DNS→接続（ルーティング/プロキシ/egress）境界
- どのNIC/サブネットから出るか、プロキシ強制か、FW/SG/NACLで何が許可されているか
- “localhost”はネットワークではなくOSのループバックに入るため、egress制御と別枠で扱う必要がある

### 4) 接続→リクエスト（HTTPクライアント挙動）境界
- リダイレクト追従、ヘッダ付与、認証情報（Basic等）付与、Hostヘッダの扱い、タイムアウト、DNS再解決、など
- ここが「到達できる/できない」だけでなく「副作用が起こる/起こらない」を左右する

### 5) レスポンス→反映/処理（出力・二次利用）境界
- SSRF自体は“到達”だが、レスポンスを返す/ログに残す/別処理に渡す、で機密性・再現性が変わる
- OWASPのSSRF防止ガイダンスは防御観点に焦点を当て、特に入力検証とネットワーク制御を組み合わせる前提で整理される。:contentReference[oaicite:11]{index=11}

---

## 到達性クラス（internal / localhost / metadata）を“判定の物差し”として固定する
本ファイルの主題は「URLトリック」ではなく、到達性クラスを固定して評価すること。

### A. localhost 到達（ループバック）
- 定義：127.0.0.1 / ::1 等、サーバ自身のローカルサービスへ到達
- 影響の型
  - 管理ポート（内部管理UI、メトリクス、デバッグ、ローカル限定API）
  - ループバックでしか公開していない“弱い前提”の機能（認証無し・IP制限のみ等）
- 判断上の重要点
  - “外部へ出られない”環境でも localhost は成立することがある（egress遮断と独立）

### B. internal 到達（プライベート/内部セグメント）
- 定義：RFC1918相当、社内/クラウドVPC内部など、ユーザから直接到達できないネットワークへ到達
- 影響の型（WSTGの「信頼関係」の具体化）
  - 内部REST、内部管理UI、内部データストアのHTTP面（内部前提で弱い設定になりやすい）
- 判断上の重要点
  - 影響評価は「何が見えるか」より「どこまで到達性が広いか（セグメント/名前解決/プロキシ）」で大きく変わる:contentReference[oaicite:12]{index=12}

### C. metadata 到達（link-local の特権面）
- 定義：クラウドが提供するインスタンスメタデータ。典型は link-local（169.254.169.254）で“インスタンス内からのみ”到達可能
- 重大化の理由
  - メタデータは“そのインスタンスの権限”に直結しうる（資格情報・トークン等）
  - ATT&CK では Cloud Instance Metadata API（T1552.005）として明確に位置づく:contentReference[oaicite:13]{index=13}
- 主要クラウドの“到達性の事実”（一次情報）
  - Azure IMDS：169.254.169.254、VM内からのみ、通信はホスト外へ出ない:contentReference[oaicite:14]{index=14}
  - GCP Metadata：`http://metadata.google.internal/computeMetadata/v1` または 169.254.169.254（VM内から）:contentReference[oaicite:15]{index=15}
  - AWS IMDS：EC2インスタンス内からメタデータにアクセス（IMDS設定/IMDSv2等の概念が重要）:contentReference[oaicite:16]{index=16}

---

## 観測ポイント（何を見て、どこまで言えるか）
SSRFは“到達した”を証拠化できないと、深い議論が全部薄くなる。観測は最初に設計する。

### 観測1：サーバがリクエストを発行した事実
- in-band（レスポンス反映）
  - 返却本文に取得結果が含まれるタイプ
- out-of-band（OOB）
  - DNS/HTTP/プロキシログなどに、サーバ発のアクセスが残るタイプ
- 差分観測
  - タイムアウト差分、例外差分、ステータス差分（“出た/出ない”の補助）
- WSTGの「注入点の特定→悪用可否→影響評価」の順に、まず“発行”を固める:contentReference[oaicite:17]{index=17}

### 観測2：到達性クラスの確定（localhost / internal / metadata）
- localhost：ループバックへ接続した痕跡（アプリログ、サービスログ、接続エラー差分）
- internal：内部IP/内部名への接続痕跡（プロキシ/FW/DNS/アプリログ）
- metadata：169.254.169.254 / metadata.google.internal / Azure IMDS への接続痕跡（宛先とヘッダ要件の差分が重要）:contentReference[oaicite:18]{index=18}

### 観測3：実行環境の特定（どこから出ているか）
- フロント（Web/API）か、ワーカー（ジョブ/プレビュー/変換）かで到達性が変わる
- “同じURL入力”でも、処理系が違えば別物（証拠は request_id/job_id と時刻窓で相関）

---

## 結果の意味（状態として説明）
到達性の結論は yes/no ではなく、**状態**として言い切る。

- 状態S1：localhost 到達あり
  - 意味：アプリは“自分自身の内部面”へ外部入力で到達できる
  - リスク：内部管理UI/ローカルAPI/デバッグ面が攻撃面化

- 状態S2：internal 到達あり
  - 意味：アプリは“内部ネットワークの信頼関係”を借用され得る（WSTGの主題）:contentReference[oaicite:19]{index=19}
  - リスク：内部サービス探索→弱い内部前提の突破→横展開の導線（ATT&CK T1046へ接続）:contentReference[oaicite:20]{index=20}

- 状態S3：metadata 到達あり
  - 意味：クラウド環境でインスタンス固有の情報・資格情報へ接続でき得る
  - リスク：資格情報取得・権限拡大（ATT&CK T1552.005）:contentReference[oaicite:21]{index=21}

---

## 攻撃者視点での利用（“到達性”が意思決定に効くポイント）
ここは「攻撃手順」ではなく、攻撃者が何を確かめ、次にどこへ寄せるかの判断モデルを固定する。

### 利用1：まず“到達性の地図”を作る（Discovery）
- localhost / internal / metadata のどれが成立するかで、次の狙いが変わる
- internal が成立するなら、内部サービス探索・内部API探索へ接続（T1046）:contentReference[oaicite:22]{index=22}

### 利用2：クラウドなら metadata が最優先の分岐点
- メタデータ到達が成立すると、権限（クレデンシャル/トークン）へ繋がる可能性がある（T1552.005）:contentReference[oaicite:23]{index=23}
- これが成立するなら、以後の行動はクラウドAPI列挙（T1526）へ寄る:contentReference[oaicite:24]{index=24}

### 利用3：入口の種類（URL入力点）が“再現性”を決める
- SSRF注入点が同期（API）か非同期（ジョブ）かで、観測と証拠化が変わる
- 報告では「どの経路が、どの実行環境で、どの到達性を持つか」を固定できると強い

---

## 次に試すこと（仮説A/Bで分岐：到達性の切り分けが主題）
### 仮説A：SSRFは成立しているが、外部観測できない（Blind）
- 次の一手
  - OOB観測点を変更（DNSのみ許可/HTTP不可 等を疑う）
  - アプリログ/プロキシログ/FWログの相関キー（request_id/job_id）を確保
  - “到達性クラス”を localhost → internal → metadata の順に、観測しやすいものから確定する

### 仮説B：URL解釈はしているが、接続が禁止されている（egress制御）
- 次の一手
  - それでも localhost は成立し得るため、localhost 到達の有無を別枠で確認
  - internal だけ禁止、metadata だけ禁止、など“宛先クラス別の制御”の可能性を評価

### 仮説C：接続はできるが、影響が限定されている（レスポンス非反映）
- 次の一手
  - 影響評価を“機密性”だけでなく“到達性そのもの”に寄せる（内部面へのアクセス経路ができた事実がリスク）
  - レスポンス処理（保存/解析/後続処理）に副作用がないかを確認（別コンポーネントへ波及することがある）

---

## 防御（優先順位：入口削除→多層で残余リスクを削る）
OWASPのSSRF防止チートシートは「防御観点に焦点を当て、攻撃手法の説明は目的ではない」と明示している。ここでは実務設計に落とす。:contentReference[oaicite:25]{index=25}

### 1) 入口削除（設計で“URLフェッチ機能”を減らす）
- 不要な外部取得・URL指定機能を撤廃/権限分離
- “ユーザがURLを渡せる機能”は、実装上 SSRF機能を持つと見做して設計審査する

### 2) アプリ層：宛先の許可（allowlist）を正規化後に適用
- 文字列ではなく parsed URL を基準に
- 宛先はホスト名ではなく **最終的に接続されるIP（解決結果）** で評価（DNSで揺れるため）
- 内部/localhost/link-local を既定拒否（業務要件がある場合のみ例外）:contentReference[oaicite:26]{index=26}

### 3) ネットワーク層：egress制御とセグメント分離
- SSRFは“WAF”で止めるより、出られない設計が効く（プロキシ強制、FW/SG）
- metadata（169.254.169.254 等）は“インスタンス内のみ”到達という前提があるため、アプリの到達性を借用されないように分離/制御する:contentReference[oaicite:27]{index=27}

### 4) 検知：到達性クラス別の監視
- 169.254.169.254（Azure/AWS）、metadata.google.internal（GCP）等への不審アクセス
- 内部DNSへの不審な問い合わせ
- これらは「到達性の借用」を示す強い兆候になり得る:contentReference[oaicite:28]{index=28}

---

## 証跡テンプレ（最小：yes/no/unknown を出す）
- Evidence ID：E-SSRF-REACH-###
- 収集（最小）
  - 注入点：どのパラメータ/機能（URL入力/インポート/プレビュー/連携 等）
  - 実行環境：フロント/ワーカー（分かる範囲）＋ 相関キー（request_id/job_id）
  - 到達性クラス結論：localhost / internal / metadata のどれが成立
  - 根拠：
    - OOBログ（DNS/HTTP/プロキシ）またはアプリログ（接続先・例外・時刻）
- 結論
  - yes：到達性クラスを相関付きで確定
  - no：当該注入点でサーバ発リクエストが発生しない、または到達性クラスが確実に遮断
  - unknown：観測点不足（どのログが必要か、追加提案を必ず添える）

---

## Labs設計（“到達性”を再現して理解する：手順書ではなく設計）
- 追加候補Lab
  - `04_labs/02_web/05_input/09_ssrf_reachability_internal_localhost_metadata/`
- 設計軸（学びが深くなる差分）
  - 実行環境差分：フロント（egress制限） / ワーカー（プロキシ経由のみ）など
  - 宛先差分：localhost / internal / metadata（Azure/GCP/AWS相当を模擬）
  - 観測差分：アプリログ（相関）＋ DNS/プロキシログ（到達先）＋ タイムアウト差分
- 成果物
  - “同じ注入点でも、実行環境とネットワークで到達性が変わる”を図と相関で示せる

---

## コマンド/リクエスト例（例示は最小限：観測設計だけ）
~~~~
# 目的：SSRFの深さは「到達性クラスを相関付きで確定できるか」で決まる。
# ここでは具体ペイロードの提示ではなく、
# (1) request_id/job_id を確保
# (2) DNS/HTTP/プロキシログの時刻窓で相関
# (3) localhost / internal / metadata のどれに到達したかを状態として結論付ける
# を“必ず”やる。
~~~~

---

## 参考（一次情報に近いもの中心）
- OWASP SSRF Prevention Cheat Sheet（防御観点）:contentReference[oaicite:29]{index=29}
- OWASP WSTG：Testing for SSRF（信頼関係/評価目的）:contentReference[oaicite:30]{index=30}
- OWASP Community：SSRF（メタデータ・内部REST等の代表例）:contentReference[oaicite:31]{index=31}
- Azure Instance Metadata Service（169.254.169.254、VM内のみ）:contentReference[oaicite:32]{index=32}
- GCP Metadata server endpoints（metadata.google.internal / 169.254.169.254）:contentReference[oaicite:33]{index=33}
- AWS EC2 Instance Metadata / IMDS（概念・設定）:contentReference[oaicite:34]{index=34}
- MITRE ATT&CK：T1552.005 Cloud Instance Metadata API:contentReference[oaicite:35]{index=35}

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_08_xxe_03_to_ssrf（internal_reachability）.md`
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
