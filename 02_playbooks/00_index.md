# 00_index（02_playbooks）
`02_playbooks/` は「手順の網羅」ではなく、**最初の5分で手を動かし、観測→判断→次の一手**を決めるための導線です。  
詳細な技術解説や攻撃手口は `01_topics/` に寄せ、playbook は **分岐（条件）と判断基準、最小証跡**に集中します。

## 目的（このプレイブック群で到達する状態）
- 入口（どこから入る）と境界（資産/信頼/権限/実行/運用）を、短時間で根拠付きで説明できる。
- “次に読むtopic” と “次に回す検証” を迷わず選べる（条件AならA、違えばB）。
- 後で説明できる最小証跡（HAR/pcap/ログ/設定スナップショット）を残せる。

## ガイドライン位置づけ
- ASVS：AuthN/AuthZ/Session/API/Secrets/Logging の「前提崩れ」を先に潰す。
- WSTG：Information Gathering を起点に、Auth/Access Control/API/Config へ観測点を供給。
- PTES：IG→VA→Exploitation→Post の接続を短く保つ（やることを増やさない）。
- MITRE ATT&CK：分類のためではなく、境界崩壊（Discovery/Credential/Lateral/Exfiltration等）の説明補助。

## 使い方（共通：最初の5分）
1) スコープ確認：許可/禁止、第三者宛通信の可否、時間制約、影響制約（変更/送信/大量アクセスの禁止）。
2) 代表点の確定：入口URL（3つまで）、代表ホスト（3つまで）、テストユーザ（2種以上：ロール/テナント差）。
3) 証跡の準備：HAR/pcap/ログの「どれを取るか」と相関キー（User/Host/Time/Destination/Identifier）。
4) 1回だけ観測：ログイン1回、代表API 1回、代表ポート 1回…のように“最小回数”で状態を掴む。
5) 分岐で次へ：AuthN/AuthZ/API/Input/Config/SaaS/NW/Exfil のどこが勝負かを決める。

## 収録プレイブック一覧（使う順の目安）
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`：パッシブ中心で資産/信頼境界→深掘り優先度
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`：Web入口を境界で整理→次の深掘り（AuthN/AuthZ/API/Input/Config）
- `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`：本人性/セッション材料/寿命/例外→次の深掘り
- `02_playbooks/04_authz_境界モデル→検証観点チェック.md`：所有/ロール/テナント/共有/状態→越権の成立条件
- `02_playbooks/05_api_権限伝播→検証観点チェック.md`：UI≠API前提で権限伝播/判定点/非同期/Webhook
- `02_playbooks/07_input_to_rce_入力→実行の導線.md`：入力がどこで解釈/実行に変わるか→優先度付け
- `02_playbooks/10_web_config_ops_設定・運用境界_初動.md`：CORS/Headers/Secrets/Logging/CDN-WAF で崩れる点を短時間で確定
- `02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`：到達性→サービス→認証→権限→Post初動
- `02_playbooks/08_saas_信頼→共有→監査ログ_初動.md`：SaaSの信頼/共有/監査をYes/No/Unknownで埋める
- `02_playbooks/09_egress_exfil_出口評価（DNS_HTTP_SMB）.md`：DNS/HTTP(S)/SMB の出口成立と封じ方

## 作成テンプレ（参考）
- `99_templates/02_playbook-template.md`
