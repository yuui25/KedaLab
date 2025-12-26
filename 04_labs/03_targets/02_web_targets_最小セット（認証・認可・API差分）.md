# 02_web_targets_最小セット（認証・認可・API差分）

## 目的
- AuthN/AuthZ/API を「観測→差分→判断」で回す最小セットを確定する。
- 教材の数を増やさず、差分セット（未ログイン/一般/管理/テナント差）を作れる構成にする。

## 最小セット（推奨）
1) keda_app（自作）
   - 入口/認証/認可/API/設定の差分が1つで回る
2) API教材（REST or GraphQL）
   - `04_labs/03_targets/02_api_targets_検証用API選定.md` から1つ

## 最小差分セット
- 未ログイン → ログイン後
- userA → userB（ロール差）
- tenantA → tenantB（可能な範囲）

## 取得する証跡
- HAR / Proxyログ（必須）
- 必要時のみ pcap

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/03_targets/04_keda_app_教材Webアプリ（自作）.md`
- 関連 labs：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- 関連 playbooks：`02_playbooks/02_web_recon_入口→境界→検証方針.md`

