# DNS 調査（ドメインが渡された場合の起点）

## 着火条件
- テスト開始時にドメイン名のみ渡され、IP が不明な状態
- IP は判明しているが、同一サーバー上の他のドメイン・サブドメインを探したい場合

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `nslookup`・`dig`（ペネトレ用Linuxディストリ標準搭載）、`gobuster`（ペネトレ用Linuxディストリ標準搭載）
- インターネットアクセス: 外部DNSに問い合わせる場合は必要。内部 DNS サーバー指定なら不要

## 観点・着眼点

**先に確認すること：**

- 渡されたドメインは外部公開されているか、内部ドメインか
- VPN 接続が必要な場合、VPN 越しに名前解決できるか（`nslookup [ドメイン] [内部DNSのIP]`）

**何が出たら次に何をするか：**

| 出力の内容 | 次のアクション |
|-----------|--------------|
| A レコードで IP が判明した | その IP を対象に `nmap -sC -sV` へ進む |
| 複数の A レコード（ロードバランサー等） | 全 IP をスキャン対象に追加する |
| MX レコードが別ホストを指している | メールサーバーのIPも調査対象に追加する |
| NS レコードで権威 DNS サーバーが判明した | ゾーン転送（`dig AXFR`）を試みる |
| CNAME でサードパーティサービスを指している | サービス名を特定して設定ミス（Subdomain Takeover）を確認する |
| サブドメインに `dev`・`staging`・`internal` 等がある | 本番より設定が緩い可能性が高いので優先して調査する |

---

## 手順

## ① A レコードで IP を特定する

```bash
# [Attacker] nslookup で確認（シンプル）
nslookup [ドメイン]

# [Attacker] dig で確認（フィールドが明確）
dig [ドメイン] A
```

**nslookup の出力例と読み方：**

```
Server:   8.8.8.8          ← 問い合わせた DNS サーバー
Address:  8.8.8.8#53

Non-authoritative answer:
Name:     target.example.com
Address:  192.0.2.100     ← ここが対象 IP
```

**dig の出力例と読み方：**

```
;; ANSWER SECTION:
target.example.com.  300  IN  A  192.0.2.100
                               ↑          ↑
                               レコード種別   IP アドレス
```

フィールドは左から「名前 / TTL / クラス / レコード種別 / 値」の順。

---

## ② 内部 DNS サーバーを指定して解決する（VPN環境・内部ドメインの場合）

```bash
# [Attacker] @[DNS_IP] で問い合わせ先を指定する
dig [ドメイン] A @[内部DNSのIP]
nslookup [ドメイン] [内部DNSのIP]
```

テスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等が変わる）を `ip a` で確認し、同じサブネットにある DNS を指定する。

---

## ③ 主要レコードをまとめて確認する

```bash
# [Attacker] 全レコード種別を一括取得
dig [ドメイン] ANY

# [Attacker] レコード種別を個別に指定
dig [ドメイン] MX    # メールサーバー
dig [ドメイン] NS    # 権威 DNS サーバー
dig [ドメイン] TXT   # SPF・DKIM・サービス認証情報等
dig [ドメイン] CNAME # 別名レコード
```

**よく使うレコード種別と意味：**

| レコード | 意味 | ペネトレ上の注目点 |
|---------|------|----------------|
| A | ドメイン → IPv4 | 対象 IP の特定 |
| MX | メール配送先 | メールサーバーのIPも調査対象に |
| NS | 権威 DNS サーバー | ゾーン転送（AXFR）の試行先 |
| TXT | 任意文字列 | 認証トークン・内部情報が含まれることがある |
| CNAME | 別名（エイリアス） | Subdomain Takeover の確認対象 |
| PTR | IP → ドメイン（逆引き） | IP からホスト名を特定する際に使う |

---

## ④ ゾーン転送を試みる（NS が判明した場合）

設定ミスのある DNS サーバーは、全ドメインレコードを一括で返す（ゾーン転送）。

```bash
# [Attacker]
dig AXFR [ドメイン] @[NSサーバーのIP]
```

成功するとドメイン配下のすべてのホスト・IP がリストで返ってくる。内部サブドメインが一気に判明する。失敗（`Transfer failed`）するのが通常。

---

## ⑤ サブドメイン列挙（ブルートフォース）

```bash
# [Attacker] gobuster でサブドメインを総当たり
gobuster dns -d [ドメイン] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# [Attacker] ffuf（gobuster が使えない環境の代替）
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://[ドメイン] -H "Host: FUZZ.[ドメイン]" -fs [除外するサイズ]
```

**出力の読み方（gobuster）：**

```
Found: dev.target.example.com    ← 解決できたサブドメイン
Found: api.target.example.com
Found: internal.target.example.com
```

発見したサブドメインはすべて dig で A レコードを確認して IP を特定する。

---

## ⑥ /etc/hosts への登録

IP が判明したら `/etc/hosts` に登録する。Kerberos・LDAP・TLS の認証は IP ではなくドメイン名を要求する場合があるため、登録しておかないと後工程でエラーが出る。

```bash
# [Attacker]
echo "[IP]  [ドメイン] [ホスト名]" | sudo tee -a /etc/hosts

# 例
echo "192.0.2.100  target.example.com target" | sudo tee -a /etc/hosts
```

**原状回復：** テスト完了後は `/etc/hosts` から該当行を削除する。

```bash
# [Attacker] 登録した行を削除
sudo sed -i '/192.0.2.100/d' /etc/hosts
```

---

## 刺さらなかったとき

- 外部 DNS で名前解決できない → テスト経路（環境による）から内部 DNS を `@[IP]` で直接指定する
- ゾーン転送が `Transfer failed` → 正常。AXFR は無効化されているのが一般的
- サブドメイン列挙の結果が 0 件 → ワードリストを変える（`subdomains-top1million-20000.txt` 等の大きめのリストに切り替え）
- nslookup で IP が返るが nmap が通らない → ファイアウォールがある可能性。`-Pn` で ping スキップして強制スキャン

## 注意点・落とし穴

- `dig ANY` は DNS サーバーの実装によって返さない場合がある。レコード種別を個別に指定して確認する
- CNAME が指しているサードパーティサービス（GitHub Pages・Heroku 等）が未設定のまま放置されている場合、Subdomain Takeover が成立する
- /etc/hosts への登録は複数テストをまたいで作業する場合に混在するリスクがある。作業前後にファイルの内容を確認する

## 関連技術
- 前：テスト開始（ドメイン渡し）
- 後：IP 特定後の OS 判定 → `../00_Playbook/00_OS_Identification.md`
- 後：vhost・サブドメインの詳細列挙 → `./Web_Enumeration.md`
