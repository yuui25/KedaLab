# Windows スタンドアロン vs AD 環境

## このファイルの位置づけ

参照元の作業ファイル：
- `../00_Playbook/Windows_AD_Attack_Flow.md`（各 Step の適用可否の根拠）
- `../00_Playbook/00_OS_Identification.md`（Windows と判定した後の分岐判断）

「Windows と判明したが AD 環境かどうかわからない」「スタンドアロンとはどういう意味か」という状況で開く。
作業中に参照するファイルではなく、判断の根拠となる原理を確認するファイル。

---

## スタンドアロンとは何か

**スタンドアロン（Standalone）** とは「Active Directory ドメインに参加していない Windows マシン」のこと。
ドメインコントローラー（DC）が存在せず、ユーザー管理はマシンごとのローカルアカウントで行われる。
ワークグループ（WORKGROUP）構成がほとんど。

---

## 環境の違い一覧

| 項目 | AD 環境 | スタンドアロン |
|------|--------|-------------|
| ドメイン | あり（例：`example.local`） | なし（`WORKGROUP`） |
| ユーザー管理 | DC が中央管理（LDAP） | 各マシンのローカルアカウント |
| 認証プロトコル | Kerberos（メイン）+ NTLM | NTLM のみ |
| 典型的に開くポート | 88(Kerberos)・389(LDAP)・445(SMB)・5985(WinRM) 等 | サービス依存（Web・FTP・RDP 等のみのことが多い） |
| `systeminfo` の Domain 欄 | `example.local` 等のドメイン名 | `WORKGROUP` |
| BloodHound | 権限チェーン可視化に有効 | 意味なし（収集するデータがない） |
| Kerberoasting / ASREPRoasting | 対象あり（SPN 付きアカウント等） | 対象なし（Kerberos 自体がない） |
| Pass-The-Hash の横展開 | 他のドメイン参加ホストへの横展開に使える | ローカル管理者共有（C$）へのアクセス程度 |
| DCSync | DC が存在するため対象あり | 対象なし（DC がいない）|
| 攻撃の主軸 | 認証情報取得 → 横展開 → DC 支配 | 初期アクセス → **ローカル権限昇格** |

---

## nmap から判断する方法

nmap スキャン結果のポート構成で AD/スタンドアロンを区別する：

**AD 環境と判断するポートの組み合わせ：**

| ポート | サービス | 意味 |
|--------|---------|------|
| **88** | Kerberos | **これが開いていれば AD 確定** |
| 389 / 636 | LDAP / LDAPS | ディレクトリサービス |
| 445 | SMB | ファイル共有（AD でもスタンドアロンでも使う）|
| 3268 / 3269 | Global Catalog | AD フォレスト全体の LDAP |
| 53 | DNS | DC が DNS を担うことが多い |

**スタンドアロンと推定するケース：**

- 88 がない + 389/3268 がない → AD ではない可能性が高い
- 開いているのが Web・SSH・FTP 等のサービスポートのみ → スタンドアロン寄り
- nmap の `Service Info: OS: Windows` + Kerberos ポートなし → スタンドアロン

**`systeminfo` でドメインを確認（シェル取得後）：**

```powershell
# [Target]
systeminfo | findstr /C:"Domain"
# → Domain: WORKGROUP     ← スタンドアロン
# → Domain: example.local ← AD 参加済み
```

```powershell
# または Get-ComputerInfo でも確認できる
Get-ComputerInfo | Select-Object CsDomain
# → CsDomain: WORKGROUP   ← スタンドアロン
```

---

## AD 環境での攻撃軸

AD は「認証情報取得 → 横展開 → DC 支配」の構造を持つ。攻撃軸の本体（BloodHound での経路把握・ACE 濫用・委任攻撃・DCSync）は `../00_Playbook/Windows_AD_Attack_Flow.md` の Step 4〜7 に集約してあるため、ここでは繰り返さない。本ファイルは「AD か否か」の**判断**に専念する。

---

## スタンドアロン環境での攻撃軸

AD のような「横展開 → DC 支配」の構造がないため、**ローカル権限昇格**が最終目標になることが多い。

**初期アクセス経路（AD と共通）：**

- Web アプリの脆弱性（ファイルアップロード・SQLi・コマンドインジェクション 等）
- 公開サービスの CVE（FTP・SSH・RDP 等）
- **SMB のリモート CVE（古い Windows / SMBv1）**: MS17-010（EternalBlue）/ MS08-067 等。**未認証で SYSTEM シェルが直接取れる初期侵入経路**で、ローカル権限昇格ではない（シェル取得が前提ではない）→ `../02_Initial_Access/SMB_Windows_Exploitation.md`

> **「OS が古い」の切り分け：** SMB が露出した古い Windows なら、まず **リモート SMB CVE（上記・初期侵入）** を試す。シェルを取った後に「OS ビルドが古い」を**ローカル権限昇格**に使うのは下表の経路で、リモート初期侵入とは別物。

**ローカル権限昇格の選択肢（シェル取得後）：**

| 状況 | 手法 | 参照先 |
|------|------|--------|
| OS ビルドが古い（ローカル特権昇格 CVE） | CVE（`searchsploit [OS バージョン] local`） | `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 0） |
| ローカルサービスが内部でリスニング | そのサービスの CVE・Buffer Overflow | `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1.5） → `Buffer_Overflow_LocalService.md` |
| `SeImpersonatePrivilege` がある | Potato 系攻撃 → SYSTEM 昇格 | （将来追記予定） |
| `whoami /all` で高権限トークン | トークン昇格 | `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1） |
| Webアプリの設定ファイルに認証情報 | ローカル管理者アカウントへの横移動 | `../02_Initial_Access/Credential_Discovery.md` |

**スタンドアロンでは「権限昇格後の横展開」が限定的：**

- 取得した管理者ハッシュは他のマシンへの Pass-The-Hash に使える可能性があるが、そのマシンも同じドメインユーザーを持っていることが前提（スタンドアロン環境では同一ハッシュを持つ他マシンがない場合が多い）
- 取得した認証情報・設定ファイルに他システムへの接続情報が書かれていないか確認する

---

## `Windows_AD_Attack_Flow.md` の各 Step の適用可否

> `Windows_AD_Attack_Flow.md` はもともと AD 環境向けに書かれているが、スタンドアロンでも読むことができる。
> 各 Step の適用可否を以下の表で確認してから使う。

| Step | 内容 | スタンドアロン |
|------|------|-------------|
| Step 0 | AD 環境かどうかの確認 | ✅ 「AD でない」と判断するために使う |
| Step 1 | ドメイン情報の特定 | ⚠️ ホスト名は確認する。ドメイン名・FQDN は存在しない |
| Step 2 | SMB 匿名アクセス・SYSVOL | ⚠️ 445 が開いていれば SMB 匿名確認は有効。SYSVOL・GPP はスキップ（AD 依存）|
| Step 3 | 初期認証情報の取得 | ✅ Web・FTP・ファイル等から認証情報を探す手法は全部有効 |
| Step 3.5 | パスワードスプレー | ⚠️ SMB/WinRM が開いていれば有効。ローカルアカウントへのスプレーになる（`--local-auth` が必要） |
| Step 4 | LDAP・BloodHound | ❌ AD 依存。スタンドアロンではスキップ |
| Step 5 | 権限チェーン特定（ACE） | ❌ AD 依存。スタンドアロンではスキップ |
| Step 6（RBCD・Unconstrained） | 委任攻撃 | ❌ AD 依存。スタンドアロンではスキップ |
| Step 6（Kerberoasting） | Kerberos 攻撃 | ❌ AD 依存。スタンドアロンではスキップ |
| Step 7 | DCSync | ❌ DC がないためスキップ |

**スタンドアロンで実際に行う流れ：**

```
[Step 0] AD でないことを確認
       ↓
[Step 1] ホスト名・OS バージョンを確認
       ↓
[Step 2] 445 が開いていれば SMB 匿名確認（SYSVOL はスキップ）
       ↓
[Step 3] 初期アクセス（Web・サービス脆弱性 等）
       ↓
[Step 3.5] WinRM/SMB が開いていればスプレー（--local-auth 付き）
       ↓
[Enumeration_Checklist.md] 侵入後列挙
  └── Step 0: OS バージョン・CVE 確認
  └── Step 1: whoami /all・特権トークン確認
  └── Step 1.5: netstat でローカルサービス確認
       ↓
[ローカル権限昇格]（CVE・BoF・SeImpersonate 等）
```

---

## 関連技術

- 関連：`../00_Playbook/Windows_AD_Attack_Flow.md`（AD 環境向け攻撃フロー）
- 関連：`../00_Playbook/00_OS_Identification.md`（Windows 判定後の分岐判断）

- 関連：../00_Playbook/00_OS_Identification.md（Windows 判定後の分岐判断）
