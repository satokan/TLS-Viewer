# 要件ドキュメント

## はじめに

本システムは、大規模なドメイン（最大100万件）に対してSSL/TLS関連情報を自動収集・分析し、SSL Pulseのようなダッシュボードで可視化するシステムです。週次での定期スキャンを実施し、インターネット全体のSSL/TLS導入状況を監視・分析することを目的としています。
このシステムによって、調査対象のドメインで動作するWebサイト等のSSL/TLSプロトコルバージョン、利用している暗号アルゴリズムに関する情報、PQC対応状況についての定点観測的な情報を提供可能である。

## 用語集

- **Scanner System**: SSL/TLS情報を収集・分析する本システム全体
- **Domain List**: スキャン対象となるドメインのリスト（CSVファイル形式）
- **TLS Scan**: 個別ドメインに対するSSL/TLS情報の収集処理
- **Database**: スキャン結果を格納するデータベースシステム
- **Dashboard**: スキャン結果を可視化するWebインターフェース
- **Certificate**: サーバー証明書
- **Cipher Suite**: 暗号スイート
- **PQ/T Hybrid**: Post-Quantum/Traditional ハイブリッド暗号構成

## 要件

### 要件 1: ドメインリストの取得

**ユーザーストーリー:** システム管理者として、CSVファイルからスキャン対象ドメインを読み込みたい。これにより、大量のドメインを効率的に管理できる。

#### 受入基準

1. WHEN CSVファイルが提供される, THE Scanner System SHALL ファイルからドメインリストを読み込む
2. THE Scanner System SHALL 最大100万件のドメインをサポートする
3. IF CSVファイルの形式が不正である, THEN THE Scanner System SHALL エラーメッセージを記録し処理を継続する
4. THE Scanner System SHALL 重複ドメインを除外する

### 要件 2: サーバー証明書情報の収集

**ユーザーストーリー:** セキュリティアナリストとして、各ドメインのサーバー証明書情報を収集したい。これにより、証明書の安全性を評価できる。

#### 受入基準

1. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL サーバー証明書の署名アルゴリズム（RSA、ECDSA、EdDSAなど）を取得する
2. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL サーバー証明書の公開鍵の種類と鍵長（ビット数）を取得する
3. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL サーバー証明書の有効期限を取得する
4. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL サーバー証明書の発行者（CA）情報を取得する
5. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL 証明書チェーンの検証結果を記録する

### 要件 3: TLSプロトコルバージョンの検出

**ユーザーストーリー:** セキュリティアナリストとして、各ドメインがサポートするTLSバージョンを把握したい。これにより、古いプロトコルの使用状況を監視できる。

#### 受入基準

1. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL TLS 1.0のサポート状況を検出する
2. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL TLS 1.1のサポート状況を検出する
3. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL TLS 1.2のサポート状況を検出する
4. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL TLS 1.3のサポート状況を検出する
5. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL SSL 3.0以前の非推奨プロトコルのサポート状況を検出する

### 要件 4: 暗号スイートの検出

**ユーザーストーリー:** セキュリティアナリストとして、各ドメインがサポートする暗号スイートを把握したい。これにより、暗号化の強度を評価できる。

#### 受入基準

1. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL サポートされている全ての暗号スイートのリストを取得する
2. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL 各暗号スイートの鍵交換アルゴリズムを識別する
3. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL 各暗号スイートの認証アルゴリズムを識別する
4. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL 各暗号スイートの暗号化アルゴリズムを識別する
5. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL 弱い暗号スイート（NULL、EXPORT、DESなど）の使用を検出する

### 要件 5: PQ/Tハイブリッド暗号の検出

**ユーザーストーリー:** セキュリティアナリストとして、耐量子暗号の導入状況を把握したい。これにより、将来の量子コンピュータ脅威への対応状況を監視できる。

#### 受入基準

1. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL PQ/Tハイブリッド鍵交換のサポート状況を検出する
2. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL ML-KEM（Module-Lattice-Based Key-Encapsulation Mechanism）のサポート状況を検出する
3. WHEN ドメインに対してTLS Scanが実行される, THE Scanner System SHALL 使用されているPQ/Tハイブリッド暗号スイートを記録する
4. THE Scanner System SHALL PQ/T対応の判定基準を設定ファイルで管理する

### 要件 6: 効率的なスキャン実行

**ユーザーストーリー:** システム管理者として、100万ドメインを効率的にスキャンしたい。これにより、週次スキャンを現実的な時間内で完了できる。

#### 受入基準

1. THE Scanner System SHALL 複数ドメインを並列処理する
2. WHEN スキャン中にタイムアウトが発生する, THE Scanner System SHALL 当該ドメインをスキップし次のドメインを処理する
3. WHEN スキャン中にエラーが発生する, THE Scanner System SHALL エラー情報を記録し処理を継続する
4. THE Scanner System SHALL スキャン進捗状況を記録する
5. THE Scanner System SHALL 中断されたスキャンを再開できる

### 要件 7: データの永続化

**ユーザーストーリー:** データアナリストとして、スキャン結果をデータベースに保存したい。これにより、履歴データの分析や傾向把握ができる。

#### 受入基準

1. WHEN TLS Scanが完了する, THE Scanner System SHALL 収集した情報をDatabaseに格納する
2. THE Scanner System SHALL スキャン実行日時を記録する
3. THE Scanner System SHALL 各ドメインの過去のスキャン履歴を保持する
4. THE Scanner System SHALL データベーススキーマのバージョン管理をサポートする

### 要件 8: ダッシュボードでの可視化

**ユーザーストーリー:** データアナリストとして、スキャン結果をダッシュボードで閲覧したい。これにより、SSL/TLS導入状況を直感的に把握できる。

#### 受入基準

1. THE Dashboard SHALL TLSバージョンの分布（全体に対する割合）を表示する
2. THE Dashboard SHALL 暗号スイートの使用状況（全体に対する割合）を表示する
3. THE Dashboard SHALL 証明書署名アルゴリズムの分布を表示する
4. THE Dashboard SHALL 証明書鍵長の分布を表示する
5. THE Dashboard SHALL PQ/Tハイブリッド構成の採用率を表示する
6. THE Dashboard SHALL 時系列での変化（各指標の推移）を表示する
7. THE Dashboard SHALL ドメインごとのセキュリティ評価グレード（A+, A, B, C, Fなど）を表示する

### 要件 12: セキュリティ評価（グレーディング）

**ユーザーストーリー:** セキュリティアナリストとして、各ドメインの構成を総合的に評価したグレードを知りたい。これにより、改善が必要なドメインを即座に特定できる。

#### 受入基準

1. THE Scanner System SHALL 収集した情報に基づき、各ドメインにセキュリティグレード（S, A, B, F）を付与する
2. THE Scanner System SHALL 独自の評価基準（TLSバージョン、暗号強度、PQC対応）に基づくグレーディングロジックを実装する
3. THE Scanner System SHALL TLS 1.3かつPQCハイブリッド暗号をサポートする場合、最高評価「S」を付与する
4. THE Scanner System SHALL 脆弱な設定（TLS 1.1以下、弱い暗号スイートなど）がある場合、最低評価「F」を付与する

### 要件 9: 週次スキャンの自動実行

**ユーザーストーリー:** システム管理者として、週次で自動的にスキャンを実行したい。これにより、最新のSSL/TLS導入状況を継続的に監視できる。

#### 受入基準

1. THE Scanner System SHALL 週次でのスキャン実行をスケジューリングできる
2. WHEN スケジュールされた時刻になる, THE Scanner System SHALL 自動的にスキャンを開始する
3. WHEN スキャンが完了する, THE Scanner System SHALL 完了通知を記録する
4. IF スキャンが失敗する, THEN THE Scanner System SHALL エラー通知を記録する

### 要件 10: OSSの活用

**ユーザーストーリー:** 開発者として、既存のOSSを活用したい。これにより、開発コストを削減し信頼性の高いシステムを構築できる。

#### 受入基準

1. THE Scanner System SHALL SSL/TLSスキャン機能に既存のOSSライブラリを使用する
2. THE Scanner System SHALL データベース操作に既存のOSSライブラリを使用する
3. THE Scanner System SHALL ダッシュボード構築に既存のOSSフレームワークを使用する

### 要件 11: GitHubでの公開

**ユーザーストーリー:** プロジェクトオーナーとして、ダッシュボードをGitHubで公開したい。これにより、コミュニティと情報を共有できる。

#### 受入基準

1. THE Dashboard SHALL 静的サイトとして生成できる
2. THE Dashboard SHALL GitHub Pagesでホスティングできる
3. THE Scanner System SHALL ソースコードをGitHubリポジトリで管理する
4. THE Scanner System SHALL ドキュメントをリポジトリに含める
