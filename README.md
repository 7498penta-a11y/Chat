# ⚡ NexusChat — Discord風チャットアプリ

## 機能
- ✅ ユーザー登録 / ログイン（JWT認証）
- ✅ リアルタイムチャット（Socket.io）
- ✅ ファイルアップロード（最大50MB）
- ✅ 画像のインラインプレビュー + ライトボックス
- ✅ タイピングインジケーター
- ✅ オンラインメンバー表示
- ✅ 複数チャンネル（general / random / media / dev）
- ✅ ファイルD&Dアップロード
- ✅ セッション維持（localStorage token）

## セットアップ

```bash
# 依存関係インストール
npm install

# サーバー起動
npm start

# ブラウザで開く
open http://localhost:3000
```

## 開発モード（nodemon）

```bash
npm run dev
```

## ファイル構成

```
discord-app/
├── server.js          # Node.js バックエンド
├── package.json
├── uploads/           # アップロードされたファイル（自動作成）
└── public/
    └── index.html     # フロントエンド（全部入り）
```

## 技術スタック

| レイヤー | 技術 |
|---------|------|
| バックエンド | Node.js + Express |
| リアルタイム | Socket.io |
| 認証 | JWT + bcryptjs |
| ファイルアップロード | Multer |
| フロントエンド | Vanilla JS + CSS |

## 注意事項

- データはメモリ上に保存されます（サーバー再起動でリセット）
- 本番環境ではDBを追加してください（MongoDB等）
- `JWT_SECRET` 環境変数を設定してください
