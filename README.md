# PDFにマイナンバーカードで電子署名するアプリ

高価なアプリを購入したり、面倒なプラグイン登録したり、その他
複雑なインストール作業を必要とすることなどなく、簡単に、
PDF形式のファイル(以下単に「PDF」といいます)にマイナンバーカードを使用して
電子署名をするアプリです。  
作成された電子署名済みのPDFは、公式の電子定款などとして使えます（使えるはずです）。

## 必要なもの
* マイナンバーカード。
* マイナンバーカード対応のカードリーダー。
* Windows7以降のOS。

## ダウンロード
[ここ](/releases/latest)からダウンロードできます。

## インストール
dspdf.exe, libeay32.dll, opensc.dll を同じディレクトリにコピーしてください。

## アンインストール
インストールしたファイルを削除するだけです。
このアプリがWindowsのレジストリに同意なく意図的な変更を加えることはありません。

## 使い方

1. カードリーダーをPCに接続してください。
1. カードリーダーにマイナンバーカードをセットしてください。
1. dspdef.exe を実行してください。
1. 署名用パスワードを入力してください。
1. PDFをアプリにドラッグ＆ドロップしてください。そのPDFと同じディレクトリに、
電子署名済みのPDFが「.signed.」を加えたファイル名で作成されます。

なお、PDFに正しく電子署名がされているかどうかは、どなたでも無料で使える Acrobat Reader という
有名なアプリで確認できます。[参考](http://www.pdf-tools.trustss.co.jp/htVerify.html)

> 電子署名の**完全な**信頼性を確認するには「検証」という作業が必要です。
(検証がどういうものかについては[ここ](http://www.soumu.go.jp/kojinbango_card/kojinninshou-02.html)の
一番下の図が分かりやすいかもしれません)  
電子定款などのように公的機関に提出するものについては、検証作業はその公的機関が行い
ますから、Acrobat Reader でそのPDFを開いてみて「文書はこの署名が適用されてから変更されていません」と
なってさえいればとりあえずそれでよいといえます。
(文書が改ざんされていないことさえ確認できれば、あとは公的機関が持っているであろう高級な
「検証アプリ」で検証してもらうだけ、というわけです)  
これに対し、電子契約書のように私人間で利用するものについては、私人が認証局(J-LIS)のサーバーと
「検証アプリ」を通じてやりとりをして検証作業を行う必要があります。
よって、電子契約書の使い勝手は「検証アプリ」の使い勝手によることになるといっても過言ではありません。
([ここ](https://www.j-lis.go.jp/jpki/minkan/procedure1_2.html)などをみると、
国が検証アプリや検証用APIを直接に提供するつもりはなく、
総務大臣が認めた私人に検証アプリや検証用APIを提供させるスタンスのようです。
それを受けて、例えば、[NTTコミュニケーションズが有料で検証用APIを提供しています](http://www.ntt.com/business/services/application/authentication/mysign.html)。
認証サーバーへのアクセスはできるだけ制限したいということなのでしょうか。いずれにせよ今のところ気軽に「検証アプリ」を作れるような環境ではなさそうです。
また、マイナンバーカードには、JR東日本のSuicaみたいに、パスワード(PINコード)を入力せずに
利用できる機能も[あるようです](http://www.soumu.go.jp/menu_news/s-news/01gyosei02_02000134.html)。
検証用APIがオープンになればマイナンバーカードの活用範囲が広がりそうな気がしますよね)

## 注意事項など
* パスワードを連続して数回間違えると**マイナンバーカードが使用不能になってしまいます**ので
パスワードは慎重に入力してください。このアプリを使用する前に
[利用者クライアントソフト](https://www.jpki.go.jp/)を使用してパスワードが正しいかどうかを
確認しておくことをお勧めします。 [参照](https://www.jpki.go.jp/procedure/password.html)
* 電子署名されたPDFには署名者の名前や住所など、文書の信用性確保のために最低限必要とされる
個人情報が付加されています。電子署名されたPDFの取り扱いは慎重に行ってください。
[参照1](http://www.soumu.go.jp/kojinbango_card/kojinninshou-01.html) | 
[参照2](https://www.j-lis.go.jp/jpki/minkan/procedure1_2.html)
* PDFに電子署名することは、文書に実印を押すのと同じことといえると思います。
電子署名されたPDFの取り扱いは慎重に行ってください。
* このアプリには、電子署名に印影画像のようなものを付加する機能はありません。
個人的にはそのような機能は（電子署名の本質からだけいえば）無用の長物であると考えています。
* xrefリストとtrailerがバイナリ形式のPDFや、
xrefリストとtrailerが連続していないPDFには今のところ未対応です。
* 署名済みのPDFその他の、AcroForm機能をすでに使用しているPDFには今のところ未対応です。
* Annotation（注釈）機能をすでに使用しているPDFには今のところ未対応です。
* Encrypt(暗号化)ディクショナリを使用しているPDFには今のところ未対応です。

## 免責条項
このアプリを利用したことで利用者にいかなる損害が生じたとしても、
このアプリの作者はその損害を賠償できません。  
この免責条項に同意できない方はこのアプリを利用しないでください。

## License
どなたも無料でこのアプリを使用できます。  
ソースコードのライセンスは New BSD です。  
このアプリは下記のライブラリ等を利用しています。
これらの有益なライブラリ等の公開に携わっているすべての方々に感謝します。
なお、本アプリのソースコードを利用する場合は、各ライブラリ等のライセンスに
違反しないように注意してください。
* [OpenSC](https://github.com/OpenSC/OpenSC/)
* [OpenSSL](https://github.com/openssl/openssl)
* [DcpCrypt](https://sourceforge.net/projects/lazarus-ccr/files/DCPcrypt/)
* [libeay32.pas](http://www.disi.unige.it/person/FerranteM/delphiopenssl/)

## Contribution
1. Fork it
1. Create your feature branch
1. Commit your changes
1. Push to the branch
1. Create new Pull Request

## How to build
[Lazarus](http://www.lazarus-ide.org/) 1.6.4 for win32 を使用すればビルドできるはずです。

付属の libeay32.dll は、OpenSSL 1.1.0e（2017年3月現在での最新release）のソースコードに、
OpenSSL github リポジトリで公開されている OpenSSL 1.1.1 のソースコード上で新規追加APIの
ひとつとされる ASN1_ITEM_lookup() 関数を加え、MinGW を用いて独自ビルドしたものです。
なお、libcrypto-1_1.dll から libeay32.dll にリネームしています。

付属の opensc.dll は、マイナンバーカード対応の、OpenSC github リポジトリ master branche（2017年3月現在ではrelease前）から
独自ビルドしたものです（commit e7915ec）。

-----
Copyright(c)2017- [UNI法務行政書士事務所](http://uni.s17.xrea.com/) All rights reserved.  

