
PDFにマイナンバーカードで電子署名するアプリ dspdf は、
下記のリンク先の文章をよくお読みになってからご利用ください。

https://github.com/uniho/dspdf/blob/master/README.md


UNI法務行政書士事務所
http://uni.s17.xrea.com/


バージョンアップ履歴

v1.0.170405
・最初のバージョン。

v1.0.170516
・https://www.touki-kyoutaku-online.moj.go.jp/cautions/append/sign_pdf.html に従って、
　Signature Format部に、/M と /Name を追加。
　ただし、/Name についてはピリオドを設定するにとどめた。
　署名者の氏名は署名用証明書の「X509v3 Subject Alternative Name」に格納されていて、
　検証ではそちらの情報のみが用いられるものと考えられるため。
