(*

 TODO
 <NONE>

*)
unit Unit1;

{$mode objfpc}{$H+}
{$Packrecords C}

{.$define USE_SHA1}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  opensc;

const
  VERSION_STR = 'v1.0.170405';

type

  { TForm1 }

  TForm1 = class(TForm)
    CheckBoxHidePIN: TCheckBox;
    EditPIN: TEdit;
    LabelPIN: TLabel;
    MemoInfo: TMemo;
    procedure CheckBoxHidePINChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of String);
  private
    { private declarations }
    ctx, card, p15card: pointer;
    p15id: sc_pkcs15_id;
    p15key: p_sc_pkcs15_object;
    pdf_objsize, pdf_startxref, pdf_rootobj_num, pdf_pageobj_num: integer;
    pdf_rootobj, pdf_pageobj, newPdf1, newPdf2: string;
    PinCode: string;
    procedure DoSign(const fname: string);
    procedure AnalyzePDF(src: pchar; srcl: integer);
  public
    { public declarations }
  end;

var
  Form1: TForm1;

implementation
uses
  {$IFDEF USE_SHA1}
  DCPsha1,
  {$ELSE}
  DCPsha256,
  {$ENDIF}
  libeay32,
  DCPCrypt2;

{$R *.lfm}

// 低レベルOpenSSL関数群
const
  LIBEAY_DLL_NAME = 'libeay32.dll'; //'libcrypto-1_1.dll'

  V_ASN1_OCTET_STRING = 4;
  V_ASN1_NULL = 5;
  V_ASN1_OBJECT = 6;

  NID_rsaEncryption = 6;
  NID_pkcs7_data = 21;
  NID_pkcs9_contentType = 50;
  NID_pkcs9_messageDigest = 51;
  NID_pkcs9_signingTime = 52;
  NID_sha1 = 64;
  //NID_sha256WithRSAEncryption = 668;
  NID_sha256 = 672;

type
  ppkcs7_issuer_and_serial = ^pkcs7_issuer_and_serial;
  pkcs7_issuer_and_serial = record
    issuer : ^X509_NAME;
    serial : PASN1_INTEGER;
  end;

  pkcs7_signer_info = record
    version : PASN1_INTEGER;
    issuer_and_serial : PPKCS7_ISSUER_AND_SERIAL;
    digest_alg : pointer;
    auth_attr : pointer;
    digest_enc_alg : pointer;
    enc_digest : pointer;
    unauth_attr : pointer;
    pkey : ^EVP_PKEY;
  end;

  pX509_ALGOR = ^X509_ALGOR;
  X509_ALGOR = record
    algorithm: pASN1_OBJECT;
    parameter: pointer; // pASN1_TYPE
  end;

  ppX509_NAME = ^pX509_NAME;
  pASN1_ITEM = pointer;

function ASN1_INTEGER_set(a: PASN1_INTEGER; v: longword): integer; cdecl; external LIBEAY_DLL_NAME;
function ASN1_INTEGER_dup(x: pASN1_INTEGER): pASN1_INTEGER; cdecl; external LIBEAY_DLL_NAME;
function ASN1_OCTET_STRING_new(): pASN1_OCTET_STRING; cdecl; external LIBEAY_DLL_NAME;
procedure ASN1_OCTET_STRING_free(p: pASN1_OCTET_STRING); cdecl; external LIBEAY_DLL_NAME;
function ASN1_STRING_set(str: pASN1_STRING; data: pointer; len: integer): integer; cdecl; external LIBEAY_DLL_NAME;
procedure ASN1_STRING_set0(str: pASN1_STRING; data: pointer; len: integer); cdecl; external LIBEAY_DLL_NAME;
function ASN1_item_i2d_bio(it: pASN1_ITEM; _out: pBIO; x: pointer): integer; cdecl; external LIBEAY_DLL_NAME;
function ASN1_ITEM_lookup(name: pchar): pASN1_ITEM; cdecl; external LIBEAY_DLL_NAME;
function OBJ_nid2obj(n: integer): pASN1_OBJECT; cdecl; external LIBEAY_DLL_NAME;
function X509_NAME_set(xn: ppX509_NAME; name: pX509_NAME): integer; cdecl; external LIBEAY_DLL_NAME;
function X509_ALGOR_set0(alg: pointer; aobj: pASN1_OBJECT; ptype: integer; pval: pointer): integer; cdecl; external LIBEAY_DLL_NAME;
function X509_gmtime_adj(s: pASN1_TIME; adj: longint): pASN1_TIME; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_new: pPKCS7; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_content_new(p7: pPKCS7; _type: integer): integer; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_add_certificate(p7: pPKCS7; cert: pX509): integer; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_set_type(p7:PPKCS7; _type:longint):longint; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_dataFinal(p7: pPKCS7; data: pBIO): integer; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_SIGNER_INFO_new(): PPKCS7_SIGNER_INFO; cdecl; external LIBEAY_DLL_NAME;
procedure PKCS7_SIGNER_INFO_free(si: PPKCS7_SIGNER_INFO); cdecl; external LIBEAY_DLL_NAME;
function PKCS7_add_signer(p7: pPKCS7; psi: pPKCS7_SIGNER_INFO): integer; cdecl; external LIBEAY_DLL_NAME;
function PKCS7_add_signed_attribute(si: pPKCS7_SIGNER_INFO; nid, _type: integer; data: pointer): integer; cdecl; external LIBEAY_DLL_NAME;

{ TForm1 }

const
  APP_NAME = 'PDFにマイナンバーカードで電子署名するアプリ';
  MSG1 = 'ここにPDFをドラッグ＆ドロップしてください。';

procedure TForm1.FormCreate(Sender: TObject);
begin
  Application.Title:= APP_NAME;
  Caption:= APP_NAME + ' ' + VERSION_STR;
  Position:= poDesktopCenter;
  BorderStyle:= bsDialog;

  EditPIN.CharCase:= ecUppercase;

  MemoInfo.Text:= 'パスワードを入力して、' + MSG1;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
end;

procedure TForm1.CheckBoxHidePINChange(Sender: TObject);
begin
  if CheckBoxHidePIN.Checked then begin
    EditPIN.PasswordChar:= '*';
  end else begin
    EditPIN.PasswordChar:= #0;
  end;
end;

procedure TForm1.FormDropFiles(Sender: TObject; const FileNames: array of String);
var
  i: integer;
  s: string;
begin
  if not EditPIN.ReadOnly then begin
    s:= EditPin.Text;
    if (Length(s) < 6) or (Length(s) > 16) then begin
      ShowMessage('エラー：署名用パスワードの長さは6文字以上16文字以下です。');
      Exit;
    end;
    PinCode:= s;
  end;

  MemoInfo.Text:= '処理中です・・・';
  Self.Invalidate;

  try
    try
      for i:= 0 to High(FileNames) do
        DoSign(FileNames[i]);

      EditPIN.ReadOnly:= true;
      EditPIN.PasswordChar:= #0;
      EditPIN.Text:= '<入力済み>';
      CheckBoxHidePIN.Enabled:= false;

      ShowMessage('完了しました！');

    except
      on e: Exception do begin
        ShowMessage(e.Message);
      end;
    end;
  finally
    MemoInfo.Text:= MSG1;
  end;
end;

procedure TForm1.DoSign(const fname: string);
const
  SIGN_LEN = 10000; // 署名の長さ

  function GetErrMsg(r: integer): string;
  begin
    result:=#$0d#$0a + sc_strerror(r) + #$0d#$0a;
  end;

  procedure RaiseError(const s: string); overload;
  begin
    raise Exception.Create(s);
  end;

  procedure RaiseError(const s: string; r: integer); overload;
  begin
    raise Exception.Create(s + ':' + GetErrMsg(r));
  end;

  function GetCert: string;
  var
    r: integer;
    obj: p_sc_pkcs15_object;
    cert: p_sc_pkcs15_cert;
  begin
    r:= sc_pkcs15_find_cert_by_id(p15card, @p15id, @obj);
    if r < 0 then
      RaiseError('証明書が見つかりません', r);
    r:= sc_pkcs15_read_certificate(p15card, obj^.data, @cert);
    if r < 0 then
      RaiseError('証明書読み込みエラー', r);
    try
      SetLength(result, cert^.data.len);
      Move(cert^.data.value^, result[1], cert^.data.len);
    finally
      sc_pkcs15_free_certificate(cert);
    end;
  end;

  function GetSign(const digest: string): string;
  var
    r: integer;
  begin
    SetLength(result, 1024);
    r:= sc_pkcs15_compute_signature(
     p15card, p15key, SC_ALGORITHM_RSA_PAD_PKCS1,
     PChar(digest), Length(digest), PChar(result), Length(result));
    if r < 0 then
      RaiseError('署名データが作成できません', r);
    if r <> 256 then
      RaiseError('署名データサイズエラー');
    SetLength(result, r);
  end;

  function GetHash(stream: TStream): string; overload;
  var
    hash: TDCP_hash;
  begin
    {$IFDEF USE_SHA1}
    hash:=TDCP_sha1.Create(nil);
    {$ELSE}
    hash:=TDCP_sha256.Create(nil);
    {$ENDIF}
    try
      hash.Init;
      stream.Position:=0;
      hash.UpdateStream(stream, stream.Size);
      {$IFDEF USE_SHA1}
      SetLength(Result, 20);
      {$ELSE}
      SetLength(Result, 32);
      {$ENDIF}
      hash.Final(Result[1]);
    finally
      hash.Free;
    end;
  end;

  function GetHash(const data: string): string; overload;
  var
    ss: TStringStream;
  begin
    ss:= TStringStream.Create(data);
    try
      Result:= GetHash(ss);
    finally
      ss.Free;
    end;
  end;

  function EncodePKCS7(const cert, hash: string): string;
  var
    r, i: integer;
    bio: PBIO;
    p7: PPKCS7;
    si: ^PKCS7_SIGNER_INFO;
    x: PX509;
    os: pASN1_OCTET_STRING;
    s, sign: string;
  begin
    x:= nil;
    try
      bio:= BIO_new_mem_buf(PChar(cert), Length(cert));
      if bio = nil then
        RaiseError('BIO_newエラー(1)');
      try
        x:= d2i_X509_bio(bio, nil);
        if x = nil then
          RaiseError('X509作成エラー');
      finally
        BIO_free(bio);
      end;

      p7:= PKCS7_new();
      if p7 = nil then
        RaiseError('PKCS7_newエラー');
      try
        r:= PKCS7_set_type(p7, NID_pkcs7_signed);
        if r = 0 then
          RaiseError('PKCS7_set_typeエラー');

        r:= PKCS7_content_new(p7, NID_pkcs7_data);
        if r = 0 then
          RaiseError('PKCS7_content_newエラー');
        pPKCS7(p7^.sign^.contents)^.data:=nil;
        pPKCS7(p7^.sign^.contents)^.length:=0;

        r:= PKCS7_add_certificate(p7, x);
        if r = 0 then
          RaiseError('PKCS7_add_certificateエラー');

        si:= PKCS7_SIGNER_INFO_new();
        if si = nil then
          RaiseError('PKCS7_SIGNER_INFO_newエラー');
        r:= PKCS7_add_signer(p7, si);
        if r = 0 then begin
          PKCS7_SIGNER_INFO_free(si);
          RaiseError('PKCS7_add_signerエラー');
        end;

        r:= ASN1_INTEGER_set(si^.version, 1);
        if r = 0 then
          RaiseError('ASN1_INTEGER_setエラー');
        r:= X509_NAME_set(
         @si^.issuer_and_serial^.issuer, X509_get_issuer_name(x));
        if r = 0 then
          RaiseError('X509_NAME_setエラー');
        ASN1_INTEGER_free(si^.issuer_and_serial^.serial);
        si^.issuer_and_serial^.serial:=
         ASN1_INTEGER_dup(X509_get_serialNumber(x));
        if si^.issuer_and_serial^.serial = nil then
          RaiseError('X509_get_serialNumberエラー');

        {$IFDEF USE_SHA1}
        X509_ALGOR_set0(
         si^.digest_alg, OBJ_nid2obj(NID_sha1), V_ASN1_NULL, nil);
        {$ELSE}
        X509_ALGOR_set0(
         si^.digest_alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, nil);
        {$ENDIF}

        r:= PKCS7_add_signed_attribute(
         si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
        if r = 0 then
          RaiseError('auth_attr->contentType作成エラー');

        r:= PKCS7_add_signed_attribute(
         si, NID_pkcs9_signingTime, V_ASN1_UTCTIME, X509_gmtime_adj(nil, 0));
        if r = 0 then
          RaiseError('auth_attr->signingTime作成エラー');

        os:= ASN1_OCTET_STRING_new();
        if os = nil then
          RaiseError('ASN1_OCTET_STRING_newエラー');
        if (ASN1_STRING_set(os, PChar(hash), Length(hash)) = 0) or
           (PKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, os) = 0) then begin
          ASN1_OCTET_STRING_free(os);
          RaiseError('auth_attr->messageDigest作成エラー');
        end;

        // auth_attr部をDER形式にする
        bio:= BIO_new(Bio_s_mem);
        if bio = nil then
          RaiseError('BIO_newエラー(2)');
        try
          r:= ASN1_item_i2d_bio(
           ASN1_ITEM_lookup('PKCS7_ATTR_SIGN'), bio, si^.auth_attr);
          if r = 0 then
            RaiseError('ASN1_item_i2d_bioエラー');
          i:= BIO_pending(bio);
          SetLength(s, i);
          BIO_read(bio, @s[1], i);
        finally
          BIO_free(bio);
        end;

        // auth_attr部のハッシュを計算する
        s:= GetHash(s);

        // auth_attr部のハッシュをPKCS#1形式にする
        s:=
        {$IFDEF USE_SHA1}
         // SHA1のPKCS#1ヘッダー
         #$30#$21#$30#$09#$06#$05#$2B#$0E#$03#$02#$1A#$05#$00#$04#$14
        {$ELSE}
         // SHA256のPKCS#1ヘッダー
         #$30#$31#$30#$0D#$06#$09#$60#$86#$48#$01#$65#$03#$04#$02#$01#$05#$00#$04#$20
        {$ENDIF}
         + s;

        // auth_attr部の署名を取得
        sign:= GetSign(s);

        // 完成したauth_attr部の署名を格納する
        X509_ALGOR_set0(
         si^.digest_enc_alg,
         OBJ_nid2obj(NID_rsaEncryption),
         V_ASN1_NULL, nil);

        ASN1_STRING_set0(si^.enc_digest, PChar(sign), Length(sign));

        // ほんとはここにもちゃんとアルゴリズムを指定する
        // べきかもしれんが、指定しなくても許されるみたい。
        pX509_ALGOR(p7^.sign^.md_algs)^.algorithm:= nil;

        // DER 形式に変換
        bio:= BIO_new(Bio_s_mem);
        if bio = nil then
          RaiseError('BIO_newエラー(3)');
        try
          r:= i2d_PKCS7_bio(bio, p7);
          if r = 0 then
            RaiseError('i2d_PKCS7_bioエラー');
          i:= BIO_pending(bio);
          SetLength(result, i);
          BIO_read(bio, @result[1], i);
        finally
          BIO_free(bio);
        end;

      finally
        PKCS7_free(p7);
      end;
    finally
      X509_Free(x);
    end;
  end;

  procedure CreateNewPdf(srcl: integer);
  const
    SUB1 = #$0d#$0a'>>'#$0d#$0a'endobj'#$0d#$0a;
  var
    l1, l2, o_root_l, o_page_l, o_acro_l, o_annot_l, o_x_l: integer;
    o_root, o_page, o_acro, o_annot, o_x, o_sig: string;
  begin
    o_root:=Format(
      '%d 0 obj'#$0d#$0a +
      '<</AcroForm %d 0 R'#$0d#$0a +
      '%s'#$0d#$0a,
      [pdf_rootobj_num, pdf_objsize{Acro}, pdf_rootobj]);
    o_root_l:=Length(o_root);

    o_page:=Format(
      '%d 0 obj'#$0d#$0a +
      '<</Annots [%d 0 R]'#$0d#$0a +
      '%s'#$0d#$0a,
      [pdf_pageobj_num, pdf_objsize+1{Annot}, pdf_pageobj]);
    o_page_l:=Length(o_page);

    o_acro:=Format(
      '%d 0 obj'#$0d#$0a +
      '<</Fields [%d 0 R] /SigFlags 3 >>'#$0d#$0a +
      'endobj'#$0d#$0a,
      [pdf_objsize{Acro}, pdf_objsize+1{Annot}]);
    o_acro_l:=Length(o_acro);

    o_annot:=Format(
      '%d 0 obj'#$0d#$0a +
      '<</Type /Annot /Subtype /Widget /FT /Sig /T (JPKI SIG)' +
      //'/V %d 0 R /P %d 0 R /Rect [0 0 0 0] >>'#$0d#$0a +
      '/AP <</N %d 0 R >> /V %d 0 R /P %d 0 R /Rect [0 0 0 0] >>'#$0d#$0a +
      'endobj'#$0d#$0a,
      //[pdf_objsize+1{Annot}, pdf_objsize+3{Sig}, pdf_pageobj_num]);
      [pdf_objsize+1{Annot}, pdf_objsize+2{XObject}, pdf_objsize+3{Sig}, pdf_pageobj_num]);
    o_annot_l:=Length(o_annot);

    o_x:=Format(
      '%d 0 obj'#$0d#$0a +
      '<</Type /XObject /Subtype /Form >>'#$0d#$0a +
      'endobj'#$0d#$0a,
      [pdf_objsize+2{XObject}]);
    o_x_l:=Length(o_x);

    o_sig:=Format(
      '%d 0 obj'#$0d#$0a +
      '<</Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached'#$0d#$0a,
      [pdf_objsize+3{Sig}]);

    l1:=0;
    l2:=0;
    while true do begin
      newPdf1:=o_root + o_page + o_acro + o_annot + o_x + o_sig + Format(
       '/ByteRange [0 %d %d %d] /Contents ',
       [srcl+l1, srcl+l1+SIGN_LEN*2+2, l2]); // +2は< >の分

      newPdf2:=
       SUB1 + Format(
       'xref'#$0d#$0a +
       '%d 1'#$0d#$0a +
       '%.10d 00000 n'#$0d#$0a +
       '%d 1'#$0d#$0a +
       '%.10d 00000 n'#$0d#$0a +
       '%d 4'#$0d#$0a +
       '%.10d 00000 n'#$0d#$0a +
       '%.10d 00000 n'#$0d#$0a +
       '%.10d 00000 n'#$0d#$0a +
       '%.10d 00000 n'#$0d#$0a +
       'trailer'#$0d#$0a +
       '<</Size %d /Root %d 0 R /Prev %d >>'#$0d#$0a +
       'startxref'#$0d#$0a +
       '%d'#$0d#$0a +
       '%%%%EOF'#$0d#$0a,
       [
       pdf_rootobj_num,
       srcl,
       pdf_pageobj_num,
       srcl+o_root_l,
       pdf_objsize,
       srcl+o_root_l+o_page_l,
       srcl+o_root_l+o_page_l+o_acro_l,
       srcl+o_root_l+o_page_l+o_acro_l+o_annot_l,
       srcl+o_root_l+o_page_l+o_acro_l+o_annot_l+o_x_l,
       pdf_objsize+4,    // /Size
       pdf_rootobj_num,  // /Root
       pdf_startxref,    // /Prev
       srcl+l1+SIGN_LEN*2+2+Length(SUB1) // +2は< >の分
       ]);

      if (l1 = Length(newPDF1)) and (l2 = Length(newPDF2)) then break;
      l1:=Length(newPDF1);
      l2:=Length(newPDF2);
    end;
  end;

var
  r, i, reader_cnt: integer;
  ctx_param: sc_context_param;
  reader: pointer;
  pin: p_sc_pkcs15_object;
  s, cert, pkcs7, sign: string;
  fsIn, fsOut, fsTmp: TMemoryStream;
  digest: string;
begin
  Screen.Cursor:= crHourglass;
  try
    FillChar(ctx_param{%H-}, sizeof(ctx_param), 0);
    ctx_param.ver:= 0;
    ctx_param.app_name:= 'dspdf';
    r:= sc_context_create(@ctx, @ctx_param);
    if r <> 0 then
      RaiseError('初期化エラー', r);
    try
      reader_cnt:= sc_ctx_get_reader_count(ctx);
      if reader_cnt = 0 then
        RaiseError('カードリーダーが見つかりません');
      // Automatically try to skip to a reader with a card if reader not specified
      i:=0;
      while i < reader_cnt do begin
        reader:= sc_ctx_get_reader(ctx, i);
        if (sc_detect_card_presence(reader) and SC_READER_CARD_PRESENT) <> 0 then begin
          if sc_connect_card(reader, @card) >= 0 then break;
        end;
        Inc(i);
      end;
      if i >= reader_cnt then
        RaiseError('カードが挿入されていません');
      try
        r:= sc_lock(card);
        if r < 0 then
          RaiseError('カードをロックできません', r);
        try
          r:= sc_pkcs15_bind(card, nil, @p15card);
          if r <> 0 then
            RaiseError('PKCS#15バインドエラー', r);
          try
            // 1=認証用 2=署名用
            sc_pkcs15_hex_string_to_id('2', @p15id);
            r:= sc_pkcs15_find_prkey_by_id_usage(p15card, @p15id,
             SC_PKCS15_PRKEY_USAGE_SIGN or
	     SC_PKCS15_PRKEY_USAGE_SIGNRECOVER or
             SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
             @p15key);
            if r < 0 then
              RaiseError('秘密鍵が見つかりません', r);

            r:= sc_pkcs15_find_pin_by_auth_id(p15card, @(p15key^.auth_id), @pin);
            if r <> 0 then
              RaiseError('秘密鍵用のPINコードが見つかりません', r);

            // PINコードの確認
            r:= sc_pkcs15_verify_pin(p15card, pin, PChar(PinCode), Length(PinCode));
            if r <> 0 then begin
              Self.Close; // アプリを終了
              raise Exception.Create(
               'パスワード(PINコード)が違います！:' + GetErrMsg(r) +
               '連続で間違えるとカードが使えなくなりますので、安全のためアプリを終了します。'#$0d#$0a +
               'JPKI利用者ソフトを使用して正しいパスワードを確認することをお勧めします。'
              );
            end;

            // PDF読み込み
            fsIn:= TMemoryStream.Create;
            try
              fsIn.LoadFromFile(fname);
              fsIn.Position:= 0;
              SetLength(s, 4);
              fsIn.ReadBuffer(s[1], 4);
              if s <> '%PDF' then
                RaiseError(fname + ' はPDFではありません');

              AnalyzePDF(fsIn.Memory, fsIn.Size);
              CreateNewPdf(fsIn.Size);

              // ハッシュ計算
              fsTmp:= TMemoryStream.Create;
              try
                fsIn.Position:= 0;
                fsTmp.LoadFromStream(fsIn);
                fsTmp.Position:=fsTmp.Size;
                fsTmp.WriteBuffer(newPdf1[1], Length(newPdf1));
                fsTmp.WriteBuffer(newPdf2[1], Length(newPdf2));
                digest:= GetHash(fsTmp);
              finally
                fsTmp.Free;
              end;

              // 証明書を取得
              cert:=GetCert();

              // 証明書などをPKCS#7 に格納
              pkcs7:=EncodePKCS7(cert, digest);
              if Length(pkcs7) > SIGN_LEN then
                RaiseError('電子署名が長くなりすぎエラー');

              // ASCIIコード数値の文字列に変換
              SetLength(sign, SIGN_LEN*2);
              FillChar(sign[1], SIGN_LEN*2, '0');
              for i:= 1 to Length(pkcs7) do begin
                s:= IntToHex(Ord(pkcs7[i]), 2);
                sign[(i-1)*2+1]:= s[1];
                sign[(i-1)*2+2]:= s[2];
              end;
              sign:='<' + sign + '>';

              // PDF出力
              fsOut:= TMemoryStream.Create;
              try
                fsIn.Position:=0;
                fsOut.LoadFromStream(fsIn);
                fsOut.Position:=fsOut.Size;
                fsOut.WriteBuffer(newPdf1[1], Length(newPdf1));
                fsOut.WriteBuffer(sign[1], Length(sign));
                fsOut.WriteBuffer(newPdf2[1], Length(newPdf2));
                fsOut.SaveToFile(ChangeFileExt(fname, '')+'.signed.pdf');
              finally
                fsOut.Free;
              end;

            finally
              fsIn.Free;
            end;
          finally
            sc_pkcs15_unbind(p15card);
          end;
        finally
          sc_unlock(card);
        end;
      finally
        sc_disconnect_card(card);
      end;
    finally
      sc_release_context(ctx);
    end;
  finally
    Screen.Cursor:= crDefault;
  end;
end;

function PosP(const sub: string; src: pchar; srclen: integer;
   start: integer=0; finish: integer=-1): integer;
var
  i, l: integer;
begin
  result:= -1;
  if sub = '' then exit;
  l:= Length(sub);
  if finish < 0 then finish:= srclen - l;
  for i:= start to finish do begin
    if sub[1] = src[i] then begin
      if (l = 1) or CompareMem(@sub[1], @src[i], l) then begin
        result:= i;
        break;
      end;
    end;
  end;
end;

function RPosP(const sub: string; src: pchar; srclen: integer;
 start: integer=-1; finish: integer=0): integer;
var
  i, l: integer;
begin
  result:= -1;
  if sub = '' then exit;
  l:= Length(sub);
  if start < 0 then start:= srclen - l;
  for i:=start downto finish do begin
    if sub[1] = src[i] then begin
      if (l = 1) or CompareMem(@sub[1], @src[i], l) then begin
        result:= i;
        break;
      end;
    end;
  end;
end;

function PosPLine(const sub: string; src: pchar; srclen: integer;
 start: integer=0; finish: integer=-1): integer;
var
  l: integer;
begin
  result:= start;
  l:= Length(sub);
  while true do begin
    result:= PosP(sub, src, srclen, result, finish);
    if result < 0 then break;
    if src[result+l] in [#$0d, #$0a] then break;
    Inc(result, l);
  end;
end;

function RPosPLine(const sub: string; src: pchar; srclen: integer;
 start: integer=-1; finish: integer=0): integer;
var
  l: integer;
begin
  result:= start;
  l:= Length(sub);
  while true do begin
    result:= RPosP(sub, src, srclen, result, finish);
    if result < 0 then break;
    if src[result+l] in [#$0d, #$0a] then break;
    Inc(result, l);
  end;
end;

function CompareSP(const s: string; p: PChar): Boolean;
begin
  result:= CompareMem(PChar(s), p, Length(s));
end;

procedure TForm1.AnalyzePDF(src: pchar; srcl: integer);

  procedure RaisePdfError(msg: string = '');
  begin
    if msg = '' then msg:= 'PDF解析エラー';
    raise Exception.Create(msg);
  end;

  // コメントを飛ばす
  procedure SkipComment(var p: integer);
  begin
    if src[p] <> '%' then Exit;
    inc(p);
    while true do begin
      if (p >= srcl) then Exit;
      if src[p] in [#$0d, #$0a] then break;
      inc(p);
    end;
  end;

  // 区切り文字（制御文字）を飛ばす
  procedure SkipKugiri(var p: integer);
  begin
    while true do begin
      if (p >= srcl) then Exit;
      if src[p] = '%' then SkipComment(p);
      if src[p] in [#$21..#$7e] then break;
      inc(p);
    end;
  end;

  // 文字列の取得
  function GetStrValue(var p: integer): string;
  var
    p1, nest: integer;
  begin
    result:= '';
    p1:= p;
    if (p >= srcl) or (src[p] <> '(') then Exit;
    inc(p);
    nest:= 0;
    while true do begin
      if (p >= srcl) then Exit;
      if (src[p] = '(') and (src[p-1] <> '\') then begin
        Inc(nest);
      end else if (src[p] = ')') and (src[p-1] <> '\') then begin
        if nest = 0 then break;
        Dec(nest);
      end;
      inc(p);
    end;

    Inc(p);
    SetString(result, PChar(src+p1), p-p1);
  end;

  // 文字列(数値表現)の取得
  function GetNStrValue(var p: integer): string;
  var
    p1: integer;
  begin
    result:= '';
    p1:= p;
    if (p >= srcl) or (src[p] <> '<') then Exit;
    inc(p);
    while true do begin
      SkipKugiri(p);
      if (p >= srcl) then Exit;
      if src[p] = '>' then break;
      inc(p);
    end;

    Inc(p);
    SetString(result, PChar(src+p1), p-p1);
  end;

  function GetDicValue(var p: integer): string; forward;

  // 配列の取得
  function GetArrValue(var p: integer): string;
  var
    p1: integer;
  begin
    result:= '';
    p1:= p;
    if (p >= srcl) or (src[p] <> '[') then Exit;
    inc(p);
    while true do begin
      SkipKugiri(p);
      if p >= srcl-1 then Exit;
      case src[p] of
        '(': GetStrValue(p); // 文字列
        '[': GetArrValue(p); // 配列
        '<': begin
          if src[p+1] = '<' then begin
            GetDicValue(p); // 辞書
          end else begin
            GetNStrValue(p); // 文字列（数値表現）
          end;
        end;
        ']': break;
        else{case}
          inc(p);
      end{case};
    end{while};

    inc(p);
    SetString(result, PChar(src+p1), p-p1);
  end;

  // 辞書の取得
  function GetDicValue(var p: integer): string;
  var
    p1: integer;
  begin
    result:= '';
    p1:= p;
    if (p >= srcl) or (src[p] <> '<') then Exit;
    inc(p);
    if (p >= srcl) or (src[p] <> '<') then Exit;
    inc(p);
    while true do begin
      SkipKugiri(p);
      if p >= srcl-1 then Exit;
      case src[p] of
        '(': GetStrValue(p); // 文字列
        '[': GetArrValue(p); // 配列
        '<': begin
          if src[p+1] = '<' then begin
            GetDicValue(p); // 辞書
          end else begin
            GetNStrValue(p); // 文字列（数値表現）
          end;
        end;
        '>': begin
          if src[p+1] <> '>' then RaisePdfError;
          Inc(p, 2);
          SetString(result, PChar(src+p1), p-p1);
          Exit;
        end;
        else{case}
          Inc(p);
      end{case};
    end{while};
  end;

  // 数値その他の取得
  function GetEtcValue(var p: integer): string;
  var
    p1, p2: integer;
  begin
    result:= '';
    p1:= p;
    while true do begin
      if (p >= srcl) then Exit;
      if not(src[p] in [#$21..#$7e]) then break;
      if src[p] in ['/', '[', ']', '(', ')', '<', '>'] then break;
      inc(p);
    end;
    SetString(result, PChar(src+p1), p-p1);

    // 間接参照か？
    if StrToIntDef(result, -1) >= 0 then begin
      p2:= p;
      SkipKugiri(p2);
      if StrToIntDef(GetEtcValue(p2), -1) >= 0 then begin
        SkipKugiri(p2);
        if GetEtcValue(p2) ='R' then begin
          p:= p2;
          SetString(result, PChar(src+p1), p-p1);
        end;
      end;
    end;
  end;

  // 値を取得
  function GetValue(var p: integer): string;
  begin
    result:= '';
    if p >= srcl-1 then Exit;
    case src[p] of
      '(': result:= GetStrValue(p); // 文字列
      '[': result:= GetArrValue(p); // 配列
      '<': begin
        if src[p+1] = '<' then begin
          result:= GetDicValue(p); // 辞書
        end else begin
          result:= GetNStrValue(p); // 文字列（数値表現）
        end;
      end;
      '/': begin // 名前
        inc(p);
        result:= '/' + GetEtcValue(p);
      end
      else begin // その他
        result:= GetEtcValue(p);
      end;
    end;
  end;

  // 辞書内のキー（＝名前要素/xxxx）に対応する値を返す。
  function GetValueInDic(const name: string; start, finish: integer): string;
  var
    i: integer;
    s1, s2: string;
  begin
    result:= '';
    i:= start + 2; // +2 は'<<' の分
    while i < finish do begin
      SkipKugiri(i);
      s1:= GetValue(i);
      if (s1 = '') or (s1[1] <> '/') then break;
      SkipKugiri(i);
      s2:= GetValue(i);
      if s1 = name then begin
        result:= s2;
        break;
      end;
    end;
  end;

  // 間接参照を数値に変換
  function ref2int(const ref: string): integer;
  var
    p: integer;
  begin
    result:= -1;
    if ref[Length(ref)] = 'R' then begin
      p:= Pos(' ', ref);
      if p > 0 then begin
        result:= StrToIntDef(Copy(ref, 1, p-1), -1);
      end;
    end;
  end;

const
  NO_FMT = '%.10d';
var
  i, n1, n2, n3, p, p2, p_startxref, p_trailer: integer;
  xrefs, poss: TStringList;
  s: string;
begin
  p:= RPosPLine('%%EOF', src, srcl);
  if p < 0 then RaisePdfError;
  p:= RPosPLine('startxref', src, srcl, p-1);
  if p < 0 then RaisePdfError;

  // startxref の値を取得
  GetEtcValue(p); SkipKugiri(p);
  if p < 0 then RaisePdfError;
  pdf_startxref:= StrToIntDef(GetEtcValue(p), -1);
  if pdf_startxref < 0 then RaisePdfError;

  // xrefリストと間接オブジェクト位置リストを作成
  xrefs:= TStringList.Create;
  poss:= TStringList.Create;
  try
    xrefs.Sorted:= true;
    poss.Sorted:= true;
    pdf_rootobj_num:= -1;
    p:= pdf_startxref;
    while true do begin
      poss.Add(Format(NO_FMT, [p])); // xref開始位置=間接オブジェクト終了位置
      GetEtcValue(p); SkipKugiri(p);
      while true do begin
        n1:= StrToIntDef(GetEtcValue(p), -1);
        if n1 < 0 then
          RaisePdfError('未対応のxref, trailer形式です');
        SkipKugiri(p);
        n2:= StrToIntDef(GetEtcValue(p), -1);
        if n2 < 0 then
          RaisePdfError('未対応のxref, trailer形式です');
        SkipKugiri(p);
        for i:= 0 to n2-1 do begin
          SetString(s, PChar(src+p), 10);
          n3:= StrToIntDef(s, -1);
          if n3 < 0 then RaisePdfError;
          s:= Format(NO_FMT, [n1+i]);
          if xrefs.IndexOf(s) < 0 then
            xrefs.AddObject(s, TObject(n3));
          s:= Format(NO_FMT, [n3]);
          if poss.IndexOf(s) < 0 then
            poss.Add(s);
          Inc(p, 20); // xrefリストは１行２０文字と定められている
        end;

        SkipKugiri(p);
        if CompareSP('trailer', PChar(src+p)) then break;
      end{while};

      // trailer辞書の解析
      GetEtcValue(p); SkipKugiri(p);
      p_trailer:= p;
      p:= PosPLine('startxref', src, srcl, p_trailer);
      if p < 0 then RaisePdfError;
      p_startxref:= p;

      if pdf_rootobj_num = -1 then begin
        s:= GetValueInDic('/Root', p_trailer, p_startxref-1);
        pdf_rootobj_num:= ref2int(s);
      end;

      s:= GetValueInDic('/Encrypt', p_trailer, p_startxref-1);
      if s <> '' then
        RaisePdfError('暗号化されたPDFには署名できません。');

      s:= GetValueInDic('/Prev', p_trailer, p_startxref-1);
      if s = '' then break; // 前方参照がもうないので終了
      p:= StrToIntDef(s, -1);
      if p < 0 then RaisePdfError;
    end;

    if pdf_rootobj_num = -1 then RaisePdfError;
    if xrefs.Count = 0 then RaisePdfError;
    pdf_objsize:= StrToIntDef(xrefs[xrefs.Count-1], -1) + 1;
    if pdf_objsize < 0 then RaisePdfError;

    // Root オブジェクトの内容を取得
    i:= xrefs.IndexOf(Format(NO_FMT, [pdf_rootobj_num]));
    if i < 0 then RaisePdfError;
    p:= integer(xrefs.Objects[i]);
    i:= poss.IndexOf(Format(NO_FMT, [p]));
    if i < 0 then RaisePdfError;
    p2:= StrToInt(poss[i+1]);
    p:= PosP('obj', src, srcl, p);
    if p < 0 then RaisePdfError;
    inc(p, 3); SkipKugiri(p);
    if GetValueInDic('/AcroForm', p, p2-1) <> '' then
      RaisePdfError('すでに署名済みである、または、AcroFormを使用しているPDFには署名できません。');
    SetString(pdf_rootobj, PChar(src+p), p2-p);
    // <<より前の部分は不要なので削除
    p:= Pos('<<', pdf_rootobj);
    if p = 0 then RaisePdfError;
    pdf_rootobj:= Copy(pdf_rootobj, p+2, MaxInt);

    // Page オブジェクトを内容を取得
    pdf_pageobj:= '';
    for i:= 0 to xrefs.Count-1 do begin
      p:= integer(xrefs.Objects[i]);
      if p > 0 then begin
        p2:= poss.IndexOf(Format(NO_FMT, [p]));
        p2:= StrToInt(poss[p2+1]);
        p:= PosP('obj', src, srcl, p);
        if p < 0 then RaisePdfError;
        inc(p, 3); SkipKugiri(p);
        if GetValueInDic('/Type', p, p2-1) = '/Page' then begin
          if GetValueInDic('/Annots', p, p2-1) <> '' then
            RaisePdfError('すでにAnnotation(注釈)を使用しているPDFには署名できません。');
          pdf_pageobj_num:= StrToInt(xrefs[i]);
          SetString(pdf_pageobj, PChar(src+p), p2-p);
          // <<より前の部分は不要なので削除
          p:= Pos('<<', pdf_pageobj);
          if p = 0 then RaisePdfError;
          pdf_pageobj:= Copy(pdf_pageobj, p+2, MaxInt);
          break;
        end;
      end;
    end;

    if pdf_pageobj = '' then RaisePdfError;

  finally
    xrefs.Free;
    poss.Free;
  end;

end;

end.

