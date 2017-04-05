unit opensc;

{$mode objfpc}{$H+}
{$Packrecords C} // 構造体等のアラインメントを4バイトに

(*
 * opensc.pas: OpenSC library header file
 *)

(*
 * opensc.h: OpenSC library header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjola <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *)

(**
 * @file src/libopensc/opensc.h
 * OpenSC library core header file
 *)

interface

uses
  Classes, SysUtils;

const
  DLL_FILE_NAME = 'opensc.dll';

  SC_MAX_AID_SIZE = 16;
  SC_MAX_OBJECT_ID_OCTETS = 16;
  SC_MAX_PATH_SIZE = 16;

type
  uint = cardinal;
  ulong = cardinal;
  pu8 = ^u8;
  u8 = byte;
  size_t = cardinal;
  p_size_t = ^size_t;

  p_sc_context = pointer;
  p_sc_pkcs15_card = pointer;
  pp_sc_pkcs15_pubkey = ^p_sc_pkcs15_pubkey;
  p_sc_pkcs15_pubkey = pointer;
  p_sc_pkcs15_cert_info = pointer;

  sc_object_id = record
    value: packed array[0..SC_MAX_OBJECT_ID_OCTETS-1] of integer;
  end;

  sc_aid = record
    value: packed array[0..SC_MAX_AID_SIZE-1] of char;
    len: size_t;
  end;

  sc_path = record
    value: packed array[0..SC_MAX_PATH_SIZE-1] of u8;
    len: size_t;

    (* The next two fields are used in PKCS15, where
     * a Path object can reference a portion of a file -
     * count octets starting at offset index.
     *)
    index: integer;
    count: integer;

    _type: integer; // type -> _type

    aid: sc_aid;
  end;

  (**
   * @struct sc_context_t initialization parameters
   * Structure to supply additional parameters, for example
   * mutex information, to the sc_context_t creation.
   *)
  p_sc_context_param = ^sc_context_param;
  sc_context_param = record
    //** version number of this structure (0 for this version) */
    ver: uint;
    (** name of the application (used for finding application
     *  dependend configuration data). If NULL the name "default"
     *  will be used. *)
    app_name: pchar;
    //** context flags */
    flags: ulong;
    //** mutex functions to use (optional) */
    thread_ctx: pointer; //sc_thread_context_t *thread_ctx;
  end;

  p_sc_algorithm_id = ^sc_algorithm_id;
  sc_algorithm_id = record
    algorithm: uint;
    oid: sc_object_id;
    params: pointer;
  end;

(**
 * Creates a new sc_context_t object.
 * @param  ctx   pointer to a sc_context_t pointer for the newly
 *               created sc_context_t object.
 * @param  parm  parameters for the sc_context_t creation (see
 *               sc_context_param_t for a description of the supported
 *               options)..
 * @return SC_SUCCESS on success and an error code otherwise.
 *)
function sc_context_create(ctx: ppointer; parm: p_sc_context_param): integer; cdecl;

(**
 * Releases an established OpenSC context
 * @param ctx A pointer to the context structure to be released
 *)
function sc_release_context(ctx: pointer): integer; cdecl;

(**
 * Returns the number a available sc_reader objects
 * @param  ctx  OpenSC context
 * @return the number of available reader objects
 *)
function sc_ctx_get_reader_count(ctx: pointer): uint; cdecl;

(**
 * Returns a pointer to the specified sc_reader_t object
 * @param  ctx  OpenSC context
 * @param  i    number of the reader structure to return (starting with 0)
 * @return the requested sc_reader object or NULL if the index is
 *         not available
 *)
function sc_ctx_get_reader(ctx: pointer; i: uint): pointer; cdecl;

(**
 * Forces the use of a specified card driver
 * @param ctx OpenSC context
 * @param short_name The short name of the driver to use (e.g. 'cardos')
 *)
function sc_set_card_driver(ctx: pointer; short_name: pchar): integer; cdecl;
(**
 * Connects to a card in a reader and auto-detects the card driver.
 * The ATR (Answer to Reset) string of the card is also retrieved.
 * @param reader Reader structure
 * @param card The allocated card object will go here *)
function sc_connect_card(reader: pointer; card: ppointer): integer; cdecl;
(**
 * Disconnects from a card, and frees the card structure. Any locks
 * made by the application must be released before calling this function.
 * NOTE: The card is not reset nor powered down after the operation.
 * @param  card  The card to disconnect
 * @return SC_SUCCESS on success and an error code otherwise
 *)
function sc_disconnect_card(card: pointer): integer; cdecl;

 (**
  * Checks if a card is present in a reader
  * @param reader Reader structure
  * @retval If an error occured, the return value is a (negative)
  *	OpenSC error code. If no card is present, 0 is returned.
  *	Otherwise, a positive value is returned, which is a
  *	combination of flags. The flag SC_READER_CARD_PRESENT is
  *	always set. In addition, if the card was exchanged,
  *	the SC_READER_CARD_CHANGED flag is set.
  *)
function sc_detect_card_presence(reader: pointer): integer; cdecl;

(**
 * Tries acquire the reader lock.
 * @param  card  The card to lock
 * @retval SC_SUCCESS on success
 *)
function sc_lock(card: pointer): integer; cdecl;
(**
 * Unlocks a previously acquired reader lock.
 * @param  card  The card to unlock
 * @retval SC_SUCCESS on success
 *)
function sc_unlock(card: pointer): integer; cdecl;

function sc_strerror(sc_errno: integer): pchar; cdecl;

const
  SC_PKCS15_MAX_LABEL_SIZE = 255;
  SC_PKCS15_MAX_ID_SIZE = 255;

  (* When changing this value, change also initialisation of the
   * static ASN1 variables, that use this macro,
   * like for example, 'c_asn1_access_control_rules'
   * in src/libopensc/asn1.c *)
  SC_PKCS15_MAX_ACCESS_RULES = 8;

type
  p_sc_pkcs15_id = ^sc_pkcs15_id;
  sc_pkcs15_id = record
    value: packed array[0..SC_PKCS15_MAX_ID_SIZE-1] of u8;
    len: size_t;
  end;

  p_sc_pkcs15_accessrule = ^sc_pkcs15_accessrule;
  sc_pkcs15_accessrule = record
    access_mode: uint;
    auth_id: sc_pkcs15_id;
  end;

  p_sc_pkcs15_df = ^sc_pkcs15_df;
  sc_pkcs15_df = record
    path: sc_path;
    record_length: integer;
    _type: uint; // type -> _type
    enumerated: integer;

    next, prev: p_sc_pkcs15_df;
  end;

  sc_pkcs15_der = record
    value: pbyte;
    len: size_t;
  end;

  pp_sc_pkcs15_object = ^p_sc_pkcs15_object;
  p_sc_pkcs15_object = ^sc_pkcs15_object;
  sc_pkcs15_object = record
    _type: uint; // type -> _type
    //* CommonObjectAttributes */
    _label: packed array[0..SC_PKCS15_MAX_LABEL_SIZE-1] of char; // label -> _label //* zero terminated */
    flags: uint;
    auth_id: sc_pkcs15_id;

    usage_counter: integer;
    user_consent: integer;

    access_rules: packed array[0..SC_PKCS15_MAX_ACCESS_RULES-1] of sc_pkcs15_accessrule;

    //* Object type specific data */
    data: pointer;
    //* emulated object pointer */
    emulated: pointer;

    df: p_sc_pkcs15_df; //* can be NULL, if object is 'floating' */
    next, prev: p_sc_pkcs15_object; //* used only internally */

    content: sc_pkcs15_der;
  end;

  pp_sc_pkcs15_cert = ^p_sc_pkcs15_cert;
  p_sc_pkcs15_cert = ^sc_pkcs15_cert;
  sc_pkcs15_cert = record
    version: integer;
    serial: pu8;
    serial_len: size_t;
    issuer: pu8;
    issuer_len: size_t;
    subject: pu8;
    subject_len: size_t;
    extensions: pu8;
    extensions_len: size_t;

    key: p_sc_pkcs15_pubkey;

    //* DER encoded raw cert */
    data: sc_pkcs15_der;
  end;

(* sc_pkcs15_bind:  Binds a card object to a PKCS #15 card object
 * and initializes a new PKCS #15 card object.  Will return
 * SC_ERROR_PKCS15_APP_NOT_FOUND, if the card hasn't got a
 * valid PKCS #15 file structure. *)
function sc_pkcs15_bind(card: p_sc_pkcs15_card; aid: pointer; pkcs15_card: ppointer): integer; cdecl;
(* sc_pkcs15_unbind:  Releases a PKCS #15 card object, and frees any
 * memory allocations done on the card object. *)
function sc_pkcs15_unbind(card: p_sc_pkcs15_card): integer; cdecl;

function sc_pkcs15_find_prkey_by_id_usage(
 card: p_sc_pkcs15_card; id: p_sc_pkcs15_id; usage: uint; pkcs15_obj: ppointer): integer; cdecl;

function sc_pkcs15_find_pin_by_auth_id(
 card: p_sc_pkcs15_card; id: p_sc_pkcs15_id; pkcs15_obj: ppointer): integer; cdecl;

function sc_pkcs15_verify_pin(
 card: p_sc_pkcs15_card; pin_obj: p_sc_pkcs15_object; pincode: pchar; pinlen: size_t): integer; cdecl;

function sc_pkcs15_compute_signature(
 card: p_sc_pkcs15_card; prkey_obj: p_sc_pkcs15_object; alg_flags: ulong;
 src: pointer; srclen: size_t; dst: pointer; dstlen: size_t): integer; cdecl;

function sc_pkcs15_hex_string_to_id(str: pchar; id: p_sc_pkcs15_id): integer; cdecl;

function sc_pkcs15_find_pubkey_by_id(
 card: p_sc_pkcs15_card; id: p_sc_pkcs15_id; obj: pp_sc_pkcs15_object): integer; cdecl;

function sc_pkcs15_read_certificate(
 card: p_sc_pkcs15_card; info: p_sc_pkcs15_cert_info; cert: pp_sc_pkcs15_cert): integer; cdecl;

function sc_pkcs15_find_cert_by_id(
 card: p_sc_pkcs15_card; id: p_sc_pkcs15_id; obj: pp_sc_pkcs15_object): integer; cdecl;

function sc_pkcs15_read_pubkey(
 card: p_sc_pkcs15_card; obj: p_sc_pkcs15_object; key: pp_sc_pkcs15_pubkey): integer; cdecl;

function sc_pkcs15_encode_pubkey(
 ctx: p_sc_context; pubkey: p_sc_pkcs15_pubkey; data: ppbyte; len: p_size_t): integer; cdecl ;

procedure sc_pkcs15_free_pubkey(pubkey: p_sc_pkcs15_pubkey); cdecl;
procedure sc_pkcs15_free_certificate(cert: p_sc_pkcs15_cert); cdecl;

const
  //* reader flags */
  SC_READER_CARD_PRESENT     = $00000001;
  SC_READER_CARD_CHANGED     = $00000002;
  SC_READER_CARD_INUSE       = $00000004;
  SC_READER_CARD_EXCLUSIVE   = $00000008;
  SC_READER_HAS_WAITING_AREA = $00000010;
  SC_READER_REMOVED          = $00000020;

  SC_ALGORITHM_RSA_PAD_PKCS1 = $00000002;

  SC_ALGORITHM_RSA_HASH_SHA1 = $00000020;

  //* keyUsageFlags are the same for all key types */
  SC_PKCS15_PRKEY_USAGE_ENCRYPT	       = $01;
  SC_PKCS15_PRKEY_USAGE_DECRYPT        = $02;
  SC_PKCS15_PRKEY_USAGE_SIGN           = $04;
  SC_PKCS15_PRKEY_USAGE_SIGNRECOVER    = $08;
  SC_PKCS15_PRKEY_USAGE_WRAP           = $10;
  SC_PKCS15_PRKEY_USAGE_UNWRAP         = $20;
  SC_PKCS15_PRKEY_USAGE_VERIFY         = $40;
  SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER  = $80;
  SC_PKCS15_PRKEY_USAGE_DERIVE         = $100;
  SC_PKCS15_PRKEY_USAGE_NONREPUDIATION = $200;

implementation

function sc_context_create(ctx: ppointer; parm: p_sc_context_param): integer; cdecl;
 external DLL_FILE_NAME;

function sc_release_context(ctx: pointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_ctx_get_reader_count(ctx: pointer): uint; cdecl;
 external DLL_FILE_NAME;

function sc_ctx_get_reader(ctx: pointer; i: uint): pointer; cdecl;
 external DLL_FILE_NAME;

function sc_set_card_driver(ctx: pointer; short_name: pchar): integer; cdecl;
 external DLL_FILE_NAME;

function sc_connect_card(reader: pointer; card: ppointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_disconnect_card(card: pointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_detect_card_presence(reader: pointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_lock(card: pointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_unlock(card: pointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_strerror(sc_errno: integer): pchar; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_bind(card: pointer; aid: pointer; pkcs15_card: ppointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_unbind(card: p_sc_pkcs15_card): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_find_prkey_by_id_usage(
 card: pointer; id: p_sc_pkcs15_id; usage: uint; pkcs15_obj: ppointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_find_pin_by_auth_id(
 card: pointer; id: p_sc_pkcs15_id; pkcs15_obj: ppointer): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_verify_pin(
 card: pointer; pin_obj: p_sc_pkcs15_object; pincode: pchar; pinlen: size_t): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_compute_signature(
 card: pointer; prkey_obj: p_sc_pkcs15_object; alg_flags: ulong;
 src: pointer; srclen: size_t; dst: pointer; dstlen: size_t): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_hex_string_to_id(str: pchar; id: p_sc_pkcs15_id): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_find_pubkey_by_id(
 card: p_sc_pkcs15_card; id: p_sc_pkcs15_id; obj: pp_sc_pkcs15_object): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_read_certificate(
 card: p_sc_pkcs15_card; info: p_sc_pkcs15_cert_info; cert: pp_sc_pkcs15_cert): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_find_cert_by_id(
 card: p_sc_pkcs15_card; id: p_sc_pkcs15_id; obj: pp_sc_pkcs15_object): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_read_pubkey(
 card: p_sc_pkcs15_card; obj: p_sc_pkcs15_object; key: pp_sc_pkcs15_pubkey): integer; cdecl;
 external DLL_FILE_NAME;

function sc_pkcs15_encode_pubkey(
 ctx: p_sc_context; pubkey: p_sc_pkcs15_pubkey; data: ppbyte; len: p_size_t): integer; cdecl ;
 external DLL_FILE_NAME;

procedure sc_pkcs15_free_pubkey(pubkey: p_sc_pkcs15_pubkey); cdecl;
 external DLL_FILE_NAME;

procedure sc_pkcs15_free_certificate(cert: p_sc_pkcs15_cert); cdecl;
 external DLL_FILE_NAME;

initialization
{$IFDEF MSWINDOWS}
   Set8087CW($133F);  // disable all floating-point exceptions
{$ENDIF}
end.

