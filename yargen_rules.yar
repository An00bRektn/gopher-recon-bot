/*
   YARA Rule Set
   Author: An00bRektn
   Date: 2022-11-25
   Identifier: sample
   Reference: Gopher Recon Bot
*/

/* Rule Set ----------------------------------------------------------------- */

rule sample_scout {
   meta:
      description = "sample - file scout"
      author = "An00bRektn"
      reference = "Gopher Recon Bot"
      date = "2022-11-25"
      hash1 = "ebc89d237075ee0b31da0aa5834cfd452dbd3fe7693ed86128625619e75c9620"
   strings:
      $x1 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x2 = "heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid HTTP header value for header %qinvalid ind" ascii
      $x3 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFloatPhoenici" ascii
      $x4 = "adding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer" ascii
      $x5 = "fmt: unknown base; can't happenframe_headers_prio_weight_shorthttp2: connection error: %v: %vinternal error - misuse of itabinva" ascii
      $x6 = "VERSION_CODENAMEWww-AuthenticateZanabazar_Squareapplication/jsonapplication/wasmavx512vpclmulqdqbad g transitionbad special kind" ascii
      $x7 = "mstartbad sequence numberbad unicode format bad value for fieldcgocall unavailableclient disconnectedcontent-dispositioncriterio" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x9 = "bad defer entry in panicbypassed recovery failedcan't scan our own stackcertificate unobtainablechacha20: wrong key sizeconnecti" ascii
      $x10 = "atildeavx512brvbarccedilcentoschan<-closedcookiecurrendaggerdebiandividedomaineacuteegraveempty errno expectfedoraforallfownerfr" ascii
      $x11 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x12 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
      $x13 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x14 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x15 = "%+vallgallpamznaposasn1aumlavx2basebetabindbitsbmi1bmi2boolbullcallcap cas1cas2cas3cas4cas5cas6centchancirccongcopycx16dArrdarrd" ascii
      $x16 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x17 = "GC work not flushedIDS_Binary_OperatorINADEQUATE_SECURITYINITIAL_WINDOW_SIZEKhitan_Small_ScriptMisdirected RequestPattern_White_" ascii
      $x18 = "01234567_1 error: 2001::/322002::/162441406253ffe::/16AuthorityBassa_VahBhaiksukiClassINETCuneiformDiacriticForbiddenHex_DigitIn" ascii
      $x19 = ", not a function.WithValue(type /etc/lsb-release/etc/resolv.conf0123456789ABCDEF0123456789abcdef2384185791015625: value of type " ascii
      $x20 = "eriod must be non-negativetls: failed to write to key log: tls: invalid server finished hashtls: unexpected ServerKeyExchangetoo" ascii
      /* Imprint */
      $x21 = "f4b76de3b87463baa926ecd58fdbcb69" ascii
   condition:
      uint16(0) == 0x457f and filesize < 14000KB and
      1 of ($x*)
}


