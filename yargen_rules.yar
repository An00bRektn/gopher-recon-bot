/*
   YARA Rule Set
   Author: An00bRektn
   Date: 2022-11-24
   Identifier: sample
   Reference: Gopher Recon Bot v2
*/

/* Rule Set ----------------------------------------------------------------- */

rule sample_scout {
   meta:
      description = "sample - file scout"
      author = "An00bRektn"
      reference = "Gopher Recon Bot v2"
      date = "2022-11-24"
      hash1 = "2b761430af14a0d4fe5ba333fcd863efa893a471cd436b530f9362040b236ea5"
   strings:
      $x1 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x2 = "heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid HTTP header value for header %qinvalid ind" ascii
      $x3 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x4 = "fmt: unknown base; can't happenframe_headers_prio_weight_shorthttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii
      $x5 = "adding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer" ascii
      $x6 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEParseFloatPhoenici" ascii
      $x7 = "Www-AuthenticateZanabazar_Squareafter object keyapplication/jsonapplication/wasmavx512vpclmulqdqbad g transitionbad special kind" ascii
      $x8 = "bad defer entry in panicbypassed recovery failedcan't scan our own stackcertificate unobtainablechacha20: wrong key sizeconnecti" ascii
      $x9 = "mstartbad sequence numberbad value for fieldcgocall unavailableclient disconnectedcontent-dispositioncriterion too shortdevice n" ascii
      $x10 = "avx512block:chan<-closedcookiedevicedomaindriverempty errno expectgopherheaderhypervinternip+netlistenminutendots:netdnsnumberob" ascii
      $x11 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x12 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
      $x13 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x14 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x15 = "GC work not flushedIDS_Binary_OperatorINADEQUATE_SECURITYINITIAL_WINDOW_SIZEKhitan_Small_ScriptMisdirected RequestPattern_White_" ascii
      $x16 = "+: allgallpasn1avx2basebindbitsbmi1bmi2boolcallcap cas1cas2cas3cas4cas5cas6chancx16datedialermsetagfailfilefromftpsfuncgziphosth" ascii
      $x17 = ", not a function.WithValue(type /etc/resolv.conf0123456789ABCDEF0123456789abcdef2384185791015625: value of type Already Reported" ascii
      $x18 = "2001::/322002::/162441406253ffe::/16AuthorityBassa_VahBhaiksukiClassINETCuneiformDiacriticForbiddenHex_DigitInheritedInstMatchIn" ascii
      $x19 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x20 = "reyobject: obj not pointer-alignedhpack: invalid Huffman-encoded datahttp: server closed idle connectionmheap.freeSpanLocked - i" ascii
      /* Imprint */
      $x21 = "f4b76de3b87463baa926ecd58fdbcb69" ascii
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      1 of ($x*)
}

