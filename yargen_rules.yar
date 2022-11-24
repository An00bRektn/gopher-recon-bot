/*
   YARA Rule Set
   Author: An00bRektn
   Date: 2022-11-23
   Identifier: sample
   Reference: Gopher Recon Bot
*/

/* Rule Set ----------------------------------------------------------------- */

rule sample_scout {
   meta:
      description = "sample - file scout"
      author = "An00bRektn"
      reference = "Gopher Recon Bot"
      date = "2022-11-23"
      hash1 = "f5129dfb4cac8ff37ee9ea0f9dcca239cf753e6d6ff8fe0ad9a944c0d43aab54"
   strings:
      $x1 = "fmt: unknown base; can't happenframe_headers_prio_weight_shorthttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii
      $x2 = "adding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer" ascii
      $x3 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii
      $x4 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x5 = "strings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not send a key shareuncaching span but s" ascii
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remoteproxy-connectionread_frame_otherreflect mismatchregexp: Compile(remote I/O error" ascii
      $x7 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x8 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPR" ascii
      $x9 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x10 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii
      $x11 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
      $x12 = "_cgo_thread_start missingallgadd: bad status Gidlearena already initializedbad status in shrinkstackbad system huge page sizecha" ascii
      $x13 = " to unallocated span/etc/sysconfig/clock/sys/hypervisor/type/usr/share/zoneinfo/37252902984619140625Egyptian_HieroglyphsIDS_Trin" ascii
      $x14 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x15 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii
      $x16 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
      $x17 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
      $x18 = "2001::/322002::/162441406253ffe::/16: status=AuthorityBassa_VahBhaiksukiClassINETCuneiformDiacriticForbiddenHex_DigitInheritedIn" ascii
      $x19 = "34694469519536141888238489627838134765625GODEBUG sys/cpu: no value specified for \"MapIter.Next called on exhausted iteratorTime" ascii
      $x20 = "../../devices/virtual/.localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/share/mime/gl" ascii
      /* Imprint */
      $x21 = "f4b76de3b87463baa926ecd58fdbcb69" ascii
      
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      1 of ($x*)
}

