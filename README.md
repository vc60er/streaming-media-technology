Table of Contents
=================

   * [流媒体技术手册](#流媒体技术手册)
      * [协议](#协议)
         * [RTP](#rtp)
         * [RTCP](#rtcp)
         * [SDP](#sdp)
         * [SRTP](#srtp)
         * [ICE](#ice)
         * [STUN](#stun)
         * [TURN](#turn)
         * [DTLS](#dtls)
         * [SCTP](#sctp)
         * [RTMP](#rtmp)
         * [RTSP](#rtsp)
         * [HLS](#hls)
         * [DASH](#dash)
      * [容器](#容器)
         * [mp4](#mp4)
         * [ts](#ts)
      * [传输控制](#传输控制)
         * [GCC](#gcc)
         * [PCC](#pcc)
         * [BBR](#bbr)
         * [NACK](#nack)
         * [QUIC](#quic)
         * [ARQ](#arq)
         * [NetEQ](#neteq)
         * [synchronize](#synchronize)
         * [FEC](#fec)
         * [RS](#rs)
      * [语音增强](#语音增强)
         * [AEC](#aec)
         * [NS](#ns)
         * [AGC](#agc)
         * [VAD](#vad)
      * [视频编码器](#视频编码器)
         * [H.264/avc](#h264avc)
         * [h.265/hevc](#h265hevc)
         * [vp8](#vp8)
         * [SVC](#svc)
         * [x264编码器参数](#x264编码器参数)
      * [颜色空间](#颜色空间)
         * [gamma校准](#gamma校准)
         * [RGB](#rgb)
         * [YUV](#yuv)
         * [YCrCb](#ycrcb)
      * [音频编码器](#音频编码器)
         * [iLBC](#ilbc)
         * [ACC](#acc)
         * [opus](#opus)
      * [智能视频封面](#智能视频封面)
      * [工具](#工具)
      * [资源](#资源)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

# 流媒体技术手册
## 协议
###  RTP
The Real-time Transport Protocol (RTP) is a network protocol for delivering audio and video over IP networks. RTP is used in communication and entertainment systems that involve streaming media, such as telephony, video teleconference applications including WebRTC, television services and web-based push-to-talk features.  

RTP typically runs over User Datagram Protocol (UDP). RTP is used in conjunction with the RTP Control Protocol (RTCP). While RTP carries the media streams (e.g., audio and video), RTCP is used to monitor transmission statistics and quality of service (QoS) and aids synchronization of multiple streams. RTP is one of the technical foundations of Voice over IP and in this context is often used in conjunction with a signaling protocol such as the Session Initiation Protocol (SIP) which establishes connections across the network.  

[wiki: Real-time Transport Protocol](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol)  
[RFC3550 - RTP: A Transport Protocol for Real-Time Applications](https://tools.ietf.org/html/rfc3550)  
[RFC3551 - RTP Profile for Audio and Video Conferences with Minimal Control](https://tools.ietf.org/html/rfc3551)  
[RFC3611 - RTP Control Protocol Extended Reports (RTCP XR)](https://tools.ietf.org/html/rfc3611)  
[RFC4585 - Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF) ](https://tools.ietf.org/html/rfc4585)  
[RFC5124 - Extended Secure RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/SAVPF) ](  https://tools.ietf.org/html/rfc5124)  
[RFC7741 - RTP Payload Format for VP8 Video](https://tools.ietf.org/html/rfc7741)   
[RFC6184 - RTP Payload Format for H.264 Video](https://tools.ietf.org/html/rfc6184)  
[RFC5450 - Transmission Time Offsets in RTP Streams](https://tools.ietf.org/html/rfc5450)  
[RFC5104 - Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)](https://tools.ietf.org/html/rfc5104)  
[RFC3550-RTP协议](rfc-chinese/RFC3550-RTP协议.pdf)  
[RFC3550-RTP应用于实时应用的传输协议](rfc-chinese/RFC3550-RTP应用于实时应用的传输协议.pdf)  



```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          payload  ...                         |
|                               +-------------------------------+
|                               | RTP padding   | RTP pad count |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- PT (Payload Type)

Identifies the format of the RTP payload. In essence, a Payload Type is an integer number that maps to a previously defined encoding, including clock rate, codec type, codec settings, number of channels (in the case of audio), etc. All this information is needed by the receiver in order to decode the stream.

Originally, the standard provided some predefined Payload Types for commonly used encoding formats at the time. For example, the Payload Type 34 corresponds to the H.263 video codec. More predefined values can be found in [RFC 3551](https://tools.ietf.org/html/rfc3551):

```
PT      encoding    media type  clock rate
        name                    (Hz)
_____________________________________________
24      unassigned  V
25      CelB        V           90,000
26      JPEG        V           90,000
27      unassigned  V
28      nv          V           90,000
29      unassigned  V
30      unassigned  V
31      H261        V           90,000
32      MPV         V           90,000
33      MP2T        AV          90,000
34      H263        V           90,000
35-71   unassigned  ?
72-76   reserved    N/A         N/A
77-95   unassigned  ?
96-127  dynamic     ?
dyn     H263-1998   V           90,000
```

Nowadays, instead of using a table of predefined numbers, applications can define their own Payload Types on the fly, and share them ad-hoc between senders and receivers of the RTP streams. These Payload Types are called dynamic, and are always chosen to be any number in the range [96-127].

An example: in a typical WebRTC session, Chrome might decide that the Payload Type 96 will correspond to the video codec VP8, PT 98 will be VP9, and PT 102 will be H.264. The receiver, after getting an RTP packet and inspecting the Payload Type field, will be able to know what decoder should be used to successfully handle the media.

- sequence number

This starts as an arbitrary random number, which then increments by one for each RTP data packet sent. Receivers can use these numbers to detect packet loss and to sort packets in case they are received out of order.

- timestamp

Again, this starts being an arbitrary random number, and then grows monotonically at the speed given by the media clock rate (defined by the Payload Type). Represents the instant of time when the media source was packetized into the RTP packet; the protocol doesn't use absolute timestamp values, but it uses differences between timestamps to calculate elapsed time between packets, which allows synchronization of multiple media streams (think lip sync between video and audio tracks), and also to calculate network latency and jitter.

- SSRC (Synchronization Source)

Another random number, it identifies the media track (e.g. one single video, or audio) that is being transmitted. Every individual media will have its own identifier, in the form of a unique SSRC shared during the RTP session. Receivers are able to easily identify to which media each RTP packet belongs by looking at the SSRC field in the packet header.

 




###  RTCP
The RTP Control Protocol (RTCP) is a sister protocol of the Real-time Transport Protocol (RTP). Its basic functionality and packet structure is defined in RFC 3550. RTCP provides out-of-band statistics and control information for an RTP session. It partners with RTP in the delivery and packaging of multimedia data, but does not transport any media data itself.  

[wiki - RTP Control Protocol](https://en.wikipedia.org/wiki/RTP_Control_Protocol)  
[RFC3550 - RTP: A Transport Protocol for Real-Time Applications](https://tools.ietf.org/html/rfc3550).    
[RTP (I): Intro to RTP and SDP](https://www.kurento.org/blog/rtp-i-intro-rtp-and-sdp)

RTP is typically transmitted over UDP, where none of the TCP reliability features are present. UDP favors skipping all the safety mechanisms, giving the maximum emphasis to reduced latency, even if that means having to deal with packet loss and other typical irregular behavior of networks, such as jitter.

As a means to provide some feedback to each participant in an RTP session, all of them should send Real-time Transport Control Protocol (RTCP) packets, containing some basic statistics about their part of the conversation. Peers that act as senders will send both RTP and RTCP Sender Reports, while peers that act as receivers will receive RTP and send RTCP Receiver Reports.


These RTCP packets are sent much less frequently than the RTP packets they accompany; typically we would see one RTCP packet per second, while RTP packets are sent at a much faster rate.

An RTCP packet contains very useful information about the stream:

SSRCs used by each media.
CNAME, an identifier that can be used to group several medias together.
Different timestamps, packet counts, and jitter estimations, from senders and receivers. These statistics can then be used by each peer to detect bad conditions such as packet loss.
Additionally, there is a set of optionally enabled extensions to the base RTCP format, that have been developed over time. These are called RTCP Feedback (RTCP-FB) messages, and can be transmitted from the receiver as long as their use has been previously agreed upon by all participants:

Google REMB is part of an algorithm that aims to adapt the sender video bitrate in order to avoid issues caused by network congestion. See Kurento | Congestion Control for a quick summary on this topic.
NACK is used by the receiver of a stream to inform the sender about packet loss. Upon receiving an RTCP NACK packet, the sender knows that it should re-send some of the RTP packets that were already sent before.
NACK PLI (Picture Loss Indication), a way that the receiver has to tell the sender about the loss of some part of video data. Upon receiving this message, the sender should assume that the receiver will not be able to decode further intermediate frames, and a new refresh frame should be sent instead. More information in RFC 4585.
CCM FIR (Full Intra Request), another method that the receiver has to let the sender know when a new full video frame is needed. FIR is very similar to PLI, but it's a lot more specific in requesting a full frame (also known as keyframe). More information in RFC 5104.
These extensions are most commonly found in WebRTC implementations, helping with packet loss and other network shenanigans. However, nothing prevents that a plain RTP endpoint implements any or all of these methods, like done by Kurento's RtpEndpoint.

These features might or might not be supported by both peers in an RTP session, and must be explicitly negotiated and enabled. This is typically done with the SDP negotiation, that we'll cover next.

 




### SDP 
The Session Description Protocol (SDP) is a format for describing multimedia communication sessions for the purposes of session announcement and session invitation.[1] Its predominant use is in support of streaming media applications, such as voice over IP (VoIP) and video conferencing. SDP does not deliver any media streams itself, but is used between endpoints for negotiation of network metrics, media types, and other associated properties. The set of properties and parameters are often called a session profile.

[wiki - Session_Description_Protocol](https://en.wikipedia.org/wiki/Session_Description_Protocol)  
[RFC4566 - SDP: Session Description Protocol](https://tools.ietf.org/html/rfc4566).    
[](https://www.kurento.org/blog/rtp-i-intro-rtp-and-sdp)

An SDP message, when generated by a participant in an RTP session, serves as an explicit description of the media that should be sent to it, from other remote peers. It's important to insist on this detail: in general (as like with everything, there are exceptions), the SDP information refers to what an RTP participant expects to receive.
Another way to put this is that an SDP message is a request for remote senders to send their data in the format specified by the message.

RFC 4566 contains the full description of all basic SDP fields. Other RFC documents were written to extend this basic format, mainly by adding new attributes (a= lines) that can be used in the media-level section of the SDP files. We'll introduce some of them as needed for our examples.



Example 1: Simplest SDP
This is an example of the most basic SDP message one can find:
```
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=video 5004 RTP/AVP 96
a=rtpmap:96 VP8/90000
```
It gets divided into two main sections:

First 5 lines are what is called the "session-level description":
```
v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
```
It describes things such as the peer's host IP address, time bases, and summary description. Most of these values are optional, so they can be set to zero (0) or empty strings with a dash (-).

Next comes the "media-level description", consisting of a line that starts with m= and any number of additional attributes (a=) afterwards:
```
m=video 5004 RTP/AVP 96
a=rtpmap:96 VP8/90000
```
In this example, the media-level description reads as follows:
- There is a single video track.
- 5004 is the local port where other peers should send RTP packets.
- 5005 is the local port where other peers should send RTCP packets. In absence of explicit mention, the RTCP port is always calculated as the RTP port + 1.
- RTP/AVP is the profile definition that applies to this media-level description. In this case it is RTP/AVP, as defined in RFC 3551.
- 96 is the expected Payload Type in the incoming RTP packets.
- VP8/90000 is the expected video codec and clock rate of the payload data, contained in the incoming RTP packets.
 

Example 2: Annotated SDP
SDP does not allow comments, but if it did, we could see one like this:
```
# Protocol version; always 0
v=0

# Originator and session identifier
o=jdoe 2890844526 2890842807 IN IP4 224.2.17.12

# Session description
s=SDP Example

# Connection information (network type and host address, like in 'o=')
c=IN IP4 224.2.17.12

# NTP timestamps for start and end of the session; can be 0
t=2873397496 2873404696

# First media: a video stream with these parameters:
# * The RTP port is 5004
# * The RTCP port is 5005 (implicitly by using RTP+1)
# * Adheres to the "RTP Profile for Audio and Video" (RTP/AVP)
# * Payload Type can be 96 or 97
m=video 5004 RTP/AVP 96 97

# Payload Type 96 encoding corresponds to VP8 codec
a=rtpmap:96 VP8/90000

# Payload Type 97 encoding corresponds to H.264 codec
a=rtpmap:97 H264/90000
```
In this example we can see how the media could be ambiguously defined to use multiple Payload Types (PT). PT is the number that identifies one set of encoding properties in the RTP packet header, including codec, codec settings, and other formats.




### SRTP  
The Secure Real-time Transport Protocol (SRTP) is a Real-time Transport Protocol (RTP) profile, intended to provide encryption, message authentication and integrity, and replay attack protection to the RTP data in both unicast and multicast applications.  

[Secure Real-time Transport Protocol](https://en.wikipedia.org/wiki/Secure_Real-time_Transport_Protocol).    
[RFC3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711)

The S in SRTP stands for Secure, which provides the missing feature in protocols described so far. RFC 3711 defines a method by which all RTP and RTCP packets can be transmitted in a way that keeps the audio or video payload from being captured and decoded by prying eyes. While plain RTP presents a mechanism to packetize and transmit media, it does not get into the matter of security; any attacker might be able to join an ongoing RTP session and snoop on the content being transmitted.

SRTP achieves its objectives by providing several protections:

Encrypts the media payload of all RTP packets. Note though that only the payload is protected, and RTP headers are unprotected. This allows for media routers and other tools to inspect the information present on the headers, maybe for distribution or statistics aggregation, while still protecting the actual media content.
Asserts that all RTP and RTCP packets are authenticated and come from the source where they purport to be coming.
Ensures the integrity of the entire RTP and RTCP packets, i.e. protecting against arbitrary modifications of the packet contents.
Prevents replay attacks, which are a specific kind of network attack where the same packet is duplicated and re-transmitted ("replayed") multiple times by a malicious participant, in an attempt to extract information about the cipher used to protect the packets. In essence, replay attacks are a form of "man-in-the-middle" attacks.
An important consequence of the encryption that SRTP provides is that it's still possible to inspect the network packets (e.g. by using Wireshark) and see all RTP header information. This proves invaluable when the need arises for debugging a failing stream!

This is the visualization of an RTP packet that has been protected with SRTP:

     (Bitmap)
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  \
     |V=2|P|X|  CC   |M|     PT      |       sequence number         |  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
     |                           timestamp                           |  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
     |           synchronization source (SSRC) identifier            |  |
     +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+  |
     |            contributing source (CSRC) identifiers             |  |-+
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | |
     |                   RTP extension (OPTIONAL)                    |  | |
  /  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | |
  |  |                          payload  ...                         |  | |
+-|  |                               +-------------------------------+  | |
| |  |                               | RTP padding   | RTP pad count |  | |
| \  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  / |
|    ~                     SRTP MKI (OPTIONAL)                       ~    |
|    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
|    :                 authentication tag (RECOMMENDED)              :    |
|    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
|                                                                         |
+---- Encrypted Portion                       Authenticated Portion ------+
For a full description of all fields, refer to the RFC documents at RFC 3550 (RTP) and RFC 3711 (SRTP).

 
 



###  ICE
Interactive Connectivity Establishment (ICE) is a technique used in computer networking to find ways for two computers to talk to each other as directly as possible in peer-to-peer networking. This is most commonly used for interactive media such as Voice over Internet Protocol (VoIP), peer-to-peer communications, video, and instant messaging. In such applications, you want to avoid communicating through a central server (which would slow down communication, and be expensive), but direct communication between client applications on the Internet is very tricky due to network address translators (NATs), firewalls, and other network barriers.  

[wiki: Interactive_Connectivity_Establishment](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment)  
[RFC5245: Interactive Connectivity Establishment (ICE): A Protocol for NAT Traversal for Offer/Answer Protocols](  https://tools.ietf.org/html/rfc5245).   
[RFC6544: TCP Candidates with Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc6544).  
[RFC8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal](https://tools.ietf.org/html/rfc6544)


### STUN 
Session Traversal Utilities for NAT (STUN) is a standardized set of methods, including a network protocol, for traversal of network address translator (NAT) gateways in applications of real-time voice, video, messaging, and other interactive communications. 

STUN is a tool used by other protocols, such as Interactive Connectivity Establishment (ICE), the Session Initiation Protocol (SIP), or WebRTC. It provides a tool for hosts to discover the presence of a network address translator, and to discover the mapped, usually public, Internet Protocol (IP) address and port number that the NAT has allocated for the application's User Datagram Protocol (UDP) flows to remote hosts. The protocol requires assistance from a third-party network server (STUN server) located on the opposing (public) side of the NAT, usually the public Internet.   

[wiki - STUN](https://en.wikipedia.org/wiki/STUN)  
[RFC 3489 - STUN - Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs)](  https://tools.ietf.org/html/rfc3489).   
[RFC5389 - Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389).   
[RFC5389_NAT 的会话穿透用法 (STUN)](rfc-chinese/RFC5389_NAT的会话穿透用法(STUN).pdf)  
[P2P技术简介-NAT（ Network Address Translation）穿越（俗称打洞）技术](https://www.cnblogs.com/vc60er/p/6916190.html)  

### TURN   
Traversal Using Relays around NAT (TURN) is a protocol that assists in traversal of network address translators (NAT) or firewalls for multimedia applications. It may be used with the Transmission Control Protocol (TCP) and User Datagram Protocol (UDP). It is most useful for clients on networks masqueraded by symmetric NAT devices. TURN does not aid in running servers on well known ports in the private network through a NAT;   

[wiki - Traversal_Using_Relays_around_NAT](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT)  
[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](  https://tools.ietf.org/html/rfc5766).  

### DTLS 
Datagram Transport Layer Security. DTLS is used to secure all data transfers between peers; encryption is a mandatory feature of WebRTC.

[wiki: Datagram_Transport_Layer_Security](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)  
[RFC6347 - Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347)  



### SCTP  
Stream Control Transport Protocol. 

SCTP as a protocol can be seen as a hybrid of UDP and TCP.

At its core, SCTP holds the following characteristics:

Connection oriented. Similar to TCP, SCTP is connection oriented. It also offers a multi-homing capability that isn’t used by WebRTC
Optional reliability. Reliability is optional in SCTP and is up to the implementer using SCTP to decide if he needs this capability or not
Optional ordering. Ordering of packets sent via SCTP is optional and is left for the implementer to decide if this is necessary for him or not
Message oriented. SCTP makes sure that each message sent is properly parsed on the receiver end in the same manner in which it was sent
Flow control. Similar to TCP, SCTP provides a flow control mechanism that makes sure the network doesn’t get congested
SCTP is not implemented by all operating systems. In such cases, an application level implementation of SCTP will usually be used.

SCTP is used in WebRTC for the implementation and delivery of the Data Channel.

Google is experimenting with the QUIC protocol as a future replacement to SCTP.

SCTP is designed to transport Public Switched Telephone Network (PSTN) signaling messages over IP networks, but is capable of broader applications.

[RFC4960 - Stream Control Transmission Protocol](https://tools.ietf.org/html/rfc4960)


### RTMP
TCP-based protocol which maintains persistent connections and allows low-latency communication.  
[wiki - Real-Time Messaging Protocol](https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol)

### RTSP
While similar in some ways to HTTP, RTSP defines control sequences useful in controlling multimedia playback. While HTTP is stateless, RTSP has state; an identifier is used when needed to track concurrent sessions. Like HTTP, RTSP uses TCP to maintain an end-to-end connection and, while most RTSP control messages are sent by the client to the server, some commands travel in the other direction (i.e. from server to client).  

[wiki - https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol](https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol)

### HLS
HTTP Live Streaming (also known as HLS) is an HTTP-based adaptive bitrate streaming communications protocol developed by Apple Inc.

[wiki - HTTP Live Streaming](https://en.wikipedia.org/wiki/HTTP_Live_Streaming)

### DASH
Dynamic Adaptive Streaming over HTTP (DASH), also known as MPEG-DASH, is an adaptive bitrate streaming technique that enables high quality streaming of media content over the Internet delivered from conventional HTTP web servers. 

[wiki: Dynamic Adaptive Streaming over HTTP (DASH)](https://en.wikipedia.org/wiki/Dynamic_Adaptive_Streaming_over_HTTP)

https://juejin.im/post/5a697868f265da3e3f4ce17d

## 容器
### mp4     
MPEG-4 Part 14 or MP4 is a digital multimedia container format most commonly used to store video and audio, but it can also be used to store other data such as subtitles and still images.[2] Like most modern container formats, it allows streaming over the Internet. The only official filename extension for MPEG-4 Part 14 files is .mp4. MPEG-4 Part 14 (formally ISO/IEC 14496-14:2003) is a standard specified as a part of MPEG-4.  

[wiki - MPEG-4_Part_14](https://en.wikipedia.org/wiki/MPEG-4_Part_14)


### ts  
MPEG transport stream (transport stream, MPEG-TS, MTS or TS) is a standard digital container format for transmission and storage of audio, video, and Program and System Information Protocol (PSIP) data.[3] It is used in broadcast systems such as DVB, ATSC and IPTV.

Transport stream specifies a container format encapsulating packetized elementary streams, with error correction and synchronization pattern features for maintaining transmission integrity when the communication channel carrying the stream is degraded.

Transport streams differ from the similarly-named MPEG program stream in several important ways: program streams are designed for reasonably reliable media, such as discs (like DVDs), while transport streams are designed for less reliable transmission, namely terrestrial or satellite broadcast. Further, a transport stream may carry multiple programs.

[wiki - MPEG transport stream](https://en.wikipedia.org/wiki/MPEG_transport_stream)


## 传输控制
### GCC
[A Google Congestion Control Algorithm for Real-Time Communication draft-ietf-rmcat-gcc-02](https://tools.ietf.org/html/draft-ietf-rmcat-gcc-02)  
[A Google Congestion Control Algorithm for Real-Time Communication draft-alvestrand-rmcat-congestion-03](https://tools.ietf.org/html/draft-alvestrand-rmcat-congestion-03)
[WebRTC GCC翻译和理解](https://zhuanlan.zhihu.com/p/87622467)
[小议WebRTC拥塞控制算法：GCC介绍](http://yunxin.163.com/blog/video18-0905/)  
[WebRTC-GCC两种实现方案对比](https://www.freehacker.cn/media/tcc-vs-gcc/)  
[WebRTC拥塞控制策略](https://www.freehacker.cn/media/webrtc-gcc/)  
[Analysis and Design of the Google Congestion Control for Web Real-time Communication (WebRTC)](https://c3lab.poliba.it/images/6/65/Gcc-analysis.pdf)

**发送端基于丢包的码率控制：**

通过接收端反馈的丢包率信息计算码率，计算公式如下：

todo

1. 丢包率>0.1：上次码率乘以（1-0.5*丢包率）
2. 丢包率<0.02：1.05倍的上次码率
3. 其他：上次码率


**接收端基于延迟的码率控制：**

根据调制策略，已经测量码率来计算码率，计算公式如下：

todo

1. normal：1.05倍的上次码率
2. overuse：0.85倍测量码率（最近500ms）
3. underuse：上次码率


**最终码率计算**

发送端收到接收端预估码率Ar后，根据发送端预估码率As(tk)、接收端预估Ar(tk)、最大允许码率Amax最小允许码率Amin，计算出最终的发送码率Rs(tk)

Rs(tk)=max(min(min(As(tk),Ar(tk)),Amax),Amin)



**基于延迟的码率控制包含五个模块：**


1. Arrival-time Filter

Arrival-time Filter模块用来计算网络延迟m(t[i])，GCC算法采用Kalman Filter来估算该值。Kalman Filter采用单程帧间延迟差值dm(ti)，单程帧间延迟差值表示两个数据帧到达接收端的延迟差值。

dm(t[i])=(t[i]−t[i−1])−(T[i]−T[i−1])

单程帧间延迟差值：相邻两个包，接收时间的差值减去发送时间的差值


dm(t[i]) = m(t[i]) + v(t[i])

v(t[i])： t[i]时刻的噪声

由于dm(t[i])是实际的测量值，包含噪声数据，可以通过Kalman Filter过滤掉噪声，估算到相对稳定的m(t[i])值



2. Adaptive Threshold

Adaptive Threshold模块用来使算法适应延迟变化的灵敏性。输出阀值γ


todo


3. Overuse Detector

Overuse Detector根据Arrival-time Filter计算出的网络延时m(ti)，以及Adaptive Threshold提供的γ(ti)值来判断当前网络是否过载，并告知Remote Rate Controller对应的信号s——overuse、normal、underuse。

- overuse: m(ti) > γ(ti) and keep 100ms
- underuse: m(ti) < -γ(ti) and keep 100ms
- normal: -γ(ti) < m(ti) < γ(ti)


4. Remote Rate Controller

根据过载检测的信号，以及接收端预估码率，来计算新的预估码率

- 当s=normal，预估码率上升为上次预估码率的105%，处于increase状态。
- 当s=overuse，预估码率降低为接收码率的85%，处于decrease状态;
- 当s=underuse，预估码率保持和上次预估码率一样，处于hold状态；



5. Remb Processing

通过RTCP REMB报文通知发送端来自接收端预估的码率

该报文每隔1s发送一次，但如果Ar(t[i]) < 0.97Ar(t[i−1])，该报文立马发送



**卡尔曼滤波（Kalman Filter）**

卡尔曼滤波本质上是一个优化算法，只要观测数据与隐藏的状态数据有关联，就可以根据观测数据计算出最小均方意义下的隐藏状态量的最优估计值。


[如何通俗并尽可能详细地解释卡尔曼滤波？](https://www.zhihu.com/question/23971601/answer/46480923)




发送端使用*基于丢包*的用塞控制算法（LBCC），接收端使用*基于延迟*的用塞控制算法（DBCC），在通过rtcp通知给发送端，发送端使用两者的最小值

- *基于丢包*的用塞控制算法（LBCC）
   

- *基于延迟*的用塞控制算法（DBCC）

1. 预先滤波
2. 到达时间滤波
3. 自适应门限
4. 过载检测
5. 速率控制器
6. pace队列





### PCC
[PCC: Performance-oriented Congestion Control](https://modong.github.io/pcc-page/)
(https://www.usenix.org/conference/nsdi18/presentation/dong)
核心思想是选择合适的发送速率，不断的调整发送速率，并根据接收端的反馈计算网络效能(u=f(吞吐，丢包率，延迟..)).
增加速率如果，网络网络效能增加，则继续增加，如果减少发送速率

1. 起始状态
2. 决策状态
3. 速率调节状态







### BBR
BBR一开始是针对TCP的拥塞控制提出来的。它的输入为ACK/SACK，输出为拥塞窗口(congestion_window)发送速度(pacing_rate)。  
[BBR: Congestion-Based Congestion Control](https://queue.acm.org/detail.cfm?id=3022184)  
[来自Google的TCP BBR拥塞控制算法解析](https://blog.csdn.net/dog250/article/details/52830576)  
[TCP BBR拥塞控制算法解析](https://blog.csdn.net/ebay/article/details/76252481)  
[Linux Kernel 4.9 中的 BBR 算法与之前的 TCP 拥塞控制相比有什么优势](https://www.zhihu.com/question/53559433)  
[一文解释清楚GOOGLE BBR拥塞控制算法原理](https://www.taohui.pub/2019/08/07/%e4%b8%80%e6%96%87%e8%a7%a3%e9%87%8a%e6%b8%85%e6%a5%9agoogle-bbr%e6%8b%a5%e5%a1%9e%e6%8e%a7%e5%88%b6%e7%ae%97%e6%b3%95%e5%8e%9f%e7%90%86/)  
[BBR及其在实时音视频领域的应用](https://mp.weixin.qq.com/s/8Hy5SBWXzhZ2X4YnjFflJw)  


https://www.youtube.com/watch?v=mnvuqLipNhg


以最大吞吐量，最小延迟为目标，通过估计瓶颈带宽和rtt来计算发包速率
1. startup: 通过增加发送速率估计瓶颈带宽，当瓶颈带宽不在增加时，该值即为最终的瓶颈带宽。发送端根据给定时间内收到的接收端应答包数据量来估算瓶颈带宽
2. drain：降低速率发送完，缓冲区中待发送的数据
3. probe_bw：增加瓶颈带宽下的发送速率，如果瓶颈带宽不增加，则使用之前的瓶颈带宽
4. probe_rtt：通过最小滤波得到rtt值，当缓存过满时，减少发送速率




### NACK
[wiki: Acknowledgement (data networks)](https://en.wikipedia.org/wiki/Acknowledgement_(data_networks))  
[RFC4588 - RTP Retransmission Payload Format](https://tools.ietf.org/html/rfc4588)  
[LearningWebRTC: NACK(Negative ACKnowledgement)](https://xjsxjtu.github.io/2017-07-16/LearningWebRTC-nack/)  


### QUIC
[wiki - QUIC](https://en.wikipedia.org/wiki/QUIC)  
[Official Google description:](https://www.chromium.org/quic)  
[Inofficial standalone library maintained by official QUIC developers](https://github.com/google/proto-quic)  
[Good introduction read-up with comment from Jim Roskind (QUIC architect)](https://ma.ttias.be/googles-quic-protocol-moving-web-tcp-udp/)



### ARQ
[Automatic repeat request](https://en.wikipedia.org/wiki/ARQ_(film))  
[重要的事情说三遍：ARQ协议](https://sexywp.com/introduction-of-arq.htm)  

**停止并等待 ARQ（Stop-and-wait ARQ）**

逐个发送，收到确认后发送下一个，长时间无确认，会重发

	问题:  
	在网络差的情况下，发送发迟迟没有收到确认包，可能会重发原始包，但是接收方有可能收到两次发送的相同包，这种情况下，接收方不容易判断，接收到的第二包是新包，还是重发包。
	
	解决办法:  
	对每个包前增加一个bit为，交替存储010101标志，如果接收到的包和上次收到包具有相同的头标志，则说明是重复包

**后退N帧 ARQ（Go-Back-N ARQ）**

按照窗口大小一次性发送，并且每个包添加序号；接收方，按照序号收包，发送确认，如果遇到乱序的则丢弃后续所有包。发送方再次从收到的确认包的最后一个的下一个开始发送数据

	问题:
	一次丢包后会造成多次重发包

**选择性重发/拒绝 ARQ (Selective Repeat/Reject ARQ）**

todo



### NetEQ

包括以下部分：

1. 自适应抖动缓冲区，
2. 丢包隐藏（或者叫丢包重建：插入静音爆、近似包），
3. 播放控制（正常，快播，慢播放），

网络抖动的的定义：

	定义1. 由于这种延迟的变化导致网络中数据分组到达速率的变化</br>
	定义2. 接收端某个数据包到达时间间隔与平均数据包到达时间间隔之差定义为该数据包的延迟抖动

1. 自适应抖动缓冲区</br>
   缓冲区的大小随着网络的变化而变化，
   优点是网络抖动较大时丢包率较低，而网络抖动较小时，语音延迟相对较小

2. 丢包隐藏</br>
   基本原理是产生一个与丢失包近似的语音包代替
   - 发送端
      - 交织
      - 前向纠错
      - 重传
   - 接收端
      - 插入法：插入静音爆，噪音包，或者重复前面的包
      - 插值法：使用模式匹配或者插值技术，期望得到原来包近似的替代包
      - 重构法：通过丢失包前后的编码信息重建一个补偿包，（ilibc）

3. 播放控制</br>


### synchronize




### FEC 
[LearningWebRTC: FEC(Forward Error Correction)](https://xjsxjtu.github.io/2017-07-16/LearningWebRTC-fec/)  
[RTP Payload Format for Flexible Forward Error Correction (FEC) - draft-ietf-payload-flexible-fec-scheme-05](https://tools.ietf.org/html/draft-ietf-payload-flexible-fec-scheme-05)  
[RFC 5109 - RTP Payload Format for Generic Forward Error Correction](https://tools.ietf.org/html/rfc5109)  



### RS 
[Reed Solomon纠删码](https://www.cnblogs.com/vc60er/p/4475026.html)


## 语音增强  
### AEC
[LearningWebRTC: AECM](https://xjsxjtu.github.io/2017-07-05/LearningWebRTC-apm_aecm/)
### NS
### AGC
### VAD 





## 视频编码器
### H.264/avc 
[wiki - Advanced Video Coding](https://en.wikipedia.org/wiki/Advanced_Video_Coding)  
[digital_video_introduction](https://github.com/leandromoreira/digital_video_introduction/blob/master/README-cn.md)   
[codec-h264](  https://www.freehacker.cn/media/codec-h264/)  
[rfc6184 - RTP Payload Format for H.264 Video](https://tools.ietf.org/html/rfc6184)  
[rfc6190 - RTP Payload Format for Scalable Video Coding](https://tools.ietf.org/html/rfc6190)  
<https://zhuanlan.zhihu.com/p/71928833>

**编码过程**

- 转yuv。  
人眼对亮度更加敏感

- 分区   
将帧分成几个分区，子分区甚至更多，<br>
在微小移动的部分使用较小的分区，而在静态背景上使用较大的分区。<br>

- 预测   
找到帧 1 和 帧 0 上的块相匹配。我们可以将这看作是运动预测。找不到的当作残差<br>
一旦我们有了分区，我们就可以在它们之上做出预测。</br>
对于帧间预测，输出**运动向量**和**残差**；</br>
至于帧内预测，输出**预测方向**和**残差**。</br>

- 转换   
在我们得到残差块（预测分区-真实分区）之后，使用离散余弦变换（DCT），将像素块转换成频率系数块，丢弃部分高频部分 

	离散余弦变换（DCT）的主要功能有：</br>
	- 将像素块转换为相同大小的频率系数块。  
	- 可逆的，也意味着你可以还原回像素。  
	- 高频部分和低频部分是分离的，压缩能量，更容易消除空间冗余。  


- 量化   
量化系数块中的数据以实现压缩。<br>
我们选择性地剔除信息（有损部分）或者简单来说，我们将除以单个的值（10），并舍入值<br>

- 墒编码.  
VLC 编码

- 比特流格式.  
AVC (H.264) 标准规定信息将在宏帧（网络概念上的）内传输，称为 NAL（网络抽象层）


nal类型

SPS，这个类型的 NAL 负责传达通用编码参数，如配置，层级，分辨率等



帧类型

- I 帧（帧内编码，关键帧）
I 帧（可参考，关键帧，帧内编码）是一个自足的帧。它不依靠任何东西来渲染，I 帧与静态图片相似。第一帧通常是 I 帧，但我们将看到 I 帧被定期插入其它类型的帧之间。

- P 帧（预测
P 帧利用了一个事实：当前的画面几乎总能使用之前的一帧进行渲染。例如，在第二帧，唯一的改变是球向前移动了。仅仅使用（第二帧）对前一帧的引用和差值，我们就能重建前一帧。


- B 帧（双向预测）


空间冗余（帧内预测）





### h.265/hevc

- 更大更多分区（和子分区）
- 帧内预测方向，改进的熵编码


### vp8


### SVC (可伸缩视频编码)

[SVC和视频通信](https://www.zego.im/article/2018/03/07/svc%e5%92%8c%e8%a7%86%e9%a2%91%e9%80%9a%e4%bf%a1/)  
[在Google Chrome WebRTC中分层蛋糕式的VP9 SVC](https://www.zego.im/article/2018/02/26/%E5%9C%A8google-chrome-webrtc%E4%B8%AD%E5%88%86%E5%B1%82%E8%9B%8B%E7%B3%95%E5%BC%8F%E7%9A%84vp9-svc/)  
[姜健：VP9可适性视频编码（SVC）新特性](https://mp.weixin.qq.com/s/PN91H_bFQ2X_ySiMGxGK5A?utm_source=tuicool&utm_medium=referral)  
[H264 SVC：从编码到RTP打包](https://xjsxjtu.github.io/2017-06-24/H264-SVC/)  
[H.264 SVC](https://www.cnblogs.com/huxiaopeng/p/5653310.html)  







### x264编码器参数 
[H.264 Video Encoding Guide](https://trac.ffmpeg.org/wiki/Encode/H.264)  
[x264参数中文详解（X264 Settings）](https://www.cnblogs.com/lihaiping/p/4037470.html)  
[H264编码常用参数整理](https://blog.csdn.net/yuangc/article/details/86678247)  
[FFmpeg使用X264编码参数](http://blog.gqylpy.com/gqy/22748/)  
[ffmpeg与H264编码指南](https://www.cnblogs.com/tocy/p/ffmpeg_h264_encode_guide.html)  
[(转)x264参数中文详解（X264 Settings）](https://www.cnblogs.com/lihaiping/p/4037470.html)  



## 颜色空间
RGB 用于计算机图形学中
YIQ，YUV，YCrCb用于视频系统
CMYK 用于彩色打印机


### gamma校准
大多数CRT显示器的变换函数产生的亮度值正比于信号幅度的某种能量（称为gamma），对信号进行gamma校准，是为了显示器的亮度输出就差不多是线性的。<br>

CRT显示关系是非线性，典型的CRT显示器的伽马曲线大致是一个伽马值为2.5的幂律曲线。显示器的这类伽马也称为display gamma，<br>
由于这个问题的存在，那么图像捕捉设备就需要进行一个伽马校正，它们使用的伽马叫做encoding gamma。所以，一个完整的图像系统需要2个伽马值：<br>

- encoding gamma：它描述了encoding transfer function，即图像设备捕捉到的场景亮度值（scene radiance values）和编码的像素值（encoded pixel values）之间的关系。
- display gamma：它描述了display transfer function，即编码的像素值和显示的亮度（displayed radiance）之间的关系。
如下图所示

(https://img-blog.csdn.net/20150529135720109)
而encoding gamma和display gamma的乘积就是真个图像系统的end-to-end gamma。如果这个乘积是1，那么显示出来的亮度就是和捕捉到的真实场景的亮度是成比例的。


[我理解的伽马校正](https://blog.csdn.net/candycat1992/article/details/46228771)

gamma校准的RGB，表示为R‘G’B‘
R ́ = R1/2.8 G ́ = G1/2.8 B ́ = B1/2.8

### RGB

### YUV
YUV是三大复合颜色视频标准（PAL,NTSC,SECAM）所采用的颜色空间，黑白系统使用亮度（Y）信息，颜色信息（U和V）以一种特定的方式加入，使得黑背电视机同样可以显示标准的黑白图像，而彩色电视机对额外的彩色信息进行解码从而显示彩色信息<br>

Y取之范围0～255，U取之范围0～+-122，V取之范围0～+-157<br>

[视频像素格式YUV和RGB](https://www.freehacker.cn/media/codec-yuv-rgb/)  
[视频像素格式](https://wikipedia.freehacker.cn/auvi/video-pixel-format.html)  
[[翻译]H.264 探索 第一部分 色彩模型](https://segmentfault.com/a/1190000006695679)  


### YCrCb
YCrCb颜色空间是YUV颜色空间缩放和编译版本，Y定义为具有8位，标准颜色表示范围为16～235，Cb和Cr标称颜色表示范围定义为16～240，




## 音频编码器
### iLBC
[Internet Low Bitrate Codec](https://en.wikipedia.org/wiki/Internet_Low_Bitrate_Codec)

### ACC
[Advanced Audio Coding](https://en.wikipedia.org/wiki/Advanced_Audio_Coding)

### opus 
Opus是一个混合编码器，由SILK和CELT两种编码器混合而成，SILK主要负责wideband(8khz)以下的语音编码，CELT主要负责高频编码，如音乐等。    
[wiki - Opus (audio format)](https://en.wikipedia.org/wiki/Opus_(audio_format))  
[RFC7587 - RTP Payload Format for the Opus Speech and Audio Codec](https://tools.ietf.org/html/rfc7587)  
[RFC6716 - Definition of the Opus Audio Codec](https://tools.ietf.org/html/rfc6716)  




## 智能视频封面

**帧过滤：**

要过滤的帧包括低质帧与过渡帧。低质的衡量标准包括亮度、清晰度以及色彩单一度，满足一定阈值(经验值)要求方可保留。<br>
过渡帧的识别可以转化为另一个视频任务:分镜头边界检测(shot boundary detection)<br>

**关键帧提取（关键内容，与视频最相关的帧）：**

对帧做聚类, 比如k-means或者k-medoids。然后将(邻近)聚类中心的帧作为关键帧

**美学分数：**

颜色方面：主要是HSV统计量，如平均HSV, 中央平均HSV, HSV颜色直方图，HSV对比度，以及对比度，Pleasure, Arousel, Dominance.<br>
纹理方面：则是基于Haralick特征, 包括Entropy, Energy, Homogeneity, GLCM。<br>
基础质量：方面考察了四个维度，包含对比度平衡、曝光平衡、JPEG质量以及全局清晰度<br>
构图方面：则是三分法则、对称构图及原创性(Uniqueness， 这个有点虚).<br>



## 工具



## 资源
- [webrtc-architecture-protocols](https://princiya777.wordpress.com/2017/08/19/webrtc-architecture-protocols)
- [webrtcglossary.com](https://webrtcglossary.com/)
- [实时语音处理实战 - 实战指南]

