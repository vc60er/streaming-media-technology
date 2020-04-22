# streaming-media-technology

## 协议
- RTP.  
[RFC3550 - RTP: A Transport Protocol for Real-Time Applications](https://tools.ietf.org/html/rfc3550).  
[RFC3551 - RTP Profile for Audio and Video Conferences with Minimal Control](https://tools.ietf.org/html/rfc3551).  
[RFC3611 - RTP Control Protocol Extended Reports (RTCP XR)](https://tools.ietf.org/html/rfc3611).  
[RFC4585 - Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF) ](https://tools.ietf.org/html/rfc4585).  
[RFC5124 - Extended Secure RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/SAVPF) ](https://tools.ietf.org/html/rfc5124).  
[RFC7741 - RTP Payload Format for VP8 Video](https://tools.ietf.org/html/rfc7741).  
[RFC6184 - RTP Payload Format for H.264 Video](https://tools.ietf.org/html/rfc6184).  
[RFC 5450 - Transmission Time Offsets in RTP Streams](https://tools.ietf.org/html/rfc5450).  
[RFC 5104 - Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF) ](https://tools.ietf.org/html/rfc5104).  

- RTCP: is defined in IETF RFC 3550. It is used alongside RTP.
	
	RTCP offers a lightweight control mechanism for RTP that can be used to send statistic reports and flow control messages.   
	
	These main two uses enable the receiver to provide feedback to the sender who can then deduce the network’s status and accommodate to it (by changing the bitrate or adding FEC).

- ICE: Interactive Connectivity Establishment.  
[RFC 5245 - Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal for Offer/Answer Protocols](https://tools.ietf.org/html/rfc5245).   

- STUN: Session Traversal Utilities for Network Address Translation (NAT).  
[RFC 3489 - STUN - Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs)](https://tools.ietf.org/html/rfc3489).   
[RFC 5389 - Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389).   
[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766). 

- TURN: Traversal Using Relays around NAT
[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766).  
- SDP: Session Description Protocol.  
[rfc4566 - SDP: Session Description Protocol](https://tools.ietf.org/html/rfc4566).  
- DTLS: Datagram Transport Layer Security
- SCTP: Stream Control Transport Protocol
- SRTP: Secure Real-Time Transport Protocol.  
[RFC3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711)

- ICE, STUN, and TURN are necessary to establish and maintain a peer-to-peer connection over UDP.
- DTLS is used to secure all data transfers between peers; encryption is a mandatory feature of WebRTC.

- SCTP and SRTP are the application protocols used to multiplex the different streams, provide congestion and flow control, and provide partially reliable delivery and other additional services on top of UDP.  

- SDP: Session Description Protocol (SDP) is a data format used to negotiate the parameters of the peer-to-peer connection. However, the SDP “offer” and “answer” are communicated out of band, which is why SDP is missing from the protocol diagram.  


- RTMP:
- RTSP:
- HLS:
- dash:



## 视频编码器
- H.264/avc
- h.265/hevc
- vp8

## 音频编码器
- iLBC
- acc

## 语音增强
- AEC
- NS

## 网络容错
- FEC
- jitter
- synchronize



## 参考
- [digital_video_introduction](https://github.com/leandromoreira/digital_video_introduction/blob/master/README-cn.md)
- [webrtc-architecture-protocols](https://princiya777.wordpress.com/2017/08/19/webrtc-architecture-protocols)
- [webrtcglossary.com](https://webrtcglossary.com/)




