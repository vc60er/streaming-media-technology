# 流媒体技术手册

## 协议
- RTP:   
	The Real-time Transport Protocol (RTP) is a network protocol for delivering audio and video over IP networks. RTP is used in communication and entertainment systems that involve streaming media, such as telephony, video teleconference applications including WebRTC, television services and web-based push-to-talk features.  
	
	RTP typically runs over User Datagram Protocol (UDP). RTP is used in conjunction with the RTP Control Protocol (RTCP). While RTP carries the media streams (e.g., audio and video), RTCP is used to monitor transmission statistics and quality of service (QoS) and aids synchronization of multiple streams. RTP is one of the technical foundations of Voice over IP and in this context is often used in conjunction with a signaling protocol such as the Session Initiation Protocol (SIP) which establishes connections across the network.  
[wiki: Real-time Transport Protocol](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol).  
[RFC3550 - RTP: A Transport Protocol for Real-Time Applications](https://tools.ietf.org/html/rfc3550).  
[RFC3551 - RTP Profile for Audio and Video Conferences with Minimal Control](https://tools.ietf.org/html/rfc3551).  
[RFC3611 - RTP Control Protocol Extended Reports (RTCP XR)](https://tools.ietf.org/html/rfc3611).  
[RFC4585 - Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF) ](https://tools.ietf.org/html/rfc4585).  
[RFC5124 - Extended Secure RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/SAVPF) ](https://tools.ietf.org/html/rfc5124).  
[RFC7741 - RTP Payload Format for VP8 Video](https://tools.ietf.org/html/rfc7741).  
[RFC6184 - RTP Payload Format for H.264 Video](https://tools.ietf.org/html/rfc6184).  
[RFC 5450 - Transmission Time Offsets in RTP Streams](https://tools.ietf.org/html/rfc5450).  
[RFC 5104 - Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF) ](https://tools.ietf.org/html/rfc5104).  

- RTCP: The RTP Control Protocol (RTCP) is a sister protocol of the Real-time Transport Protocol (RTP). Its basic functionality and packet structure is defined in RFC 3550. RTCP provides out-of-band statistics and control information for an RTP session. It partners with RTP in the delivery and packaging of multimedia data, but does not transport any media data itself.  
[RFC3550 - RTP: A Transport Protocol for Real-Time Applications](https://tools.ietf.org/html/rfc3550).  

- ICE: Interactive Connectivity Establishment.  
[wiki: Interactive_Connectivity_Establishment](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment)
[RFC 5245: Interactive Connectivity Establishment (ICE): A Protocol for NAT Traversal for Offer/Answer Protocols](https://tools.ietf.org/html/rfc5245).   
[RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc6544).  
[RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal](https://tools.ietf.org/html/rfc6544)



- STUN: Session Traversal Utilities for Network Address Translation (NAT).  
[RFC 3489 - STUN - Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs)](https://tools.ietf.org/html/rfc3489).   
[RFC 5389 - Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389).   
[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766). 

- TURN: Traversal Using Relays around NAT
[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766).  

- SDP: Session Description Protocol (SDP) is a data format used to negotiate the parameters of the peer-to-peer connection. However, the SDP “offer” and “answer” are communicated out of band, which is why SDP is missing from the protocol diagram.  
[wiki - Session_Description_Protocol](https://en.wikipedia.org/wiki/Session_Description_Protocol)   
[RFC 4566 - SDP: Session Description Protocol](https://tools.ietf.org/html/rfc4566).  

- DTLS: Datagram Transport Layer Security. DTLS is used to secure all data transfers between peers; encryption is a mandatory feature of WebRTC.
[wiki: Datagram_Transport_Layer_Security](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)   
[RFC 6347 - Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347)    


- SCTP: Stream Control Transport Protocol. SCTP is designed to
   transport Public Switched Telephone Network (PSTN) signaling messages
   over IP networks, but is capable of broader applications.
[RFC 4960 - Stream Control Transmission Protocol](https://tools.ietf.org/html/rfc4960)

- SRTP: Secure Real-Time Transport Protocol.  
[RFC3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711)


- ICE, STUN, and TURN are necessary to establish and maintain a peer-to-peer connection over UDP.

- SCTP and SRTP are the application protocols used to multiplex the different streams, provide congestion and flow control, and provide partially reliable delivery and other additional services on top of UDP.  


- RTMP: RTMP is a TCP-based protocol which maintains persistent connections and allows low-latency communication. 
[wiki - Real-Time Messaging Protocol](https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol)

- RTSP: While similar in some ways to HTTP, RTSP defines control sequences useful in controlling multimedia playback. While HTTP is stateless, RTSP has state; an identifier is used when needed to track concurrent sessions. Like HTTP, RTSP uses TCP to maintain an end-to-end connection and, while most RTSP control messages are sent by the client to the server, some commands travel in the other direction (i.e. from server to client).   
[wiki - https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol](https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol)  

- HLS: HTTP Live Streaming (also known as HLS) is an HTTP-based adaptive bitrate streaming communications protocol developed by Apple Inc. 
[wiki - HTTP Live Streaming](https://en.wikipedia.org/wiki/HTTP_Live_Streaming)  

- DASH: Dynamic Adaptive Streaming over HTTP (DASH), also known as MPEG-DASH, is an adaptive bitrate streaming technique that enables high quality streaming of media content over the Internet delivered from conventional HTTP web servers.   
[wiki: ynamic Adaptive Streaming over HTTP (DASH)](https://en.wikipedia.org/wiki/Dynamic_Adaptive_Streaming_over_HTTP)


## 容器
- mp4
- ts


## 视频编码器
- H.264/avc
[digital_video_introduction](https://github.com/leandromoreira/digital_video_introduction/blob/master/README-cn.md)
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




