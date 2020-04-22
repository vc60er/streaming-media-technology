# 流媒体技术手册

## 协议
- **RTP**   
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
	[RFC3550-RTP协议](rfc-chinese/RFC3550-RTP协议.pdf)     
	[RFC3550-RTP应用于实时应用的传输协议](rfc-chinese/RFC3550-RTP应用于实时应用的传输协议.pdf)     

- **RTCP**  
	The RTP Control Protocol (RTCP) is a sister protocol of the Real-time Transport Protocol (RTP). Its basic functionality and packet structure is defined in RFC 3550. RTCP provides out-of-band statistics and control information for an RTP session. It partners with RTP in the delivery and packaging of multimedia data, but does not transport any media data itself.  
	
	[wiki - RTP Control Protocol](https://en.wikipedia.org/wiki/RTP_Control_Protocol)   
	[RFC3550 - RTP: A Transport Protocol for Real-Time Applications](https://tools.ietf.org/html/rfc3550).  

- **ICE**  
	Interactive Connectivity Establishment (ICE) is a technique used in computer networking to find ways for two computers to talk to each other as directly as possible in peer-to-peer networking. This is most commonly used for interactive media such as Voice over Internet Protocol (VoIP), peer-to-peer communications, video, and instant messaging. In such applications, you want to avoid communicating through a central server (which would slow down communication, and be expensive), but direct communication between client applications on the Internet is very tricky due to network address translators (NATs), firewalls, and other network barriers.  

	[wiki: Interactive_Connectivity_Establishment](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment)
	[RFC 5245: Interactive Connectivity Establishment (ICE): A Protocol for NAT Traversal for Offer/Answer Protocols](https://tools.ietf.org/html/rfc5245).   
	[RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc6544).  
	[RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal](https://tools.ietf.org/html/rfc6544)



- **STUN**   
	Session Traversal Utilities for NAT (STUN) is a standardized set of methods, including a network protocol, for traversal of network address translator (NAT) gateways in applications of real-time voice, video, messaging, and other interactive communications. 

	STUN is a tool used by other protocols, such as Interactive Connectivity Establishment (ICE), the Session Initiation Protocol (SIP), or WebRTC. It provides a tool for hosts to discover the presence of a network address translator, and to discover the mapped, usually public, Internet Protocol (IP) address and port number that the NAT has allocated for the application's User Datagram Protocol (UDP) flows to remote hosts. The protocol requires assistance from a third-party network server (STUN server) located on the opposing (public) side of the NAT, usually the public Internet.   

	[wiki - STUN](https://en.wikipedia.org/wiki/STUN)
	[RFC 3489 - STUN - Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs)](https://tools.ietf.org/html/rfc3489).   
	[RFC 5389 - Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389).   
	[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766).   
	[RFC5389_NAT 的会话穿透用法 (STUN)](rfc-chinese/RFC5389_NAT的会话穿透用法(STUN).pdf)   

- **TURN**.   
	Traversal Using Relays around NAT (TURN) is a protocol that assists in traversal of network address translators (NAT) or firewalls for multimedia applications. It may be used with the Transmission Control Protocol (TCP) and User Datagram Protocol (UDP). It is most useful for clients on networks masqueraded by symmetric NAT devices. TURN does not aid in running servers on well known ports in the private network through a NAT;   

	[wiki - Traversal_Using_Relays_around_NAT](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT)
	[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766).  

- **SDP**   
	The Session Description Protocol (SDP) is a format for describing multimedia communication sessions for the purposes of session announcement and session invitation.[1] Its predominant use is in support of streaming media applications, such as voice over IP (VoIP) and video conferencing. SDP does not deliver any media streams itself, but is used between endpoints for negotiation of network metrics, media types, and other associated properties. The set of properties and parameters are often called a session profile.

	[wiki - Session_Description_Protocol](https://en.wikipedia.org/wiki/Session_Description_Protocol)   
	[RFC 4566 - SDP: Session Description Protocol](https://tools.ietf.org/html/rfc4566).  

- **DTLS**   
	Datagram Transport Layer Security. DTLS is used to secure all data transfers between peers; encryption is a mandatory feature of WebRTC.

	[wiki: Datagram_Transport_Layer_Security](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)   
	[RFC 6347 - Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347)    


- **SRTP**.  
	The Secure Real-time Transport Protocol (SRTP) is a Real-time Transport Protocol (RTP) profile, intended to provide encryption, message authentication and integrity, and replay attack protection to the RTP data in both unicast and multicast applications.  
	
	[Secure Real-time Transport Protocol
	](https://en.wikipedia.org/wiki/Secure_Real-time_Transport_Protocol).    
	[RFC3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711)


- **SCTP**.  
	Stream Control Transport Protocol. SCTP is designed to transport Public Switched Telephone Network (PSTN) signaling messages over IP networks, but is capable of broader applications.   
	[RFC 4960 - Stream Control Transmission Protocol](https://tools.ietf.org/html/rfc4960)


- **RTMP**  
	TCP-based protocol which maintains persistent connections and allows low-latency communication.  
	[wiki - Real-Time Messaging Protocol](https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol)

- **RTSP**  
	While similar in some ways to HTTP, RTSP defines control sequences useful in controlling multimedia playback. While HTTP is stateless, RTSP has state; an identifier is used when needed to track concurrent sessions. Like HTTP, RTSP uses TCP to maintain an end-to-end connection and, while most RTSP control messages are sent by the client to the server, some commands travel in the other direction (i.e. from server to client).  

	[wiki - https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol](https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol)  

- **HLS**  
	HTTP Live Streaming (also known as HLS) is an HTTP-based adaptive bitrate streaming communications protocol developed by Apple Inc.   

	[wiki - HTTP Live Streaming](https://en.wikipedia.org/wiki/HTTP_Live_Streaming)  

- **DASH**  
	Dynamic Adaptive Streaming over HTTP (DASH), also known as MPEG-DASH, is an adaptive bitrate streaming technique that enables high quality streaming of media content over the Internet delivered from conventional HTTP web servers.   
	[wiki: ynamic Adaptive Streaming over HTTP (DASH)](https://en.wikipedia.org/wiki/Dynamic_Adaptive_Streaming_over_HTTP)


## 容器
- **mp4**.     
	MPEG-4 Part 14 or MP4 is a digital multimedia container format most commonly used to store video and audio, but it can also be used to store other data such as subtitles and still images.[2] Like most modern container formats, it allows streaming over the Internet. The only official filename extension for MPEG-4 Part 14 files is .mp4. MPEG-4 Part 14 (formally ISO/IEC 14496-14:2003) is a standard specified as a part of MPEG-4.  

	[wiki - MPEG-4_Part_14](https://en.wikipedia.org/wiki/MPEG-4_Part_14)

- **ts**.  
	MPEG transport stream (transport stream, MPEG-TS, MTS or TS) is a standard digital container format for transmission and storage of audio, video, and Program and System Information Protocol (PSIP) data.[3] It is used in broadcast systems such as DVB, ATSC and IPTV.  

	Transport stream specifies a container format encapsulating packetized elementary streams, with error correction and synchronization pattern features for maintaining transmission integrity when the communication channel carrying the stream is degraded.  

	Transport streams differ from the similarly-named MPEG program stream in several important ways: program streams are designed for reasonably reliable media, such as discs (like DVDs), while transport streams are designed for less reliable transmission, namely terrestrial or satellite broadcast. Further, a transport stream may carry multiple programs.

	[wiki - MPEG transport stream](https://en.wikipedia.org/wiki/MPEG_transport_stream)


## 网络容错
- **FEC**
	[Reed Solomon纠删码](https://www.cnblogs.com/vc60er/p/4475026.html)
- **jitter**
- **synchronize**


## 语音增强
- **AEC**
- **NS**
- **AGC**


## 视频编码器
- **H.264/avc**   
	[digital_video_introduction](https://github.com/leandromoreira/digital_video_introduction/blob/master/README-cn.md)
- **h.265/hevc**  
- **vp8***

## 音频编码器
- **iLBC**
- **ACC**

## 参考
- [digital_video_introduction](https://github.com/leandromoreira/digital_video_introduction/blob/master/README-cn.md)
- [webrtc-architecture-protocols](https://princiya777.wordpress.com/2017/08/19/webrtc-architecture-protocols)
- [webrtcglossary.com](https://webrtcglossary.com/)




