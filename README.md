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
	[RFC5450 - Transmission Time Offsets in RTP Streams](https://tools.ietf.org/html/rfc5450).  
	[RFC5104 - Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF) ](https://tools.ietf.org/html/rfc5104).  
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
	[RFC6544: TCP Candidates with Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc6544).  
	[RFC8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal](https://tools.ietf.org/html/rfc6544)



- **STUN**   
	Session Traversal Utilities for NAT (STUN) is a standardized set of methods, including a network protocol, for traversal of network address translator (NAT) gateways in applications of real-time voice, video, messaging, and other interactive communications. 

	STUN is a tool used by other protocols, such as Interactive Connectivity Establishment (ICE), the Session Initiation Protocol (SIP), or WebRTC. It provides a tool for hosts to discover the presence of a network address translator, and to discover the mapped, usually public, Internet Protocol (IP) address and port number that the NAT has allocated for the application's User Datagram Protocol (UDP) flows to remote hosts. The protocol requires assistance from a third-party network server (STUN server) located on the opposing (public) side of the NAT, usually the public Internet.   

	[wiki - STUN](https://en.wikipedia.org/wiki/STUN)
	[RFC 3489 - STUN - Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs)](https://tools.ietf.org/html/rfc3489).   
	[RFC5389 - Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389).   
	[RFC5389_NAT 的会话穿透用法 (STUN)](rfc-chinese/RFC5389_NAT的会话穿透用法(STUN).pdf)   
	[P2P技术简介-NAT（ Network Address Translation）穿越（俗称打洞）技术](https://www.cnblogs.com/vc60er/p/6916190.html)    

- **TURN**.   
	Traversal Using Relays around NAT (TURN) is a protocol that assists in traversal of network address translators (NAT) or firewalls for multimedia applications. It may be used with the Transmission Control Protocol (TCP) and User Datagram Protocol (UDP). It is most useful for clients on networks masqueraded by symmetric NAT devices. TURN does not aid in running servers on well known ports in the private network through a NAT;   

	[wiki - Traversal_Using_Relays_around_NAT](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT)   
	[RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5766).  

- **SDP**   
	The Session Description Protocol (SDP) is a format for describing multimedia communication sessions for the purposes of session announcement and session invitation.[1] Its predominant use is in support of streaming media applications, such as voice over IP (VoIP) and video conferencing. SDP does not deliver any media streams itself, but is used between endpoints for negotiation of network metrics, media types, and other associated properties. The set of properties and parameters are often called a session profile.

	[wiki - Session_Description_Protocol](https://en.wikipedia.org/wiki/Session_Description_Protocol)   
	[RFC4566 - SDP: Session Description Protocol](https://tools.ietf.org/html/rfc4566).  

- **DTLS**   
	Datagram Transport Layer Security. DTLS is used to secure all data transfers between peers; encryption is a mandatory feature of WebRTC.

	[wiki: Datagram_Transport_Layer_Security](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)   
	[RFC6347 - Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347)    


- **SRTP**.  
	The Secure Real-time Transport Protocol (SRTP) is a Real-time Transport Protocol (RTP) profile, intended to provide encryption, message authentication and integrity, and replay attack protection to the RTP data in both unicast and multicast applications.  
	
	[Secure Real-time Transport Protocol
	](https://en.wikipedia.org/wiki/Secure_Real-time_Transport_Protocol).    
	[RFC3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711)


- **SCTP**.  
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


## 传输控制
- **GCC**  
	[A Google Congestion Control Algorithm for Real-Time Communication draft-ietf-rmcat-gcc-02](https://tools.ietf.org/html/draft-ietf-rmcat-gcc-02)  
	[小议WebRTC拥塞控制算法：GCC介绍](http://yunxin.163.com/blog/video18-0905/)  
	[WebRTC拥塞控制策略](https://www.freehacker.cn/media/webrtc-gcc/)  
	[WebRTC-GCC两种实现方案对比](https://www.freehacker.cn/media/tcc-vs-gcc/)  
	[Analysis and Design of the Google Congestion Control for Web Real-time Communication (WebRTC)](https://c3lab.poliba.it/images/6/65/Gcc-analysis.pdf)   

	
- **BBR**  
	BBR一开始是针对TCP的拥塞控制提出来的。它的输入为ACK/SACK，输出为拥塞窗口(congestion_window)发送速度(pacing_rate)。  
	[BBR: Congestion-Based Congestion Control](https://queue.acm.org/detail.cfm?id=3022184)  
	[来自Google的TCP BBR拥塞控制算法解析](https://blog.csdn.net/dog250/article/details/52830576)  
	[TCP BBR拥塞控制算法解析](https://blog.csdn.net/ebay/article/details/76252481)     
	[Linux Kernel 4.9 中的 BBR 算法与之前的 TCP 拥塞控制相比有什么优势](https://www.zhihu.com/question/53559433)   
	[一文解释清楚GOOGLE BBR拥塞控制算法原理](https://www.taohui.pub/2019/08/07/%e4%b8%80%e6%96%87%e8%a7%a3%e9%87%8a%e6%b8%85%e6%a5%9agoogle-bbr%e6%8b%a5%e5%a1%9e%e6%8e%a7%e5%88%b6%e7%ae%97%e6%b3%95%e5%8e%9f%e7%90%86/)  
	[BBR及其在实时音视频领域的应用](https://mp.weixin.qq.com/s/8Hy5SBWXzhZ2X4YnjFflJw)   


- **PCC**  
	[PCC: Performance-oriented Congestion Control](https://modong.github.io/pcc-page/)   


- **NACK**  
	[Acknowledgement (data networks)](https://en.wikipedia.org/wiki/Acknowledgement_(data_networks))   
	[RFC4588 - RTP Retransmission Payload Format](https://tools.ietf.org/html/rfc4588)   
	[LearningWebRTC: NACK(Negative ACKnowledgement)](https://xjsxjtu.github.io/2017-07-16/LearningWebRTC-nack/)   


- **QUIC**  
	[wiki - QUIC](https://en.wikipedia.org/wiki/QUIC)   
	[Official Google description:](https://www.chromium.org/quic)   
	[Inofficial standalone library maintained by official QUIC developers](https://github.com/google/proto-quic)   
	[Good introduction read-up with comment from Jim Roskind (QUIC architect)](https://ma.ttias.be/googles-quic-protocol-moving-web-tcp-udp/)   

- **ARQ**  
	[Automatic repeat request](https://en.wikipedia.org/wiki/ARQ_(film))
	[重要的事情说三遍：ARQ协议](https://sexywp.com/introduction-of-arq.htm)

- **jitter**  

- **synchronize**  

- **FEC**   
	[LearningWebRTC: FEC(Forward Error Correction)](https://xjsxjtu.github.io/2017-07-16/LearningWebRTC-fec/)   
	[RTP Payload Format for Flexible Forward Error Correction (FEC) - draft-ietf-payload-flexible-fec-scheme-05](https://tools.ietf.org/html/draft-ietf-payload-flexible-fec-scheme-05)   
	[RFC 5109 - RTP Payload Format for Generic Forward Error Correction](https://tools.ietf.org/html/rfc5109)   

- **RS**   
	[Reed Solomon纠删码](https://www.cnblogs.com/vc60er/p/4475026.html)  


## 语音增强  
- **AEC**  
[LearningWebRTC: AECM](https://xjsxjtu.github.io/2017-07-05/LearningWebRTC-apm_aecm/)  
- **NS**  
- **AGC** 
- **VAD**   





## 视频编码器
- **H.264/avc**   
	[wiki - Advanced Video Coding](https://en.wikipedia.org/wiki/Advanced_Video_Coding)  
	[digital_video_introduction](https://github.com/leandromoreira/digital_video_introduction/blob/master/README-cn.md)	[codec-h264](https://www.freehacker.cn/media/codec-h264/)  
	[rfc6184 - RTP Payload Format for H.264 Video](https://tools.ietf.org/html/rfc6184)  
	[rfc6190 - RTP Payload Format for Scalable Video Coding](https://tools.ietf.org/html/rfc6190)	

- **h.265/hevc**  

- **vp8**  

- **yuv**  
	[视频像素格式YUV和RGB](https://www.freehacker.cn/media/codec-yuv-rgb/)    
	[视频像素格式](https://wikipedia.freehacker.cn/auvi/video-pixel-format.html)   
	[[翻译]H.264 探索 第一部分 色彩模型](https://segmentfault.com/a/1190000006695679)   

- **SVC**   
	[SVC和视频通信](https://www.zego.im/article/2018/03/07/svc%e5%92%8c%e8%a7%86%e9%a2%91%e9%80%9a%e4%bf%a1/)   
	[在Google Chrome WebRTC中分层蛋糕式的VP9 SVC](https://www.zego.im/article/2018/02/26/%E5%9C%A8google-chrome-webrtc%E4%B8%AD%E5%88%86%E5%B1%82%E8%9B%8B%E7%B3%95%E5%BC%8F%E7%9A%84vp9-svc/)   
	[姜健：VP9可适性视频编码（SVC）新特性](https://mp.weixin.qq.com/s/PN91H_bFQ2X_ySiMGxGK5A?utm_source=tuicool&utm_medium=referral)   
	[H264 SVC：从编码到RTP打包](https://xjsxjtu.github.io/2017-06-24/H264-SVC/)   
	[H.264 SVC](https://www.cnblogs.com/huxiaopeng/p/5653310.html)   

- **x264编码器参数**   
	[H.264 Video Encoding Guide](https://trac.ffmpeg.org/wiki/Encode/H.264)   
	[x264参数中文详解（X264 Settings）](https://www.cnblogs.com/lihaiping/p/4037470.html)   
	[H264编码常用参数整理](https://blog.csdn.net/yuangc/article/details/86678247)   
	[FFmpeg使用X264编码参数](http://blog.gqylpy.com/gqy/22748/)  
	[ffmpeg与H264编码指南](https://www.cnblogs.com/tocy/p/ffmpeg_h264_encode_guide.html)  
	[(转)x264参数中文详解（X264 Settings）](https://www.cnblogs.com/lihaiping/p/4037470.html)  


## 音频编码器
- **iLBC**  
	[Internet Low Bitrate Codec](https://en.wikipedia.org/wiki/Internet_Low_Bitrate_Codec)  

- **ACC**  
	[Advanced Audio Coding](https://en.wikipedia.org/wiki/Advanced_Audio_Coding)  

- **opus**   
	Opus是一个混合编码器，由SILK和CELT两种编码器混合而成，SILK主要负责wideband(8khz)以下的语音编码，CELT主要负责高频编码，如音乐等。    
	[wiki - Opus (audio format)](https://en.wikipedia.org/wiki/Opus_(audio_format))  
	[RFC7587 - RTP Payload Format for the Opus Speech and Audio Codec](https://tools.ietf.org/html/rfc7587)
	[RFC6716 - Definition of the Opus Audio Codec](https://tools.ietf.org/html/rfc6716)



## 工具



## 资源
- [webrtc-architecture-protocols](https://princiya777.wordpress.com/2017/08/19/webrtc-architecture-protocols)
- [webrtcglossary.com](https://webrtcglossary.com/)


