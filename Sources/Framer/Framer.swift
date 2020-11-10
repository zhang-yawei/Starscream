//////////////////////////////////////////////////////////////////////////////////////////////////
//
//  Framer.swift
//  Starscream
//
//  Created by Dalton Cherry on 1/23/19.
//  Copyright © 2019 Vluxe. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//////////////////////////////////////////////////////////////////////////////////////////////////

import Foundation
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-------+-+-------------+-------------------------------+
  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
  | |1|2|3|       |K|             |                               |
  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
  |     Extended payload length continued, if payload len == 127  |
  + - - - - - - - - - - - - - - - +-------------------------------+
  |                               |Masking-key, if MASK set to 1  |
  +-------------------------------+-------------------------------+
  | Masking-key (continued)       |          Payload Data         |
  +-------------------------------- - - - - - - - - - - - - - - - +
  :                     Payload Data continued ...                :
  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
  |                     Payload Data continued ...                |
  +---------------------------------------------------------------+
*/

let FinMask: UInt8          = 0x80 // 1000 0000 表示这是消息的最后一个片段。第一个片段也有可能是最后一个片段。
let OpCodeMask: UInt8       = 0x0F // 0000 1111  4 bit 最大0xF 定义“有效负载数据”的解释。如果收到一个未知的操作码，接收终端必须断开WebSocket连接。下面的值是被定义过的。
// RSV1，RSV2，RSV3: 每个1 bit 必须设置为0，除非扩展了非0值含义的扩展。如果收到了一个非0值但是没有扩展任何非0值的含义，接收终端必须断开WebSocket连接。
let RSVMask: UInt8          = 0x70 // 0111 0000 RSV
let RSV1Mask: UInt8         = 0x40 // 0100 0000  RSV1

//mask标志位，定义“有效负载数据”是否添加掩码。如果设置为1，那么掩码的键值存在于Masking-Key中，根据5.3节描述，这个一般用于解码“有效负载数据”。所有的从客户端发送到服务端的帧都需要设置这个bit位为1。
let MaskMask: UInt8         = 0x80 // 1000 0000 第二个字节的第一个bit
//Payload length: 7 bits, 7+16 bits, or 7+64 bits 以字节为单位的“有效负载数据”长度，如果值为0-125，那么就表示负载数据的长度。如果是126，那么接下来的2个bytes解释为16bit的无符号整形作为负载数据的长度。如果是127，那么接下来的8个bytes解释为一个64bit的无符号整形（最高位的bit必须为0）作为负载数据的长度。多字节长度量以网络字节顺序表示（译注：应该是指大端序和小端序）。在所有的示例中，长度值必须使用最小字节数来进行编码，例如：长度为124字节的字符串不可用使用序列126,0,124进行编码。有效负载长度是指“扩展数据”+“应用数据”的长度。“扩展数据”的长度可能为0，那么有效负载长度就是“应用数据”的长度。
let PayloadLenMask: UInt8   = 0x7F // 0111 1111

let MaxFrameSize: Int       = 32

// Standard WebSocket close codes
public enum CloseCode: UInt16 {
    case normal                 = 1000
    case goingAway              = 1001
    case protocolError          = 1002
    case protocolUnhandledType  = 1003
    // 1004 reserved.
    case noStatusReceived       = 1005
    //1006 reserved.
    case encoding               = 1007
    case policyViolated         = 1008
    case messageTooBig          = 1009
}

// 对应 OpCodeMask
public enum FrameOpCode: UInt8 {
    case continueFrame = 0x0 // %x0 表示一个持续帧
    case textFrame = 0x1 //  %x1 表示一个文本帧
    case binaryFrame = 0x2 // %x2 表示一个二进制帧
    // 3-7 are reserved. // %x3-7 预留给以后的非控制帧
    case connectionClose = 0x8 // %x8 表示一个连接关闭包
    case ping = 0x9 // ​ %x9 表示一个ping包
    case pong = 0xA // %xA 表示一个pong包
    // B-F reserved.
    case unknown = 100 // %xB-F 预留给以后的控制帧
}

public struct Frame {
    let isFin: Bool // 是否最后一个
    let needsDecompression: Bool // 需要解压
    let isMasked: Bool //是否添加掩码
    let opcode: FrameOpCode // 操作符
    let payloadLength: UInt64 //数据长度
    let payload: Data // 对应数据
    let closeCode: UInt16 //only used by connectionClose opcode
}

public enum FrameEvent {
    case frame(Frame)
    case error(Error)
}

public protocol FramerEventClient: class {
    func frameProcessed(event: FrameEvent)
}

// 数据帧接口
public protocol Framer {
    func add(data: Data)
    func register(delegate: FramerEventClient)
    func createWriteFrame(opcode: FrameOpCode, payload: Data, isCompressed: Bool) -> Data
    func updateCompression(supports: Bool)
    func supportsCompression() -> Bool
}

//ws数据帧
public class WSFramer: Framer {
    private let queue = DispatchQueue(label: "com.vluxe.starscream.wsframer", attributes: [])
    private weak var delegate: FramerEventClient?
    private var buffer = Data()
    public var compressionEnabled = false
    private let isServer: Bool
    
    public init(isServer: Bool = false) {
        self.isServer = isServer
    }
    //是否压缩
    public func updateCompression(supports: Bool) {
        compressionEnabled = supports
    }
    // 当前是否支持压缩?
    public func supportsCompression() -> Bool {
        return compressionEnabled
    }
    
    enum ProcessEvent {
        case needsMoreData
        case processedFrame(Frame, Int)
        case failed(Error)
    }
    
    public func add(data: Data) {
        queue.async { [weak self] in
            self?.buffer.append(data)
            while(true) {
               let event = self?.process() ?? .needsMoreData
                switch event {
                case .needsMoreData:
                    // 当前帧需要更多的段,添加入data,等待最后一段.
                    return
                case .processedFrame(let frame, let split):
                    guard let s = self else { return }
                    s.delegate?.frameProcessed(event: .frame(frame))
                    if split >= s.buffer.count {
                        // 当前的data恰好结束一帧.
                        s.buffer = Data()
                        return
                    }
                    // 下一帧数据
                    s.buffer = s.buffer.advanced(by: split)
                case .failed(let error):
                    self?.delegate?.frameProcessed(event: .error(error))
                    self?.buffer = Data()
                    return
                }
            }
        }
    }

    public func register(delegate: FramerEventClient) {
        self.delegate = delegate
    }
    
    private func process() -> ProcessEvent {
        // 小于两个字节,
        if buffer.count < 2 {
            return .needsMoreData
        }
        var pointer = [UInt8]()
        //buffer复制到pointer
        buffer.withUnsafeBytes { pointer.append(contentsOf: $0) }

        let isFin = (FinMask & pointer[0])
        let opcodeRawValue = (OpCodeMask & pointer[0])
        let opcode = FrameOpCode(rawValue: opcodeRawValue) ?? .unknown
        let isMasked = (MaskMask & pointer[1])
        let payloadLen = (PayloadLenMask & pointer[1])
        let RSV1 = (RSVMask & pointer[0])
        var needsDecompression = false
        // 需要压缩并且不是一个连续帧. 也就是最后一帧
        if compressionEnabled && opcode != .continueFrame {
            //RSV1Mask 扩展为 压缩标记 吗???
           needsDecompression = (RSV1Mask & pointer[0]) > 0
        }
        if !isServer && (isMasked > 0 || RSV1 > 0) && opcode != .pong && !needsDecompression {
            // 客户端操作,(存在掩码,或者 RSV标记存在) 并且 不是pong,并且 RSV1标记不存在. 也就是说后RSV两位的标记. 无法处理的数据帧.
            let errCode = CloseCode.protocolError.rawValue
            return .failed(WSError(type: .protocolError, message: "masked and rsv data is not currently supported", code: errCode))
        }
        // 是否是控制帧
        let isControlFrame = (opcode == .connectionClose || opcode == .ping)
        
        if !isControlFrame && (opcode != .binaryFrame && opcode != .continueFrame &&
            opcode != .textFrame && opcode != .pong) {
            //%x3-7 或者 %xB-F 预留的控制帧和非控制帧, 无法处理
            let errCode = CloseCode.protocolError.rawValue
            return .failed(WSError(type: .protocolError, message: "unknown opcode: \(opcodeRawValue)", code: errCode))
        }
        if isControlFrame && isFin == 0 {
            // 控制帧只能是最后一个片段
            let errCode = CloseCode.protocolError.rawValue
            return .failed(WSError(type: .protocolError, message: "control frames can't be fragmented", code: errCode))
        }
        
        var offset = 2
    
        if isControlFrame && payloadLen > 125 {
            // 超出控制帧的长度.
            return .failed(WSError(type: .protocolError, message: "payload length is longer than allowed for a control frame", code: CloseCode.protocolError.rawValue))
        }
        
        var dataLength = UInt64(payloadLen)
        var closeCode = CloseCode.normal.rawValue
        if opcode == .connectionClose {
// 如果是关闭帧
//控制帧的操作码值是0x8。 关闭帧可能包含内容（body）（帧的“应用数据”部分）来表明连接关闭的原因，例如终端的断开，或者是终端收到了一个太大的帧，或者是终端收到了一个不符合预期的格式的内容。如果这个内容存在，内容的前两个字节必须是一个无符号整型（按照网络字节序）来代表在7.4节中定义的状态码。跟在这两个整型字节之后的可以是UTF-8编码的的数据值（原因），数据值的定义不在此文档中。数据值不一定是要人可以读懂的，但是必须对于调试有帮助，或者能传递有关于当前打开的这条连接有关联的信息。数据值不保证人一定可以读懂，所以不能把这些展示给终端用户。
            if payloadLen == 1 {
                closeCode = CloseCode.protocolError.rawValue
                dataLength = 0
            } else if payloadLen > 1 {
                // 如果长度大于1
                if pointer.count < 4 {
                    // 当前长度小于4
                    return .needsMoreData
                }
                let size = MemoryLayout<UInt16>.size
                closeCode = pointer.readUint16(offset: offset)
                // 后两个字节是错误码,
                offset += size
                dataLength -= UInt64(size)
                if closeCode < 1000 || (closeCode > 1003 && closeCode < 1007) || (closeCode > 1013 && closeCode < 3000) {
                    closeCode = CloseCode.protocolError.rawValue
                }
            }
        }
        
        if payloadLen == 127 {
            //如果是127，那么接下来的8个bytes解释为一个64bit的无符号整形（最高位的bit必须为0）作为负载数据的长度。
             let size = MemoryLayout<UInt64>.size
            if size + offset > pointer.count {
                // 当前帧没有传输完成.
                return .needsMoreData
            }
            dataLength = pointer.readUint64(offset: offset)
            offset += size
        } else if payloadLen == 126 {
            //如果是126，那么接下来的2个bytes解释为16bit的无符号整形作为负载数据的长度
            let size = MemoryLayout<UInt16>.size
            if size + offset > pointer.count {
                return .needsMoreData
            }
            dataLength = UInt64(pointer.readUint16(offset: offset))
            offset += size
        }
        
        let maskStart = offset
        // masking-key 的起始位置. 没有判断掩码标志位.
        if isServer {
            //所有从客户端发往服务端的数据帧都已经与一个包含在这一帧中的32 bit的掩码进行过了运算。如果mask标志位（1 bit）为1，那么这个字段存在，如果标志位为0，那么这个字段不存在。在5.3节中会介绍更多关于客户端到服务端增加掩码的信息。
            offset += MemoryLayout<UInt32>.size
        }
        
        if dataLength > (pointer.count - offset) {
            return .needsMoreData
        }
        
        //I don't like this cast, but Data's count returns an Int.
        //Might be a problem with huge payloads. Need to revisit.
        let readDataLength = Int(dataLength)
        
        let payload: Data
        if readDataLength == 0 {
            payload = Data()
        } else {
            if isServer {
                // 服务端接受,有掩码,
                payload = pointer.unmaskData(maskStart: maskStart, offset: offset, length: readDataLength)
            } else {
                let end = offset + readDataLength
                //客户端,无掩码
                payload = Data(pointer[offset..<end])
            }
        }
        offset += readDataLength

        let frame = Frame(isFin: isFin > 0, needsDecompression: needsDecompression, isMasked: isMasked > 0, opcode: opcode, payloadLength: dataLength, payload: payload, closeCode: closeCode)
        return .processedFrame(frame, offset)
    }
    
    public func createWriteFrame(opcode: FrameOpCode, payload: Data, isCompressed: Bool) -> Data {
        let payloadLength = payload.count
        
        let capacity = payloadLength + MaxFrameSize
        var pointer = [UInt8](repeating: 0, count: capacity)
        
        //set the framing info
        pointer[0] = FinMask | opcode.rawValue
        if isCompressed {
             pointer[0] |= RSV1Mask
        }
        
        var offset = 2 //skip pass the framing info
        if payloadLength < 126 {
            pointer[1] = UInt8(payloadLength)
        } else if payloadLength <= Int(UInt16.max) {
            pointer[1] = 126
            writeUint16(&pointer, offset: offset, value: UInt16(payloadLength))
            offset += MemoryLayout<UInt16>.size
        } else {
            pointer[1] = 127
            writeUint64(&pointer, offset: offset, value: UInt64(payloadLength))
            offset += MemoryLayout<UInt64>.size
        }
        
        //clients are required to mask the payload data, but server don't according to the RFC
        if !isServer {
            pointer[1] |= MaskMask
            
            //write the random mask key in
            let maskKey: UInt32 = UInt32.random(in: 0...UInt32.max)
            
            writeUint32(&pointer, offset: offset, value: maskKey)
            let maskStart = offset
            offset += MemoryLayout<UInt32>.size
            
            //now write the payload data in
            for i in 0..<payloadLength {
                pointer[offset] = payload[i] ^ pointer[maskStart + (i % MemoryLayout<UInt32>.size)]
                offset += 1
            }
        } else {
            for i in 0..<payloadLength {
                pointer[offset] = payload[i]
                offset += 1
            }
        }
        return Data(pointer[0..<offset])
    }
}

/// MARK: - functions for simpler array buffer reading and writing

public protocol MyWSArrayType {}
extension UInt8: MyWSArrayType {}

public extension Array where Element: MyWSArrayType & UnsignedInteger {
    
    /**
     Read a UInt16 from a buffer.
     - parameter offset: is the offset index to start the read from (e.g. buffer[0], buffer[1], etc).
     - returns: a UInt16 of the value from the buffer
     */
    func readUint16(offset: Int) -> UInt16 {
        // 取offer起始的2个字节.
        return (UInt16(self[offset + 0]) << 8) | UInt16(self[offset + 1])
    }
    
    /**
     Read a UInt64 from a buffer.
     - parameter offset: is the offset index to start the read from (e.g. buffer[0], buffer[1], etc).
     - returns: a UInt64 of the value from the buffer
     */
    func readUint64(offset: Int) -> UInt64 {
        var value = UInt64(0)
        for i in 0...7 {
            value = (value << 8) | UInt64(self[offset + i])
        }
        return value
    }
    
    
    /**添加掩码的数据帧必须像5.2节定义的一样，设置frame-masked字段为1。
     掩码值像第5.2节说到的完全包含在帧中的frame-masking-key上。它是用于对定义在同一节中定义的帧负载数据Payload data字段中的包含Extension data和Application data的数据进行添加掩码。

     掩码字段是一个由客户端随机选择的32bit的值。当准备掩码帧时，客户端必须从允许的32bit值中须知你咋一个新的掩码值。掩码值必须是不可被预测的；因此，掩码必须来自强大的熵源（entropy），并且给定的掩码不能让服务器或者代理能够很容易的预测到后续帧。掩码的不可预测性对于预防恶意应用作者在网上暴露相关的字节数据至关重要。RFC 4086讨论了安全敏感的应用需要一个什么样的合适的强大的熵源。

     掩码不影响Payload data的长度。进行掩码的数据转换为非掩码数据，或者反过来，根据下面的算法即可。这个同样的算法适用于任意操作方向的转换，例如：对数据进行掩码操作和对数据进行反掩码操作所涉及的步骤是相同的。

     表示转换后数据的八位字节的i（transformed-octet-i ）是表示的原始数据的i（original-octet-i）与索引i模4得到的掩码值（masking-key-octet-j）经过异或操作（XOR）得到的：

     j = i MOD 4
     transfromed-octed-i = original-octet-i XOR masking-key-octet-j

     在规范中定义的位于frame-payload-length字段的有效负载的长度，不包括掩码值的长度。它只是Payload data的长度。如跟在掩码值后面的字节数组的数。

*/
    // 根据掩码,计算出原始数据.
    func unmaskData(maskStart: Int, offset: Int, length: Int) -> Data {
        // length字节
        var unmaskedBytes = [UInt8](repeating: 0, count: length)
        let maskSize = MemoryLayout<UInt32>.size
        for i in 0..<length {
            unmaskedBytes[i] = UInt8(self[offset + i] ^ self[maskStart + (i % maskSize)])
        }
        return Data(unmaskedBytes)
    }
}

/**
 Write a UInt16 to the buffer. It fills the 2 array "slots" of the UInt8 array.
 - parameter buffer: is the UInt8 array (pointer) to write the value too.
 - parameter offset: is the offset index to start the write from (e.g. buffer[0], buffer[1], etc).
 */
public func writeUint16( _ buffer: inout [UInt8], offset: Int, value: UInt16) {
    buffer[offset + 0] = UInt8(value >> 8)
    buffer[offset + 1] = UInt8(value & 0xff)
}

/**
 Write a UInt32 to the buffer. It fills the 4 array "slots" of the UInt8 array.
 - parameter buffer: is the UInt8 array (pointer) to write the value too.
 - parameter offset: is the offset index to start the write from (e.g. buffer[0], buffer[1], etc).
 */
public func writeUint32( _ buffer: inout [UInt8], offset: Int, value: UInt32) {
    for i in 0...3 {
        buffer[offset + i] = UInt8((value >> (8*UInt32(3 - i))) & 0xff)
    }
}

/**
 Write a UInt64 to the buffer. It fills the 8 array "slots" of the UInt8 array.
 - parameter buffer: is the UInt8 array (pointer) to write the value too.
 - parameter offset: is the offset index to start the write from (e.g. buffer[0], buffer[1], etc).
 */
public func writeUint64( _ buffer: inout [UInt8], offset: Int, value: UInt64) {
    for i in 0...7 {
        buffer[offset + i] = UInt8((value >> (8*UInt64(7 - i))) & 0xff)
    }
}
