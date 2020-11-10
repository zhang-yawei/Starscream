//////////////////////////////////////////////////////////////////////////////////////////////////
//
//  FrameCollector.swift
//  Starscream
//
//  Created by Dalton Cherry on 1/24/19.
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

public protocol FrameCollectorDelegate: class {
    func didForm(event: FrameCollector.Event)
    func decompress(data: Data, isFinal: Bool) -> Data?
}

public class FrameCollector {
    public enum Event {
        case text(String)
        case binary(Data)
        case pong(Data?)
        case ping(Data?)
        case error(Error)
        case closed(String, UInt16)
    }
    weak var delegate: FrameCollectorDelegate?
    var buffer = Data()
    var frameCount = 0
    var isText = false //was the first frame a text frame or a binary frame?
    var needsDecompression = false
    
    // 拼接数据帧
    public func add(frame: Frame) {
        //check single frame action and out of order frames
        
        if frame.opcode == .connectionClose {
            var code = frame.closeCode
            var reason = "connection closed by server"
            if let customCloseReason = String(data: frame.payload, encoding: .utf8) {
                reason = customCloseReason
            } else {
                code = CloseCode.protocolError.rawValue
            }
            delegate?.didForm(event: .closed(reason, code))
            return
        } else if frame.opcode == .pong {
            // pong
            delegate?.didForm(event: .pong(frame.payload))
            return
        } else if frame.opcode == .ping {
            // ping
            delegate?.didForm(event: .ping(frame.payload))
            return
        } else if frame.opcode == .continueFrame && frameCount == 0 {
            // 第一帧不能是继续帧
            let errCode = CloseCode.protocolError.rawValue
            delegate?.didForm(event: .error(WSError(type: .protocolError, message: "first frame can't be a continue frame", code: errCode)))
            reset()
            return
        } else if frameCount > 0 && frame.opcode != .continueFrame {
            // 后面的帧,只能是继续帧
            let errCode = CloseCode.protocolError.rawValue
            delegate?.didForm(event: .error(WSError(type: .protocolError, message: "second and beyond of fragment message must be a continue frame", code: errCode)))
            reset()
            return
        }
        if frameCount == 0 {
            // 第一帧长度opcode 字符或者二进制
            isText = frame.opcode == .textFrame
            needsDecompression = frame.needsDecompression
        }
        
        let payload: Data
        if needsDecompression {
            payload = delegate?.decompress(data: frame.payload, isFinal: frame.isFin) ?? frame.payload
        } else {
            payload = frame.payload
        }
        buffer.append(payload)
        frameCount += 1

        if frame.isFin {
            if isText {
                // Text帧 utf-8
                if let string = String(data: buffer, encoding: .utf8) {
                    delegate?.didForm(event: .text(string))
                } else {
                    let errCode = CloseCode.protocolError.rawValue
                    delegate?.didForm(event: .error(WSError(type: .protocolError, message: "not valid UTF-8 data", code: errCode)))
                }
            } else {
                delegate?.didForm(event: .binary(buffer))
            }
            reset()
        }
    }
    
    func reset() {
        buffer = Data()
        frameCount = 0
    }
}
