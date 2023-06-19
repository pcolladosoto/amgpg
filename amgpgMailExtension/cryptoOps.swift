import MailKit
import Foundation
import OSLog

class CryptoOps {
    static let sharedInstance = CryptoOps()
    
    let defaultLog = Logger(subsystem: "amgpg-crypto", category: "mail")
    
    private func shouldEncode(_ message: MEMessage) -> Bool {
        true
    }
    
    private func splitRFC2822(msgRFC: Data) -> (Data, Data) {
        var msgHdrsRaw = Data()
        var msgBodyRaw = Data()
        
        for i in 1..<msgRFC.count {
            if msgRFC[i-1] == UInt8(ascii: "\n") && msgRFC[i] == UInt8(ascii: "\n") {
                msgHdrsRaw.append(msgRFC[0...i])
                msgBodyRaw.append(msgRFC[i+1..<msgRFC.count])
                break;
            }
        }
        
        // defaultLog.debug("Hdrs (base64) -> \(msgHdrsRaw.base64EncodedString())")
        // defaultLog.debug("Body (base64) -> \(msgBodyRaw.base64EncodedString())")
        
        return (msgHdrsRaw, msgBodyRaw)
    }

    func encodeMessage(msgRFC: Data, to: String) -> Data? {
        var (hdrs, body) = splitRFC2822(msgRFC: msgRFC)
        
        let bodyPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: body.count)
        body.copyBytes(to: bodyPtr, count: body.count)
        
        // defaultLog.debug("encrypting message for: \(to)")
        
        let encMessage = amgpg_encrypt(
            msg_t(msg: bodyPtr, len: body.count, ret: 0), PUBRING, SECRING, to
        )

        if encMessage.ret != RNP_SUCCESS {
            defaultLog.debug("couldn't encrypt the message: \(String(format:"%02x", encMessage.ret))")
            return nil
        }

        hdrs.append(Data(bytes: encMessage.msg, count: encMessage.len))

        // defaultLog.debug("encoded (base64) -> \(hdrs.base64EncodedString())")

        rnp_buffer_destroy(encMessage.msg)

        return hdrs
    }
    
    func decodeMessage(msgRFC: Data) -> Data? {
        var (hdrs, body) = splitRFC2822(msgRFC: msgRFC)
        
        let bodyPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: body.count)
        body.copyBytes(to: bodyPtr, count: body.count)

        let decMessage = amgpg_decrypt(msg_t(msg: bodyPtr, len: body.count, ret: 0), PUBRING, SECRING)
        
        if decMessage.ret != RNP_SUCCESS {
            // defaultLog.debug("couldn't decrypt the message: \(String(format:"%02x", decMessage.ret))")
            return nil
        }

        hdrs.append(Data(bytes: decMessage.msg, count: decMessage.len))

        // defaultLog.debug("decoded (base64) -> \(hdrs.base64EncodedString())")

        rnp_buffer_destroy(decMessage.msg)

        return hdrs
    }
    
    func securityStatus(for message: MEMessage) -> MEOutgoingMessageEncodingStatus {
        MEOutgoingMessageEncodingStatus(
            canSign: true,
            canEncrypt: true,
            securityError: nil,
            addressesFailingEncryption: [])
    }
}

class ExampleDecoder {
    static let sharedInstance = ExampleDecoder()
    
    func shouldDecodeMessage(withData: Data) -> Bool {
        true
    }
    
    func decodedMessage(from data: Data) -> MEDecodedMessage {
        MEDecodedMessage(
            data: data,
            securityInformation: MEMessageSecurityInformation(
                signers: [],
                isEncrypted: true,
                signingError: nil,
                encryptionError: nil),
            context: nil,
            banner: nil)
    }
}
