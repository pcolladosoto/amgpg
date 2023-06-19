import MailKit
import OSLog

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {
    static let shared = MessageSecurityHandler()

    let defaultLog = Logger(subsystem: "amgpg-main", category: "mail")

    enum MessageSecurityError: Error {
        case unverifiedEmails(addresses: [MEEmailAddress])
        case invalidEmails(addresses: [MEEmailAddress])
        case noAddress
        case noEncodableData
        case encodingError
        case draft
        var errorReason: String {
            switch self {
            case .unverifiedEmails(let addresses):
                return "Invalid email addresses detected: \(addresses)"
            case .invalidEmails(let addresses):
                return "Invalid email addresses detected: \(addresses)"
            case .noAddress:
                return "No recipient provided."
            case .noEncodableData:
                return "No encodable data found."
            case .encodingError:
                return "We couldn't really encrypt the thing..."
            case .draft:
                return "We aren't encrypt drafts at the moment..."
            }
        }
    }

    // MARK: - Encoding Messages
    func encodingStatus(for message: MEMessage, composeContext: MEComposeContext) async -> MEOutgoingMessageEncodingStatus {
        var failingAddresses: [MEEmailAddress] = []

        var signOk = false;
        if let from = message.fromAddress.addressString {
            signOk = amgpg_key_is(PUBRING, SECRING, from, true) == RNP_SUCCESS
        }

        var encryptOk = false;
        if let toAddr = message.toAddresses.first {
            if let to = toAddr.addressString {
                encryptOk = amgpg_key_is(PUBRING, SECRING, to, false) == RNP_SUCCESS
            }

            if (!encryptOk) {
                failingAddresses.append(toAddr)
            }
        }

        defaultLog.debug(
            "decided we can: encrypt? \(encryptOk); sign? \(signOk)"
        )

        return MEOutgoingMessageEncodingStatus(
            canSign: signOk,
            canEncrypt: encryptOk,
            securityError: nil,
            addressesFailingEncryption: failingAddresses
        )
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext) async -> MEMessageEncodingResult {
        guard let msgHeaders = message.headers, let msgRFC = message.rawData else {
            defaultLog.error("Didn't find any message headers... That sounds fishy!")
            return MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: MessageSecurityError.noEncodableData,
                encryptionError: MessageSecurityError.noEncodableData
            )
        }

        if message.state == MEMessageState.draft || msgHeaders["x-uniform-type-identifier"] != nil {
            defaultLog.debug(
                "We're drafting: \(msgHeaders["x-uniform-type-identifier"]!), \(message.state.rawValue)"
            )
            return MEMessageEncodingResult(
                encodedMessage: MEEncodedOutgoingMessage(
                    rawData: msgRFC,
                    isSigned: false,
                    isEncrypted: false
                ),
                signingError: nil,
                encryptionError: nil
            )
        }

        defaultLog.debug("Should we sign? \(composeContext.shouldSign)")
        
        var processedMessage : Data? = nil
        if composeContext.shouldEncrypt {
            guard let toAddr = message.toAddresses.first else {
                defaultLog.debug("no TO addresses provided...")
                return  MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: MessageSecurityError.noAddress,
                    encryptionError: MessageSecurityError.noAddress
                )
            }

            guard let addr = toAddr.addressString else {
                defaultLog.debug("no valid address within \(toAddr)")
                return  MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: MessageSecurityError.invalidEmails(addresses: [toAddr]),
                    encryptionError: MessageSecurityError.invalidEmails(addresses: [toAddr])
                )
            }
            
            processedMessage = CryptoOps.sharedInstance.encodeMessage(msgRFC: msgRFC, to: addr)
        }

        guard let finalMsg = processedMessage else {
            return  MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: MessageSecurityError.encodingError,
                encryptionError: MessageSecurityError.encodingError
            )
        }

        return MEMessageEncodingResult(
            encodedMessage: MEEncodedOutgoingMessage(
                rawData: finalMsg,
                isSigned: false,
                isEncrypted: composeContext.shouldEncrypt
            ),
            signingError: nil,
            encryptionError: nil
        )
    }

    // MARK: - Decoding Messages
    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // defaultLog.debug("time to decode -> \(data.base64EncodedString())")
        guard let decodedMessage = CryptoOps.sharedInstance.decodeMessage(msgRFC: data) else {
            return nil
        }
        
        return MEDecodedMessage(
            data: decodedMessage,
            securityInformation: MEMessageSecurityInformation(
                signers: [],
                isEncrypted: true,
                signingError: nil,
                encryptionError: nil
            ),
            context: nil
        )
    }

    // MARK: - Displaying Security Information

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        // Return a view controller that shows details about the encoded message.
        return MessageSecurityViewController(
            nibName: "MessageSecurityViewController", bundle: Bundle.main
        )
    }

    // MARK: mark - Displaying Additional Context

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        // Return a view controller that can show additional message context.
        return nil
    }

    func primaryActionClicked(forMessageContext context: Data) async -> MEExtensionViewController? {
        let controller = MessageSecurityViewController.sharedInstance
        return controller
    }
}
