import MailKit
import OSLog

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {
    static let shared = MessageSecurityHandler()
    
    let defaultLog = Logger(subsystem: "fooLog", category: "mail")
    
    enum MessageSecurityError: Error {
        case unverifiedEmails(emailAdresses: [MEEmailAddress])
        case noEncodableData
        case draft
        var errorReason: String {
            switch self {
            case .unverifiedEmails(let emailAdresses):
                return "Invalid email addresses detected.\n\(emailAdresses)"
            case .noEncodableData:
                return "No encodable data found."
            case .draft:
                return "We aren't encrypt drafts at the moment..."
            }
        }
    }

    // MARK: - Encoding Messages
    func encodingStatus(for message: MEMessage, composeContext: MEComposeContext) async -> MEOutgoingMessageEncodingStatus {
        // Indicate whether you support signing, encrypting, or both. If the
        // message contains recipients that you can't sign or encrypt for,
        // specify an error and include the addresses in the
        // addressesFailingEncryption array parameter. Update this code with
        // the options your extension supports.
        
        return MEOutgoingMessageEncodingStatus(
            canSign: true,
            canEncrypt: true,
            securityError: nil,
            addressesFailingEncryption: []
            // addressesFailingEncryption: message.allRecipientAddresses
        )
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext) async -> MEMessageEncodingResult {
        defaultLog.debug("Current message state -> \(message.state.rawValue)")
        
        guard let msgHeaders = message.headers, var msgBody = message.rawData else {
            defaultLog.error("Didn't find any message headers... That sounds fishy!")
            return MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: nil,
                encryptionError: MessageSecurityHandler.MessageSecurityError.noEncodableData
            )
        }

        // defaultLog.debug("Printing out the message's headers...")
        // for (header, value) in msgHeaders {
        //    defaultLog.debug("\(header) -> \(value)")
        // }
        
        defaultLog.debug("Raw Base64-encoded message -> \(msgBody.base64EncodedString())")

        if message.state == MEMessageState.draft || msgHeaders["x-uniform-type-identifier"] != nil {
            defaultLog.debug(
                "Skipping actions on the draft: 'x-uniform-type-identifier' -> \(msgHeaders["x-uniform-type-identifier"]!)"
            )
            return MEMessageEncodingResult(
                encodedMessage: MEEncodedOutgoingMessage(
                    rawData: msgBody,
                    isSigned: false,
                    isEncrypted: false),
                signingError: nil,
                encryptionError: nil
            )
        }

        // Triggering RNP...
        // triggerRNP();

        defaultLog.debug("Getting ready to send a message...")
        defaultLog.debug("Should we encrypt? \(composeContext.shouldEncrypt)")
        defaultLog.debug("Should we sign? \(composeContext.shouldSign)")

        // The result of the encoding operation. This object contains
        // the encoded message or an error to indicate what failed.
        // let result: MEMessageEncodingResult
        
        // Add code here to sign and/or encrypt the message.
        //
        // If the encoding is successful, you create an instance
        // of MEEncodedOutgoingMessage that contains the encoded data and
        // indications whether the data is signed and/or encrypted.
        // For example:
        //
        // encodedMessage = MEEncodedOutgoingMessage(rawData:encodedData, isSigned:true, isEncrypted:true)
        //
        // Finally, create an MEMessageEncodingResult that includes the
        // MEEncodedOutgoingMessage or errors to indicate why the encoding
        // failed. If the message doesn't need to be encoded, pass nil,
        // otherwise pass an MEEncodedOutgoingMessage as shown above.
        // result = MEMessageEncodingResult(
        //    encodedMessage: nil, signingError: nil, encryptionError: nil
        // )

        guard let additionalBody = "We have modified the message :P".data(using: .ascii) else {
            defaultLog.error("Couldn't populate the addiotnal message body......")
            return  MEMessageEncodingResult(
                encodedMessage: MEEncodedOutgoingMessage(
                    rawData: msgBody,
                    isSigned: composeContext.isSigned,
                    isEncrypted: composeContext.isEncrypted),
                signingError: nil,
                encryptionError: nil)
        }

        defaultLog.debug("Appending a goodie to the message: \(additionalBody.base64EncodedString())")
        msgBody.append(additionalBody)

        return MEMessageEncodingResult(
            encodedMessage: MEEncodedOutgoingMessage(
                rawData: msgBody,
                isSigned: composeContext.isSigned,
                isEncrypted: composeContext.isEncrypted),
            signingError: nil,
            encryptionError: nil)
    }

    // MARK: - Decoding Messages

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // In this method, you decode the message data. Create an
        // MEMessageSecurityInformation object to capture details about the decoded
        // message. If an error occurs, create an NSError that describes the
        // failure, and specify it in the security information object. For example:
        //
        // let securityInfo = MEMessageSecurityInformation(signers: [], isEncrypted: false, signingError: nil, encryptionError: nil)
        //
        // Create a decoded message object that contains the decoded data and the
        // security information. For example:
        //
        // let decodedData = ... 
        // let decodedMessage = MEDecodedMessage(data: decodedData, securityInformation: securityInfo, context: nil)
        
        // If the message doesn't need to be decoded, return nil.
        // Otherwise return an MEDecodedMessage, as shown above. 
        return nil;
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
