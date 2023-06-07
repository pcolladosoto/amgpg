import MailKit

class MessageSecurityViewController: MEExtensionViewController {
    static let sharedInstance = MessageSecurityViewController()

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
    }
    
    override var nibName: NSNib.Name? {
        return "MessageSecurityViewController"
    }
}
