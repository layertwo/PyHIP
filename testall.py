import unittest
import testHIPState
import testHIPOptMessage
import testHI
import testConversation
import testUtils
import testIPAddress

alltests = unittest.TestSuite((testHIPState.suite,
                               testHIPOptMessage.suite,
                               testHI.suite,
                               testConversation.suite,
                               testUtils.suite,
                               testIPAddress.suite))

unittest.TextTestRunner().run(alltests)
