import unittest
import binascii

from pniffer.utils import (
    bin2str, bin2int, ip2domain, generate_header_dict
)


class UtilsTestCase(unittest.TestCase):
    def test_bin2str(self):
        answer = 'abcdef'
        arg = binascii.unhexlify(answer)
        self.assertEqual(bin2str(arg), answer)

    def test_bin2int(self):
        answers = [11259375, 10]
        args = [binascii.unhexlify('abcdef'), 10]

        for i in range(len(args)):
            with self.subTest(i=i):
                self.assertEqual(bin2int(args[i]), answers[i])

    def test_bin2int_exception(self):
        self.assertRaises(ValueError, bin2int, 'pniffer')

    def test_ip2domain(self):
        answers = ['198.51.100.1', 'localhost']
        args = ['198.51.100.1', '127.0.0.1']

        for i in range(len(args)):
            with self.subTest(i=i):
                self.assertEqual(ip2domain(args[i]), answers[i])

    def test_generate_header_dict(self):
        keys = ['a', 'b', 'c']
        values = ['d', 'e', 'f']
        answer = dict(zip(keys, values))

        self.assertEqual(generate_header_dict(keys, values), answer)

    def test_generate_header_dict_exception(self):
        """
        Mismatch the number of argument
        """

        keys = ['a', 'b', 'c']
        values = ['A', 'B']

        self.assertRaises(TypeError, generate_header_dict, keys, values)


if __name__ == '__main__':
    unittest.main(verbosity=2)
