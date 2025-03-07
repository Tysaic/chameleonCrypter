import unittest
from crypter.toggle import CypherHandler
import os

class TestSetCreds(unittest.TestCase):
    """
    Define test to the follow examples:
    * Encrypt files and folders with credentials in memory
    * Decrypt files and folders with credentials in memory
    
    Run: python -m unittest tests/test.py
    """
    def setUp(self):
        self.password = "$$abcd1234"
        self.handler = CypherHandler(password=self.password)

    def test_encrypting_single_file(self):
        """
        python one_crypter.py --encrypt <file_or_folder_path>
        """
        file_to_encrypt = os.getcwd()+"/tests/file_to_encrypt.txt"
        original_content = "This is a test file to encrypt"
        with open(file_to_encrypt, "w") as file_path:
            file_path.write(original_content)
        self.handler.encrypter_decrypter(file_to_encrypt, cypher_type=False)
        with open(file_to_encrypt, "r") as file_path:
            encrypted_content = file_path.read()
        self.assertNotEqual(original_content, encrypted_content)
        print("[T+] Testing encrypting single file is Done!")
    
    def test_decrypting_single_file(self):
        """
        python one_crypter.py --decrypt <file_or_folder_path>
        """
        file_to_decrypt = os.getcwd()+"/tests/file_to_decrypt.txt"
        original_content = "This is a test file to decrypt"

        with open(file_to_decrypt, "w") as file_path:
            file_path.write(original_content)
        self.handler.encrypter_decrypter(file_to_decrypt, cypher_type=False)
        with open(file_to_decrypt, "r") as file_path:
            encrypted_content = file_path.read()

        decryted_file = self.handler.encrypter_decrypter(file_to_decrypt, cypher_type=True)
        with open(file_to_decrypt, "r") as file_path:
            decrypted_content = file_path.read()
        self.assertEqual(original_content, decrypted_content)
        print("[T+] Testing decrypting single file is Done!")


if __name__ == '__main__':
    unittest.main()
