from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
import base64
import os
import binascii
import argparse
import getpass
import platform


class CypherHandler:
    """
    False => encrypt
    True => decrypt
    """

    def __init__(self, password, credentials_files=None):
        try:
            self.password = bytes(password, 'utf-8')
            self.salt = binascii.unhexlify("a33626f9ccaa6e0f8c80b549e23f15cd")
            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA512(),
                length = 32,
                #salt = os.urandom(16),
                salt = self.salt,
                iterations = 480000,
            )
            print("[!] There are not salts and any credentials file. [!]\n")
            print("[!] The salt would be difficult and get wrong decrypt function if not set.\n")
            print("[!] Credentials built with random salt and password if the case.\n")
            print("[+] Save the file in a site where only you can access no anybody else.\n")
            # Deactivating credentials builder
            #self.credentials_builder()
            self.key = base64.urlsafe_b64encode(kdf.derive(self.password))
            self.cypher_suite = Fernet(self.key)

        except TypeError as e:
            print(f"[-] Error: {e} [-]")
            print("[-] Please set password and path where will encrypted [-]")
            print("[!] Example of use: python3 one_crypter.py --encrypt <path> --password <password> [!]")

    def get_cypher_keys(self) -> tuple:
        """
        Return  Simple Key
        [self.key, self.cyphersuite]
        """

        return (self.key, self.cypher_suite)

    def get_cypher_suite(self):
        """
        Return the cipher suite used by the encrypter.

        Returns:
            str: The cipher suite used by the encrypter.
        """
        print("TYPE GET: ", type(self.cypher_suite))
        return self.cypher_suite
    

    def file_directory_checker(self, path) -> dict:
        """
        Check if the given path is a file, a directory, or if it exists.

        Args:
            path (str): The path to be checked.

        Returns:
            dict: A dictionary containing the following information:
                - is_file (bool): True if the path is a file, False otherwise.
                - is_dir (bool): True if the path is a directory, False otherwise.
                - is_exists (bool): True if the path exists, False otherwise.
        """

        is_file = os.path.isfile(path) # Aca problema porque no desencrypta
        # Cuando el archivo esta encryptado no lo determina como isfile = True si no como falso
        is_dir = os.path.isdir(path)
        is_exists_path = os.path.exists(path)

        return {'is_file': is_file, 'is_dir': is_dir, 'is_exists': is_exists_path}

    def operation(self, path, cypher_type = False) -> None:
        """
        The `encrypter_decrypter` function deterministically encrypts or decrypts 
        the data at a given path. 
        It checks whether the path is a file or a directory 
        and processes the data accordingly.
        """
        # Defining local encrypt just file data
        def encrypt_data(path, flag_cypher):
            try:
            #main_path = os.path.abspath(path)
                main_path = os.path.abspath(
                                self.sanitizer_path(path)
                )
                #Error here
                with open(main_path, 'rb') as delta_file:
                    if flag_cypher:
                        crypted_data = self.cypher_suite.decrypt(delta_file.read())
                    else:
                        # Check if the file were encrypted before
                        crypted_data = self.cypher_suite.encrypt(delta_file.read())
                    with open(main_path, 'wb') as file_to_write:
                        file_to_write.write(crypted_data)
                self.rename_encrypter_fname(main_path, cypher_type)
            
            except Exception as e:
                print("[!] Possible crypter Error [!]")
                print("[!] There are a lot Files would be mixed betweed encrypted and decrypted files [!]")
                print("[!] Please in case of error make the operation to SINGLE FILE [!]")
                print("[!] Example: python3 one_crypter.py --decrypt <path> --password <password> [!]")
            
            except PermissionError as e:
                print("[-] Permission error: ", e)
                print("[-] Please run the script as root or with the right permissions [-]")
            
            finally:
                pass
            
        checker = self.file_directory_checker(path)


        ### Where are here!
        # It is possible to encrypt but not to decrypt

        # Check if there are a simple file or directory
        if checker['is_exists']:

            if checker['is_file']:
                # Encrypting single file
                encrypt_data(path, cypher_type)

            elif checker['is_dir']:
                
                # Order the tree from last point to the root
                tree = iter(os.walk(path, topdown=False))
                for absolute_path_item, dirnames_item, filesnames_item in tree:
                    # Encrypting files
                    for file_item in filesnames_item:
                        encrypt_data(os.path.join(absolute_path_item, file_item), cypher_type)
                        #encrypt_data(os.path.abspath(file_item), cypher_type)
                    # Encrypting directories
                    if platform.system() != 'Windows':
                        for dir_item in dirnames_item:
                            #encrypt_data(os.path.join(absolute_path_item, dir_item), cypher_type)
                            self.rename_encrypter_fname(os.path.abspath(path), cypher_type)
                encrypt_data(path, cypher_type)
                print("[!] Recursive item are encrypted.")

        else:

            print("[-] File doesn't exists! ")
    
    def sanitizer_path(self, path) -> str:
        """
        Sanitize the given path by removing any trailing slashes.

        Args:
            path (str): The path to be sanitized.

        Returns:
            str: The sanitized path.
        """
        modified_path = path.replace("\\\\", "\\")
        return modified_path


    def rename_encrypter_fname(self, absolute_path, encrypt_file = False) -> None:
        """
        Encrypting the name as the folder and the files.
        encrypt_or_decrypt => False default to encrypt, True to decrypt
        """

        #absolute_path = os.path.abspath(path)

        try:
            print("[+] File or Folder where will be operated [+] : ", absolute_path)
            single_name = os.path.basename(absolute_path)
            # True decrypt files else encrypt
            if encrypt_file:
                new_name = self.cypher_suite.decrypt(
                    single_name.encode()
                ).decode()
            else:
                new_name = self.cypher_suite.encrypt(
                    single_name.encode()
                ).decode()
            
            full_path_new_name = os.path.join(os.path.dirname(absolute_path), new_name)
            print(f"[+] File {absolute_path}/{single_name} (de/en)crypted")
            os.rename(absolute_path, full_path_new_name)


        except (InvalidToken, FileNotFoundError) as e:
            print("Error:", e)
            print("[-] Password Wrong or file corrupted will be pass [!]")
            print("[-] Take care if the file were encrypter o iterative with a lot decrypt would corrupt the file [!]")
    
    def convert_hex_to_bytes(self, hex_string):
        print("HEX:", hex_string)
        return binascii.unhexlify(hex_string)

if __name__ == '__main__':


    parser = argparse.ArgumentParser(
        description="Encrypt and decrypter software developed in python using SHA-512",
        prog="Encrypt_Cowboy",
    )
    parser.add_argument("-e", type=str, help='Encrypt files/folders')
    parser.add_argument("--encrypt", type=str, help='Encrypt files/folder set PATH')
    parser.add_argument("--decrypt", type=str, help='Decrypt files/folders set PATH')
    parser.add_argument("-d", type=str, help='Decrypt files/folders')
    args = parser.parse_args()
    password = getpass.getpass("Password credential:")
    cypher_handler = CypherHandler(password)

    """
    List of options.
    Encrypt - Decrypt - Creating credentials file
    """
    if args.encrypt or args.e:
        decrypt_or_encrypt = False # True = decrypt , False = encrypt
        path = args.encrypt if args.encrypt else args.e
        print("[+] Encrypt the files and folders.")
    elif args.decrypt or args.d:
        decrypt_or_encrypt = True # True = decrypt , False = encrypt
        path = args.decrypt if args.decrypt else args.d
        print("[+] Decrypt the files and folders.")
    
    try:
        cypher_handler.operation(path, decrypt_or_encrypt)
        #cypher_handler.get_cypher_suite()
    
    except NameError as error:
        print("Error:", error)
        print("Set the path or the variable is not defined.")




"""
* Al decriptar iterativamente corrompe el archivo.
* Buscar una bandera en la cual se sepa si se encripto o desencrypto anteriormente
* Al encryptar solo una vez funciona bien pero al desencryptar deben de ser 2 veces
"""