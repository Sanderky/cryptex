import numpy as np
import random
from Crypto.PublicKey import RSA
import Crypto.Signature.pkcs1_15 as pkcs1_15
from Crypto.Hash import SHA256
import binascii
from pydub import AudioSegment
from subprocess import check_output
from colorama import Fore
from colorama import Style

class RNG:
    def __init__(this, file):
        this.file = file
        this.iterator = -1
        this.samples = []
        this.wavToM4a()
        this.generateSamplesFromSource()
    
    def wavToM4a(this):
        print('\nConvering .wav file to .m4a...\n')
        check_output(f"ffmpeg -i {this.file} -c:a aac -q:a 2 source.m4a", shell=True)
        print(f'{Fore.GREEN}\n~ Done')
        print(f'~ File saved as source.m4a{Style.RESET_ALL}')
    
    def generateSamplesFromSource(this):
        print('\nGenerating samples from source...\n')
        this.samples = np.uint8(AudioSegment.from_file('source.m4a', format='m4a').get_array_of_samples())
        random.shuffle(this.samples)

    def randomBytes(this, N):
        arrayOfRandomBytes = []
        while(len(arrayOfRandomBytes) < N):
            this.iterator += 1
            if(this.iterator == len(this.samples)):
                print(f"{Fore.RED}End of source file!\n{Style.RESET_ALL}")
                this.iterator = 0
            arrayOfRandomBytes.append(this.samples[this.iterator])
        return bytes(arrayOfRandomBytes)

class Cryptex:

    @classmethod
    def generateRsaKey(this, rng):
        print('Generating RSA keys. Can took a while...\n')
        key = RSA.generate(2048, rng.randomBytes)
        private_key = key.export_key()
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        file_out.close()
        public_key = key.publickey().export_key()
        file_out = open("public.pem", "wb")
        file_out.write(public_key)
        file_out.close()
        print(f'{Fore.GREEN}~ Done')
        print('~ Private key saved as private.pem')
        print(f'~ Public key saved as public.pem{Style.RESET_ALL}')

    @classmethod
    def signFile(this, privateKeyFile, fileToSign):
        print('\nSignign a file...\n')
        with open(privateKeyFile, 'rb') as privateKey:
            with open(fileToSign, 'rb') as file:
                signature = pkcs1_15.new(RSA.import_key(privateKey.read())).sign(SHA256.new(file.read()))
                file_out = open('signature.bin', 'wb')
                file_out.write(binascii.hexlify(signature))
                print(f"{Fore.GREEN}~ Done")
                print(f"~ Signature saved as signature.bin{Style.RESET_ALL}")

    @classmethod
    def verifySignature(this, file, publicKeyFile, signatureFile):
        print('\nVerifying a signature...\n')
        with open(publicKeyFile, 'rb') as publicKey:
            with open(signatureFile, 'rb') as signature:
                with open(file, 'rb') as file:
                    try:
                        verifier = pkcs1_15.new(RSA.import_key(publicKey.read())).verify(SHA256.new(file.read()), binascii.unhexlify(signature.read()))
                        print(f"{Fore.GREEN}~ Signature is valid{Style.RESET_ALL}")
                    except:
                        print(f"{Fore.RED}~ Signature is invalid{Style.RESET_ALL}")

def main():
    print('\n')
    print(f'{Fore.BLUE}         CRYPTEX{Style.RESET_ALL}')
    while(True):
        print('')
        print(f'{Fore.BLUE}- - - - - - - - - - - - - -')
        print('1 -> Generate RSA keys pair')
        print('2 -> Sign a file')
        print('3 -> Verify a signature')
        print('4 -> Exit program')
        print(f'- - - - - - - - - - - - - -{Style.RESET_ALL}')
        print('')
        option = int(input('> Select option: '))
        print('')

        if option == 1:
            print(f'{Fore.YELLOW}=====================')
            print('1) RSA KEYS GENERATOR')
            print(f'=====================\n{Style.RESET_ALL}')
            print(f'{Fore.LIGHTYELLOW_EX}Note:')
            print(f'{Style.DIM}Random Number Generator uses audio wav file as entropy source\n{Style.RESET_ALL}')
            audioFilePath = input('> Provide path to file in .wav format: ')
            rng = RNG(audioFilePath)
            Cryptex.generateRsaKey(rng)

        elif option == 2:
            print(f'{Fore.YELLOW}=========================')
            print('2) FILE DIGITAL SIGNATURE')
            print(f'=========================\n{Style.RESET_ALL}')
            privateKeyFile = input('> Provide path to private key file: ')
            fileToSign = input('> Which file you want to sign? ')
            Cryptex.signFile(privateKeyFile, fileToSign)

        elif option == 3:
            print(f'{Fore.YELLOW}==============================')
            print('3) DIGITAL SIGNATURE VERIFYING')
            print(f'==============================\n{Style.RESET_ALL}')
            file = input('> Which file you want to verify? ')
            publicKeyFile = input('> Provide path to public key file: ')
            signatureFile =  input('> Provide path to signature file: ')
            Cryptex.verifySignature(file, publicKeyFile, signatureFile)

        elif option == 4:
            print('Exiting program...\n')
            exit()
        else:
            print('Please select a right option\n')

if __name__ == "__main__":
    main()