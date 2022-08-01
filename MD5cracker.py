import hashlib
from optparse import OptionParser
import sys
import string
import io

banner = """
    __  _______  ______                     __            
   /  |/  / __ \/ ____/_____________ ______/ /_____  _____
  / /|_/ / / / /___ \/ ___/ ___/ __ `/ ___/ //_/ _ \/ ___/
 / /  / / /_/ /___/ / /__/ /  / /_/ / /__/ ,< /  __/ /    
/_/  /_/_____/_____/\___/_/   \__,_/\___/_/|_|\___/_/     
                                                          """

def bruteforce(hash, wordlist, verbose):
    spaces = " " * 30
    for word in wordlist:
        wordlist_hash = hashlib.new("md5", word.strip().encode()).hexdigest()
        if verbose is not None:
            print("\rTrying password: " +  word.strip() + spaces, end = "")
        if hash == wordlist_hash:
            return word 
    return None
        

def main(options, args):
    print(banner)
     
    verbose = options.verbose
    hash = options.hash
    file = options.file
    outfile = options.outfile
    wordlistf = options.wordlist
    wordlist_file = io.open(wordlistf, "r", errors="ignore")
    wordlist = wordlist_file.readlines()

    result = ""
    if hash is not None:
        print("[+] Bruteforce started  | hash: " + hash + " | wordlist: " + wordlistf +" |\n")
        result = bruteforce(hash, wordlist, verbose)
    elif file is not None:
        hashfile = open(file, "r")    
        hash = hashfile.readline().strip()
        print("[+] Bruteforce started  | hash: " + hash + " | wordlist: " + wordlistf +" |\n")
        result = bruteforce(hash, wordlist, verbose)

    if result is not None:
        print("\n\nPassword found -> " + hash + ":" +  result)
        if outfile is not None:
            ofile = open(outfile, "w")
            ofile.write(hash + ":" + result)
    else:
        print("\n\nPassword not found")


if __name__ == "__main__":

    parser = OptionParser("Usage: %prog [options]", prog=sys.argv[0])

    parser.add_option("-w", "--wordlist", dest = "wordlist", help = "Wordlist to use for bruteforcing", metavar = "WORDLIST")
    parser.add_option("-s", "--hash", dest = "hash", help = "String of the hash to crack", metavar = "HASH")
    parser.add_option("-f", "--file", dest = "file", help = "File with the hash to crack", metavar = "FILE")
    parser.add_option("-o", "--outfile", dest = "outfile", help = "Output file witch cracked passwords", metavar = "OUTFILE")
    parser.add_option("-v", "--verbose", dest = "verbose", help = "Verbose output (SLOWER)", action = "store_false")

    (options, args) = parser.parse_args()

    if options.wordlist == None or (options.hash == None and options.file == None):
        print(parser.print_help())
        exit(0)
    main(options, args)

