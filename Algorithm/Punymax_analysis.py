#!C:\Users\MaksymilianJanSzyman\AppData\Local\Programs\Python\Python37-32\python.exe

# Copyright 2020 Maksymilian Jan Szymanski 
# Universidad Carlos III Madrid
# Contributor: Andrés Marín López
#
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
#
#   http://www.apache.org/licenses/LICENSE-2.0 
#
# Unless required by applicable law or agreed to in writing, 
# software distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and 
# limitations under the License.


########################################################
#                      IMPORTS                         #
########################################################
from PIL import Image, ImageDraw, ImageFont            #
import pytesseract                                     #
import argparse                                        #
import cgi                                             #
import idna                                            #
import re                                              #
from datetime import datetime                          #
import os                                              #
from fontTools.ttLib import TTFont                     #
import collections                                     #
from operator import itemgetter                        #
import mariadb                                         #
import argparse                                        #
import sys                                             #
import csv                                             #
import datetime                                        #
########################################################



#common arguments
font_size = 86
fonts_folder = 'websitesFont'
font_list_in_dir = os.listdir('./' + fonts_folder)
space = 4
access_type = 0 # 0 for script, 1 for web


########################################################
#                        MAIN                          #
########################################################

def main(argv):
    verbose = 0
    hostname = 0
    permutation = 0
    args = None
    web_args = cgi.FieldStorage()

    if len(web_args) <= 0:
        args = init_parser()
        if args.verboselevel > 0: print("[DEBUG] STANDALONE EXECUTION")
        verbose = args.verboselevel
        hostname = args.hostname
        permutation = args.permutation
        access_type = 0
    else:
        hostname = web_args["url"].value 
        if web_args["verbose"].value == "small":
            verbose = 0
        elif web_args["verbose"].value == "medium":
            verbose = 1
        else:
            verbose = 2
        permutation = int(web_args["permutation"].value)
        access_type = 1

    test_writer = None
    if args and args.csvfilename:
        test_file = open(args.csvfilename + '.csv', mode='w+',encoding='utf8') 
        test_writer = csv.writer(test_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONE)
        test_writer.writerow(["Original URL","Found URL","Similarity","Phishing probability"])

    conn = None
    try:
        # CHANGE: setup your local database parameters
        conn = mariadb.connect(
            user="user",
            password="password",
            host="127.0.0.1",
            port=3306,
            database="mysql"

        )
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")

    cur = conn.cursor()

    start_time = datetime.datetime.now()
    if args and args.filename != None:
        f= open(args.filename,"r",encoding='utf-8', errors='ignore')
        fileLines = f.readlines()
        for line in fileLines:

            print(line)
            analyze(line,test_writer,verbose,cur,permutation,access_type)
        f.close
    else: 
        analyze(hostname,test_writer,verbose,cur,permutation,access_type)
    elapsed_time = datetime.datetime.now() - start_time
    if verbose > 0 : print(str(elapsed_time.seconds) + "s",":",str(elapsed_time.microseconds) + "ms") 
    cur.close
    conn.close




########################################################
#               Core algorithm function                #
########################################################

def analyze(full_text, test_writer,level_of_verbose,cursor, permutation_type, access_type):

    # ## variables ## #
    x_res = 120
    y_res = 150
    no_permutation = [ [0,0,0,0] ]
    permutations1 = [ [0,0,x_res/2,y_res/2] , [x_res/2,y_res/2,x_res,0],[x_res/2,y_res/2,x_res,y_res],[0,y_res,x_res/2,y_res/2]]
    permutations2 = [ [0,0,x_res,y_res/2] , [0,y_res/2,x_res,y_res] , [0,0,x_res/2,y_res] , [x_res/2,0,x_res,y_res]]
    permutations3H = [ [2*x_res/10,0,3*x_res/10,y_res] , [3*x_res/10,0,4*x_res/10,y_res] , [4*x_res/10,0,5*x_res/10,y_res] , [5*x_res/10,0,6*x_res/10,y_res] , [6*x_res/10,0,7*x_res/10,y_res] , [7*x_res/10,0,8*x_res/10,y_res] ]
    permutations3V = [ [0,2*y_res/10,x_res,3*y_res/10] , [0,3*y_res/10,x_res,4*y_res/10] , [0,4*y_res/10,x_res,5*y_res/10] , [0,5*y_res/10,x_res,6*y_res/10] , [0,6*y_res/10,x_res,7*y_res/10] , [0,7*y_res/10,x_res,8*y_res/10], [0,8*y_res/10,x_res,9*y_res/10] ]
    permutations3 = permutations3H + permutations3V
    permutations4 = permutations1 + permutations2
    permutations5 = permutations1 + permutations3H + permutations3V
    permutations6 = permutations2 + permutations3H + permutations3V
    permutations7 = permutations1 + permutations2 + permutations3H + permutations3V
    permutations_list = [permutations1,permutations2,permutations3,permutations4,permutations5,permutations6,permutations7]
    permutations = permutations_list[permutation_type] + no_permutation
    prob = 90
    # CHANGE: the following tesseract address to your server tesseract address
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract"
    main_letters_array = [] # [[[letra , prob] , [letra2 , prob]] , posicion]

    # Decode punycode
    try:
        full_text = idna.decode(full_text).replace('\n', '')
    except:
        full_text = full_text.replace('\n', '')
    
    url = full_text
    if level_of_verbose > 1: print("[DEBUG] " + str(full_text.encode('utf8')))
    full_text = list(full_text)

    # Main loop to obtain all homographs
    # Need to go through all checked letters
    char_index = 0
    while char_index < len(full_text): 
        if level_of_verbose > 1: print("[DEBUG] " + str(full_text[char_index].encode('utf-8')))
        # Check if letter is a valid one and if it is outside whitelisted alphabet
        if (full_text[char_index] != '.') and (len(re.findall("[a-zA-Z0-9-]",full_text[char_index])) == 0):
            if level_of_verbose > 1: print("[DEBUG] Found Unicode character")
            letters = []
            valid = True
            fnt_name = find_font_for_letter(full_text[char_index],font_list_in_dir,level_of_verbose)
            if fnt_name is '':
                print("[DEBUG] Did not find adequate font")
                test_writer.writerow([url,"font_error",0,0])
                valid = False
                letters = ['#']
            if valid:
                fnt =  ImageFont.truetype(fnt_name, font_size)
                wrong = 0
                for n in range(len(permutations)):
                    if level_of_verbose > 1: print("[DEBUG] Performing permutation number: " + str(n))
                    img = Image.new('RGB', (x_res, y_res), color=(255, 255, 255))
                    d = ImageDraw.Draw(img)
                    d.text(((x_res/2) - font_size/4, (y_res/2) - font_size/2), full_text[char_index], font=fnt, fill=(0, 0, 0))
                    d.rectangle(permutations[n],fill=(0, 0, 0))
                    # Uncomment the next line to use white modifications and not black.
                    #d.rectangle(permutations[n],fill=(255, 255, 255))
                    # Uncomment the next line to save images of the modified characters.
                    #img.save(full_text[char_index] + '_' + str(n) + '_' + 'pil_text.png')
                    new_letter = pytesseract.image_to_string(img, lang='eng', config="-c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyz0123456789 --psm 10 tessedit_do_invert=0")
                    if level_of_verbose > 1:
                        print("[DEBUG] Detected letter: [" + new_letter + "]")
                    if new_letter is '':
                        new_letter = '#'
                        wrong += 1
                    letters.append(new_letter)
                counter=collections.Counter(letters)
                d_counter = dict(counter)
                for v,k in d_counter.items():
                    d_counter[v] = round(k/(len(permutations)),2) * 100
                main_letters_array.append([d_counter,char_index])
                if level_of_verbose > 1: 
                    print("[DEBUG] " + str(main_letters_array))
        char_index +=1
    urls = []
    if level_of_verbose > 1: print(urls)
    urls.append([url,0])
    count = 0
    for element in main_letters_array:
        count+=1
        if level_of_verbose > 1: 
            print("[DEBUG] " + str(count))
            print("[DEBUG] " + str(element))
        urls_copy = list(urls)
        urls = []
        for key, value in element[0].items():
            if level_of_verbose > 1: 
                print("[DEBUG] " + str(element[1]))
                print("[DEBUG] " + key)
                print("[DEBUG] " + str(value))
            for elemt in urls_copy:
                text = elemt[0]
                text = text[:element[1]] + str(key) + text[element[1]+1:]
                urls.append([str(text),(value + elemt[1])/count])

    urls = sorted(urls, key=itemgetter(1),reverse=True)
    percentage_domain = get_real_factor(urls[0][0],cursor)
    if level_of_verbose > 0 : print("Analyzed URLs:" + str(len(urls)))
    best_guess = ["none",0,0]
    best_guess_percentage = 0
    for count in range(len(urls)):
        main_url = str(urls[count][0])
        percentage_domain = get_real_factor(urls[count][0],cursor)
        percentage_domain = (urls[count][1] + percentage_domain)/2
        if percentage_domain > 50:
            if percentage_domain > best_guess_percentage:
                best_guess_percentage = percentage_domain
                best_guess[0] = main_url
                best_guess[1] = urls[count][1]/100
                best_guess[2] = percentage_domain/100
        prob = str(urls[count][1])
        if level_of_verbose > 0: print("\t[Hostname (" + str(count) + "): " + main_url + "]")
        if level_of_verbose > 0: print("\t[Probability of similarity: " +  prob + "%]")
        if level_of_verbose > 0: print("\t[Probability of pishing: " + str(percentage_domain)   + "%]")
    if access_type != 1:
        print("Best guess: " + best_guess[0])
        print("Probability of similarity: " + str(best_guess[1]*100) + "%")
        print("Probability of pishing: " + str(best_guess[2]*100)     + "%")
        if test_writer:
            test_writer.writerow([url,best_guess[0],best_guess[1],best_guess[2]])
    elif access_type == 1 and best_guess[1] != 0:
        if level_of_verbose > 0:
            print("Best guess: " + best_guess[0])
            print("Probability of similarity: " + str(best_guess[1]*100) + "%")
            print("Probability of pishing: " + str(best_guess[2]*100)     + "%")
        else:
            print("[" + best_guess[0] + "]")


########################################################
# Search through all the fonts to find the correct one #
########################################################

def find_font_for_letter(letter, font_list,verbose):
    # print(font_list)
    i = 0
    found = False
    while i < len(font_list) and not found:
        # print(str(i) + "<" + str(len(font_list)))
        if char_in_font(letter,TTFont(fonts_folder + "/" + font_list[i])):
            found = True
            if verbose > 0: print("[DEBUG] Letter: [" + str(ord(letter)) + "] is in font: [" + font_list[i] + "]")
            return (fonts_folder + "/" + font_list[i])
        i += 1
    if not found:
        # print("Letter: [" + letter + "] could not be found anywhere")
        return ''


########################################################
def char_in_font(unicode_char, font):
    for cmap in font['cmap'].tables:
        if cmap.isUnicode():
            if ord(unicode_char) in cmap.cmap:
                return True           
    return False


########################################################
#       Parse the arguments from the command line      #
########################################################
def init_parser():
    parser = argparse.ArgumentParser(description='Analyze URLs for possible homograph attacks')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i ', dest='filename', action='store', required=False,
                    help='filename from where the URLs are loaded')
    group.add_argument('-s ', dest='hostname', action='store', required=False,
                    help='string with the hostname to analyse')
    parser.add_argument('-o', dest='csvfilename', action='store',required=False, default=None,
                    help='csv filename where the output is going to be saved')
    parser.add_argument('-v', dest='verboselevel', action='store',required=False, default=0, type=int,
                    help='a higher level is a more detailed level')
    parser.add_argument('-p', dest='permutation', action='store',required=False, default=0, type=int, choices = [0,1,2,3,4,5,6], 
                    help='permutation type ')
                    
    args = parser.parse_args()
    return args

########################################################
# Returns a percentage about the position of the       #
# hostname in the databse (if it exists)               #
########################################################
def get_real_factor(domain,cursor):
    percentage_domain =  0
    max_elems = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM top_10_million_domains")
        for elem in cursor:
            max_elems = elem[0]
        cursor.execute("SELECT Rank FROM top_10_million_domains WHERE Domain =?",(domain,))
        for elem in cursor:
            percentage_domain = round((((max_elems - elem[0])*100/max_elems)/2)+50,2)
        return percentage_domain
    except mariadb.Error as e:
        print(f"Error: {e}")



########################################################
#                          START                       #
########################################################

print("Content-type: text/html\n\n")
if __name__ == "__main__":
   main(sys.argv[1:])

########################################################
#                          END                       #
########################################################